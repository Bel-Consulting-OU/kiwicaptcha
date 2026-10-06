defmodule Kiwicaptcha.SidecarDelegationTest do
  @moduledoc """
  The sidecar delegation plane: the spawned kiwicaptcha-verifier (the
  full Rust core with the real execution verifier) fronts an
  execution-armed challenge; the SDK's fail-closed default refuses it,
  the sidecar policy delegates and accepts. Skipped where the verifier
  crate is unavailable.
  """

  use ExUnit.Case, async: false

  setup_all do
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  @repo_root Path.expand("../../..", __DIR__)
  @sidecar_bin Path.join(@repo_root, "target/debug/kiwicaptcha-verifier")
  @secret "elixir-sidecar-delegation-0123456789abcdef"

  setup do
    unless File.exists?(@sidecar_bin) do
      build = System.cmd("cargo", ["build", "-q", "-p", "kiwicaptcha-verifier"], cd: @repo_root)

      if elem(build, 1) != 0 or not File.exists?(@sidecar_bin) do
        raise "skip"
      end
    end

    build =
      System.cmd("cargo", ["build", "-q", "-p", "kiwicaptcha-verifier", "--features", "test-fixtures"],
        cd: @repo_root
      )

    if elem(build, 1) != 0, do: raise("skip")

    spawn_helper = Path.join(__DIR__, "support/sidecar-spawn.sh")
    stop_helper = Path.join(__DIR__, "support/sidecar-stop.sh")
    work = Path.join(System.tmp_dir!(), "kiwi-sidecar-#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(work)
    evidence_file = Path.join(work, "evidence.json")
    pid_file = Path.join(work, "sidecar.pid")
    store_dir = Path.join(work, "store")

    {out, 0} =
      System.cmd("bash", [
        spawn_helper,
        @sidecar_bin,
        @secret,
        evidence_file,
        pid_file,
        store_dir
      ])

    url = out |> String.split("\n") |> Enum.reject(&(&1 == "")) |> List.last()
    doc = Jason.decode!(File.read!(evidence_file))

    on_exit(fn ->
      System.cmd("bash", [stop_helper, pid_file, store_dir])
      File.rm_rf!(work)
    end)

    %{url: url, doc: doc}
  end

  defp record_from_wire(wire) do
    %Kiwicaptcha.Record{
      nonce: wire["nonce"],
      scope: wire["scope"],
      binding_tag: wire["binding_tag"] || "",
      issued_at: wire["issued_at"],
      expires_at: wire["expires_at"],
      algorithm: wire["algorithm"],
      m_kib: wire["m_kib"],
      t: wire["t"],
      p: wire["p"],
      target_bits: wire["target_bits"],
      salt: wire["salt"],
      prefix: wire["prefix"],
      challenge: wire["challenge"],
      min_duration_ms: wire["min_duration_ms"],
      issued_at_ns: wire["issued_at_ns"] || 0,
      protocol_version: wire["protocol_version"] || 2,
      policy_version: wire["policy_version"] || 1,
      execution_program: wire["execution_program"],
      execution_version: wire["execution_version"] || 0,
      execution_commitment: wire["execution_commitment"],
      kid: wire["kid"] || 1,
      server_mac: wire["server_mac"]
    }
  end

  defp counter_for(record) do
    salt = Base.decode64!(record.salt)

    Stream.iterate(0, &(&1 + 1))
    |> Enum.find(fn counter ->
      digest = :crypto.hash(:sha256, record.prefix <> Integer.to_string(counter) <> salt)
      leading_zero_bits(digest) >= record.target_bits
    end)
  end

  defp leading_zero_bits(digest, acc \\ 0)
  defp leading_zero_bits(<<0::size(8), rest::binary>>, acc), do: leading_zero_bits(rest, acc + 8)

  defp leading_zero_bits(<<byte::size(8), _::binary>>, acc),
    do: acc + leading_zero_bits_of_byte(byte)

  defp leading_zero_bits(<<>>, acc), do: acc

  defp leading_zero_bits_of_byte(byte) do
    Enum.reduce_while(7..0, 0, fn shift, count ->
      if Bitwise.band(Bitwise.bsr(byte, shift), 1) == 0 do
        {:cont, count + 1}
      else
        {:halt, count}
      end
    end)
  end

  defp build_token(doc, record) do
    Base.encode64(
      Enum.join(
        [
          record.nonce,
          Integer.to_string(counter_for(record)),
          "5000",
          "{}",
          doc["digest"] <> ":" <> doc["trace"]
        ],
        "."
      )
    )
  end

  @tag :sidecar
  test "the fail-closed default refuses the armed record, the sidecar policy delegates", %{url: url, doc: doc} do
    record = record_from_wire(doc["record"])
    refute is_nil(record.execution_program), "the minted record is execution-armed"

    token = build_token(doc, record)

    # The fail-closed default: the armed record refuses exactly as
    # before the delegation plane existed.
    adapter = local_store(record)
    :ok = adapter.store.(record)
    options = %{storage: adapter, secret_key: @secret, expected_scope: "login", client_ip: "203.0.113.7"}

    refused = Kiwicaptcha.verify(token, options)
    refute refused.ok
    assert refused.code == :execution_mismatch

    # The sidecar policy: the delegation accepts.
    policy = %Kiwicaptcha.ExecutionPolicy{sidecar_url: url}
    delegated_adapter = local_store(record)
    :ok = delegated_adapter.store.(record)
    accepted = Kiwicaptcha.verify(token, Map.merge(options, %{storage: delegated_adapter, execution_policy: policy}))
    assert accepted.ok, "the delegation must accept: #{inspect(accepted.code)}"

    # Single-use: the sidecar consumed; a replay never re-accepts.
    replay = Kiwicaptcha.verify(token, Map.merge(options, %{storage: delegated_adapter, execution_policy: policy}))
    refute replay.ok
    assert replay.code in [:already_consumed, :record_not_found]

    # An unreachable sidecar answers the retry disposition.
    down_adapter = local_store(record)
    :ok = down_adapter.store.(record)
    down = Kiwicaptcha.verify(token, Map.merge(options, %{
      storage: down_adapter,
      execution_policy: %Kiwicaptcha.ExecutionPolicy{sidecar_url: "http://127.0.0.1:1", timeout_ms: 300}
    }))
    refute down.ok
    assert down.code == :storage_unavailable
  end

  # The plain map-of-funs storage the verify entry documents for tests
  # and tools: one pending record in an ets table, the transitions
  # implemented over it. The delegation legs never consume locally.
  defp local_store(record) do
    table = :ets.new(:kiwi_sidecar_store, [:set, :public])
    :ets.insert(table, {:pending, record})

    find = fn nonce ->
      case :ets.lookup(table, :pending) do
        [{_, %Kiwicaptcha.Record{} = found}] -> if found.nonce == nonce, do: found
        _ -> nil
      end
    end

    runtime_state = fn nonce ->
      case find.(nonce) do
        nil -> %{kind: :missing, record: nil, consumed: nil}
        found -> %{kind: :pending, record: found, consumed: nil}
      end
    end

    %{
      store: fn _record -> :ok end,
      find: find,
      runtime_state: runtime_state,
      consume: fn _nonce, _identity -> nil end,
      commit_result: fn _nonce, _valid, _binding, _mac -> false end,
      delete_if_pending: fn _nonce -> %{kind: :missing} end,
      authenticated_result_commit?: fn -> false end
    }
  end
end
