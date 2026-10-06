defmodule Kiwicaptcha.VerifyGatesTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The verifier behavior suite over the PHP-issued golden records:
  # the canonical cheap-gate order, the rollout floor window, the
  # one-shot replay semantics, the measured solve duration and every
  # locally drivable VerifyError code.
  def store_of(name) do
    row = golden_record(name)
    record = record_from_row(row)
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    Kiwicaptcha.Stores.Memory.store(pid, record)
    {store, record, row}
  end

  def options_for(record, row, storage, extra \\ %{}) do
    row["verify_opts"]
    |> golden_options(record, storage)
    |> Map.merge(Map.new(extra))
  end

  def token_of(row), do: row["token_b64"]

  def re_encode(token, changes) do
    token
    |> Map.merge(Map.new(changes))
    |> Kiwicaptcha.Token.encode()
  end

  test "the golden happy paths verify with the contract shape" do
    for name <- ["sha_plain", "sha_bound", "sha_decoy_v3", "rsw"] do
      {storage, record, row} = store_of(name)
      result = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
      assert result.ok, "#{name}: #{result.code} #{result.detail}"
      assert result.disposition == :allow
      assert result.decision_handle == record.nonce
      assert is_binary(result.price)
      assert result.code == :""
      assert result.detail == nil
    end

    {_s, _r, row} = store_of("sha_decoy_v3")
    {storage, record, _row} = store_of("sha_decoy_v3")
    decoy = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
    assert decoy.decoy_field == "decoy_field_a1b2c3d4e5f60718"

    {storage, record, row} = store_of("sha_plain")
    plain = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
    assert is_integer(plain.solve_duration_ms)
    assert plain.solve_duration_ms > 1000
  end

  test "execution armed records fail closed" do
    {storage, record, row} = store_of("sha_execution_v4")
    result = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
    refute result.ok
    assert result.code == :execution_mismatch
  end

  test "the golden negative records answer their pinned codes" do
    {storage, record, row} = store_of("tampered_signature")
    result = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
    refute result.ok
    assert result.code == :bad_signature
    assert result.decision_handle == nil
    assert result.price == nil
  end

  test "an argon2id rung verifies through the native binding" do
    if Kiwicaptcha.Pow.argon2_available?() do
      {storage, record, row} = store_of("argon2id")
      result = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
      assert result.ok, inspect(result.code)
      assert result.disposition == :allow
    end
  end

  test "an unrepresentable argon2id rung refuses loudly, never downgrades" do
    record = %{record_from_row(golden_record("argon2id")) | m_kib: 100}

    token = %Kiwicaptcha.Token{
      nonce: record.nonce,
      counter: 3,
      duration_ms: 1500,
      telemetry: %{"v" => 1},
      execution_digest: nil,
      execution_trace: nil,
      rsw_proof: nil
    }

    assert Kiwicaptcha.Verify.recompute_valid_proof(nil, record, token) == :unsupported
  end

  test "an unknown token answers record_not_found" do
    row = golden_record("sha_plain")

    {:ok, pid} =
      Kiwicaptcha.Stores.Memory.start(now: fn -> record_from_row(row).issued_at + 10 end)

    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    result = Kiwicaptcha.verify(row["token_b64"], base_options(storage: store))
    assert result.code == :record_not_found
  end

  test "malformed tokens answer malformed_token" do
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start()
    store = Kiwicaptcha.Stores.Memory.adapter(pid)

    for raw <- ["not base64!!!", "", "QQ==", String.duplicate("a", 40_000)] do
      result = Kiwicaptcha.verify(raw, base_options(storage: store))
      assert result.code == :malformed_token
    end
  end

  test "an expired record answers expired on the verifier clock" do
    {storage, record, row} = store_of("sha_plain")

    result =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{now: fn -> record.expires_at + 1 end})
      )

    assert result.code == :expired

    {storage, record, row} = store_of("sha_plain")

    result =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{now: fn -> record.issued_at - 61 end})
      )

    assert result.code == :expired
  end

  test "the record is consumed exactly once and replays deterministically" do
    {storage, record, row} = store_of("sha_plain")
    opts = options_for(record, row, storage)
    first = Kiwicaptcha.verify(token_of(row), opts)
    assert first.ok
    replay = Kiwicaptcha.verify(token_of(row), opts)
    assert replay.code == :already_consumed
    state = storage.runtime_state.(record.nonce)
    assert state.kind == :consumed
  end

  test "a stored success replays only under the proven operation identity" do
    {storage, record, row} = store_of("sha_plain")
    base = options_for(record, row, storage)

    ok =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{operation_identity: "op-123"})
      )

    assert ok.ok

    replay =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{operation_identity: "op-123"})
      )

    assert replay.ok
    assert replay.from_stored_result
    assert replay.solve_duration_ms == nil
    assert replay.decision_handle == record.nonce

    other =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{operation_identity: "op-456"})
      )

    assert other.code == :already_consumed
    anonymous = Kiwicaptcha.verify(token_of(row), base)
    assert anonymous.code == :already_consumed
  end

  test "a stored invalid outcome replays to any caller" do
    {storage, record, row} = store_of("sha_plain")
    {:ok, token} = Kiwicaptcha.Token.decode(token_of(row))
    wrong = re_encode(token, counter: 999_999)
    opts = options_for(record, row, storage)
    bad = Kiwicaptcha.verify(wrong, opts)
    assert bad.code == :insufficient_work
    replay = Kiwicaptcha.verify(wrong, opts)
    assert replay.code == :insufficient_work
  end

  test "a resultless consumed record answers consume_indeterminate" do
    {storage, record, row} = store_of("sha_plain")
    storage.consume.(record.nonce, nil)
    result = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage))
    assert result.code == :consume_indeterminate
  end

  test "a forged success grant without the mac is refused as malformed" do
    {storage, record, row} = store_of("sha_plain")
    storage.consume.(record.nonce, "grant-op")
    storage.commit_result.(record.nonce, true, nil, nil)

    forged =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{operation_identity: "grant-op"})
      )

    assert forged.code == :malformed_record

    {storage2, record, row} = store_of("sha_plain")
    storage2.consume.(record.nonce, nil)
    storage2.commit_result.(record.nonce, true, nil, nil)
    anonymous = Kiwicaptcha.verify(token_of(row), options_for(record, row, storage2))
    assert anonymous.code == :already_consumed
  end

  test "an operation identity is validated before the transition" do
    {storage, record, row} = store_of("sha_plain")

    result =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{operation_identity: "spaces not allowed"})
      )

    assert result.code == :consume_indeterminate
    assert storage.runtime_state.(record.nonce).kind == :pending
  end

  test "scope region issuer and policy epoch answer their typed codes" do
    expect_code = fn extra ->
      {storage, record, row} = store_of("sha_plain")
      Kiwicaptcha.verify(token_of(row), options_for(record, row, storage, extra)).code
    end

    assert expect_code.(%{expected_scope: "other"}) == :wrong_scope
    # The scope option is required: an empty option is the typed
    # required_scope refusal, never an any-scope acceptance.
    assert expect_code.(%{expected_scope: ""}) == :required_scope
    assert expect_code.(%{region: "us"}) == :wrong_region
    assert expect_code.(%{region: nil, expected_issuer: "prod"}) == :wrong_issuer
    assert expect_code.(%{expected_policy_version: 2}) == :wrong_policy_version
  end

  test "the policy rollout window accepts the old epoch and fails closed above it" do
    {storage, record, row} = store_of("sha_plain")

    strict =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{expected_policy_version: 2})
      )

    assert strict[:code] == :wrong_policy_version, strict[:detail]

    {storage, record, row} = store_of("sha_plain")

    window_ok =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{expected_policy_version: 2, policy_version_floor: 1})
      )

    assert window_ok[:ok] == true, "#{window_ok[:code]} #{window_ok[:detail]}"

    {storage, record, row} = store_of("sha_plain")

    window_reject =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{expected_policy_version: 3, policy_version_floor: 2})
      )

    assert window_reject[:code] == :wrong_policy_version, window_reject[:detail]
  end

  test "the ip binding answers missing client ip and ip mismatch and never deletes on missing" do
    {storage, record, row} = store_of("sha_bound")
    assert Kiwicaptcha.verify(token_of(row), options_for(record, row, storage)).ok

    {storage2, record2, row2} = store_of("sha_bound")

    no_ip =
      Kiwicaptcha.verify(token_of(row2), options_for(record2, row2, storage2, %{client_ip: nil}))

    assert no_ip.code == :missing_client_ip
    assert storage2.runtime_state.(record2.nonce).kind == :pending

    wrong_ip =
      Kiwicaptcha.verify(
        token_of(row2),
        options_for(record2, row2, storage2, %{client_ip: "198.51.100.9"})
      )

    assert wrong_ip.code == :ip_mismatch
    assert storage2.runtime_state.(record2.nonce).kind == :missing
  end

  test "the request binding is exact option equality with the named legacy mode" do
    {storage, record, row} = store_of("sha_bound")
    assert Kiwicaptcha.verify(token_of(row), options_for(record, row, storage)).ok

    {storage2, record2, row2} = store_of("sha_bound")

    wrong =
      Kiwicaptcha.verify(
        token_of(row2),
        options_for(record2, row2, storage2, %{expected_request_binding: "tx-other"})
      )

    assert wrong.code == :request_binding_mismatch

    plain_row = golden_record("sha_plain")
    plain = record_from_row(plain_row)
    {:ok, pid3} = Kiwicaptcha.Stores.Memory.start(now: fn -> plain.issued_at + 10 end)
    s3 = Kiwicaptcha.Stores.Memory.adapter(pid3)
    Kiwicaptcha.Stores.Memory.store(pid3, plain)

    legacy =
      Kiwicaptcha.verify(
        plain_row["token_b64"],
        options_for(plain, plain_row, s3, %{
          expected_request_binding: "tx-9999",
          binding_expectation: :legacy
        })
      )

    assert legacy.ok

    {:ok, pid4} = Kiwicaptcha.Stores.Memory.start(now: fn -> plain.issued_at + 10 end)
    s4 = Kiwicaptcha.Stores.Memory.adapter(pid4)
    Kiwicaptcha.Stores.Memory.store(pid4, plain)

    exact =
      Kiwicaptcha.verify(
        plain_row["token_b64"],
        options_for(plain, plain_row, s4, %{expected_request_binding: "tx-9999"})
      )

    assert exact.code == :request_binding_mismatch
  end

  test "the kid gate answers unknown kid for revoked and unresolved kids" do
    {storage, record, row} = store_of("sha_bound")

    revoked =
      Kiwicaptcha.verify(token_of(row), options_for(record, row, storage, %{revoked_kids: [2]}))

    assert revoked.code == :unknown_kid

    # A kid beyond the newest configured kid is the forward guard: the
    # forged record is re-signed so only the kid gate can reject it.
    forged = record |> Kiwicaptcha.Record.to_json_map() |> Map.put("kid", 9)
    signed = re_sign(forged, 9)
    {:ok, pid3} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    s3 = Kiwicaptcha.Stores.Memory.adapter(pid3)
    Kiwicaptcha.Stores.Memory.store(pid3, signed)

    forward =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, s3, %{secrets_by_kid: %{1 => secret()}})
      )

    assert forward.code == :unknown_kid
  end

  def re_sign(record_data, kid) do
    record_data =
      record_data
      |> Map.put("protocol_version", 2)
      |> Map.delete("server_mac")

    canonical =
      Kiwicaptcha.Canonical.canonical_payload(%Kiwicaptcha.Canonical.Args{
        protocol_version: 2,
        nonce: record_data["nonce"],
        scope: record_data["scope"],
        binding_tag: record_data["binding_tag"],
        issued_at: record_data["issued_at"],
        expires_at: record_data["expires_at"],
        algorithm: record_data["algorithm"],
        m_kib: record_data["m_kib"],
        t: record_data["t"],
        p: record_data["p"],
        target_bits: record_data["target_bits"],
        salt: record_data["salt"],
        min_duration_ms: record_data["min_duration_ms"],
        region: record_data["region"],
        policy_version: record_data["policy_version"],
        request_binding: record_data["request_binding"],
        issuer: record_data["issuer"],
        kid: kid,
        decoy_field: record_data["decoy_field"],
        execution_version: record_data["execution_version"],
        execution_commitment: record_data["execution_commitment"],
        rsw_modulus_sha256: record_data["rsw_modulus_sha256"],
        server_mac_committed: false
      })

    challenge =
      Kiwicaptcha.B64.encode_std(canonical) <>
        "." <> Kiwicaptcha.Canonical.sign_payload_v2(canonical, secret())

    record_data = Map.put(record_data, "challenge", challenge)
    record_data = Map.put(record_data, "prefix", challenge <> "|" <> record_data["salt"] <> "|")
    {:ok, record} = Kiwicaptcha.Record.from_json(record_data)
    record
  end

  test "too fast fires on a receipt inside the signed minimum duration" do
    {storage, record, row} = store_of("sha_plain")

    result =
      Kiwicaptcha.verify(
        token_of(row),
        options_for(record, row, storage, %{now_ns: record.issued_at_ns + 100})
      )

    assert result.code == :too_fast

    {storage2, record2, row2} = store_of("sha_plain")

    ok =
      Kiwicaptcha.verify(
        token_of(row2),
        options_for(record2, row2, storage2, %{now_ns: record2.issued_at_ns + 600_000})
      )

    assert ok.ok

    {storage3, record3, row3} = store_of("sha_plain")

    skewed =
      Kiwicaptcha.verify(
        token_of(row3),
        options_for(record3, row3, storage3, %{now_ns: record3.issued_at_ns - 6_000_000})
      )

    assert skewed.code == :too_fast

    {storage4, record4, row4} = store_of("sha_plain")

    within =
      Kiwicaptcha.verify(
        token_of(row4),
        options_for(record4, row4, storage4, %{now_ns: record4.issued_at_ns - 1_000_000})
      )

    assert within.ok
  end

  test "a wrong proof on a real sha256 record is insufficient work" do
    {storage, record, row} = store_of("sha_plain")
    {:ok, token} = Kiwicaptcha.Token.decode(token_of(row))
    wrong = re_encode(token, counter: token.counter + 1)
    result = Kiwicaptcha.verify(wrong, options_for(record, row, storage))
    assert result.code == :insufficient_work
  end

  test "structural tampering fails closed as malformed record and burns the record" do
    row = golden_record("sha_plain")
    record = record_from_row(row)

    mutations = [
      fn r -> %{r | scope: "has space"} end,
      fn r -> %{r | protocol_version: 1} end,
      fn r -> %{r | expires_at: r.issued_at + 301} end,
      fn r -> %{r | target_bits: 21} end,
      fn r -> %{r | salt: Kiwicaptcha.B64.encode_std(:binary.copy(<<1>>, 15))} end,
      fn r -> %{r | prefix: "wrong|prefix|"} end
    ]

    for mutate <- mutations do
      {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
      store = Kiwicaptcha.Stores.Memory.adapter(pid)
      store.store.(mutate.(record))
      result = Kiwicaptcha.verify(row["token_b64"], base_options(storage: store))
      assert result.code == :malformed_record
      assert store.runtime_state.(record.nonce).kind == :missing
    end

    {:ok, kid_pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    kid_store = Kiwicaptcha.Stores.Memory.adapter(kid_pid)
    kid_store.store.(%{record | kid: 0})
    kid_result = Kiwicaptcha.verify(row["token_b64"], base_options(storage: kid_store))
    assert kid_result.code == :bad_signature
  end

  test "armed records demand execution evidence and refuse stray digests" do
    exec_row = golden_record("sha_execution_v4")
    exec_record = record_from_row(exec_row)
    {:ok, token} = Kiwicaptcha.Token.decode(exec_row["token_b64"])
    bare = re_encode(token, execution_digest: nil, execution_trace: nil)
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> exec_record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    store.store.(exec_record)
    result = Kiwicaptcha.verify(bare, options_for(exec_record, exec_row, store))
    assert result.code == :execution_mismatch

    plain_row = golden_record("sha_plain")
    plain = record_from_row(plain_row)
    {:ok, stray_token} = Kiwicaptcha.Token.decode(plain_row["token_b64"])
    stray = re_encode(stray_token, execution_digest: String.duplicate("a", 64))
    {:ok, pid4} = Kiwicaptcha.Stores.Memory.start(now: fn -> plain.issued_at + 10 end)
    store4 = Kiwicaptcha.Stores.Memory.adapter(pid4)
    store4.store.(plain)
    stray_result = Kiwicaptcha.verify(stray, options_for(plain, plain_row, store4))
    assert stray_result.code == :execution_mismatch
  end

  test "an unarmed signed rsw record without a trapdoor is unsupported" do
    {storage, record, row} = store_of("rsw")

    no_trapdoor =
      Kiwicaptcha.verify(token_of(row), options_for(record, row, storage, %{rsw: nil}))

    assert no_trapdoor.code == :unsupported_rsw_params

    {storage2, record2, row2} = store_of("rsw")
    {:ok, token} = Kiwicaptcha.Token.decode(token_of(row2))
    refute token.rsw_proof == nil
    wrong = re_encode(token, counter: 3)
    wrong_result = Kiwicaptcha.verify(wrong, options_for(record2, row2, storage2))
    assert wrong_result.code == :insufficient_work

    plain_row = golden_record("sha_plain")
    plain_record = record_from_row(plain_row)
    {:ok, pid3} = Kiwicaptcha.Stores.Memory.start(now: fn -> plain_record.issued_at + 10 end)
    s3 = Kiwicaptcha.Stores.Memory.adapter(pid3)
    Kiwicaptcha.Stores.Memory.store(pid3, plain_record)
    {:ok, stray_token} = Kiwicaptcha.Token.decode(plain_row["token_b64"])
    stray = re_encode(stray_token, rsw_proof: String.duplicate("a", 512))
    stray_result = Kiwicaptcha.verify(stray, options_for(plain_record, plain_row, s3))
    assert stray_result.code == :insufficient_work
  end

  test "the telemetry gate rejects bot signals on a pending record only" do
    row = golden_record("sha_plain")
    record = record_from_row(row)
    {:ok, token} = Kiwicaptcha.Token.decode(row["token_b64"])

    check = fn telemetry ->
      {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
      store = Kiwicaptcha.Stores.Memory.adapter(pid)
      store.store.(record)
      raw = re_encode(token, telemetry: telemetry)
      Kiwicaptcha.verify(raw, options_for(record, row, store, %{enforce_telemetry: true}))
    end

    assert check.(%{}).code == :telemetry_rejected
    uniform = Enum.map(0..29, &(&1 * 100))
    assert check.(%{"et" => uniform}).code == :telemetry_rejected

    human = Enum.map(0..29, fn i -> i * 100 + trunc(:math.sin(i) * 37) + rem(i * i, 13) end)
    assert check.(%{"et" => human}).ok
    assert check.(%{"wd" => true}).code == :telemetry_rejected
  end

  test "a store failure answers storage unavailable fail closed" do
    row = golden_record("sha_plain")

    failing = %{
      runtime_state: fn _nonce -> raise "down" end,
      find: fn _nonce -> raise "down" end,
      consume: fn _n, _i -> nil end,
      commit_result: fn _n, _v, _b, _m -> false end,
      delete_if_pending: fn _n -> %{kind: :missing, consumed: nil} end,
      store: fn _r -> :ok end,
      authenticated_result_commit?: fn -> true end
    }

    result = Kiwicaptcha.verify(row["token_b64"], base_options(storage: failing))
    assert result.code == :storage_unavailable
  end
end
