defmodule Kiwicaptcha.SidecarVerdictTest do
  @moduledoc """
  The delegation verdict contract, without the sidecar binary: a fresh
  acceptance is a fresh result (never a stored-result replay), the
  opt-in telemetry gate runs before the delegation, and the caller's
  telemetry posture and operation identity ride along instead of being
  dropped at the seam.
  """

  use ExUnit.Case, async: false

  import Kiwicaptcha.TestSupport

  setup_all do
    {:ok, _} = Application.ensure_all_started(:inets)
    :ok
  end

  defp start_stub(body) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listen)
    test = self()

    spawn(fn ->
      case :gen_tcp.accept(listen, 3000) do
        {:ok, sock} ->
          {:ok, request} = :gen_tcp.recv(sock, 0, 2000)
          send(test, {:request, request})

          response =
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: " <>
              Integer.to_string(byte_size(body)) <> "\r\nconnection: close\r\n\r\n" <> body

          :gen_tcp.send(sock, response)
          :gen_tcp.close(sock)

        _ ->
          :ok
      end

      :gen_tcp.close(listen)
    end)

    "http://127.0.0.1:#{port}"
  end

  defp armed_setup(url, extra, telemetry) do
    row = golden_record("sha_execution_v4")
    record = record_from_row(row)
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    Kiwicaptcha.Stores.Memory.store(pid, record)

    token_b64 =
      case telemetry do
        nil ->
          row["token_b64"]

        telemetry ->
          {:ok, token} = Kiwicaptcha.Token.decode(row["token_b64"])
          token |> Map.merge(%{telemetry: telemetry}) |> Kiwicaptcha.Token.encode()
      end

    options =
      row["verify_opts"]
      |> golden_options(record, store)
      |> Map.merge(%{execution_policy: %Kiwicaptcha.ExecutionPolicy{sidecar_url: url}})
      |> Map.merge(Map.new(extra))

    {record, token_b64, options}
  end

  test "fresh delegation success is a fresh result" do
    url = start_stub(~s({"success": true}))
    {_record, token_b64, options} = armed_setup(url, %{}, nil)
    result = Kiwicaptcha.verify(token_b64, options)
    assert result.ok, inspect(result)
    refute result.from_stored_result
    assert_receive {:request, request}
    assert request =~ "enforce_telemetry"
    assert request =~ "operation_identity"
  end

  test "delegation runs the telemetry gate first" do
    url = start_stub(~s({"success": true}))
    {_record, token_b64, options} = armed_setup(url, %{enforce_telemetry: true}, %{"wd" => true})
    result = Kiwicaptcha.verify(token_b64, options)
    refute result.ok
    assert result.code == :telemetry_rejected
    refute_received {:request, _}

    # Opt-out: the same bot token delegates when the gate is off.
    {_record, token2, options2} = armed_setup(url, %{}, %{"wd" => true})
    assert Kiwicaptcha.verify(token2, options2).ok
  end

  test "delegation forwards telemetry posture and operation identity" do
    url = start_stub(~s({"success": true}))

    {_record, token_b64, options} =
      armed_setup(
        url,
        %{enforce_telemetry: true, operation_identity: "order-123"},
        %{"et" => [0, 12, 40]}
      )

    result = Kiwicaptcha.verify(token_b64, options)
    assert result.ok, inspect(result)
    assert_receive {:request, request}
    body = request |> String.split("\r\n\r\n", parts: 2) |> List.last()
    payload = Jason.decode!(body)
    assert payload["enforce_telemetry"] == true
    assert payload["operation_identity"] == "order-123"
  end
end
