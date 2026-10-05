defmodule Kiwicaptcha.IntegrationsTest.StaticOptions do
  @moduledoc false
  # The MFA resolver target: options built in a module function.
  def build, do: %{secret_key: "x", storage: nil}
end

defmodule Kiwicaptcha.IntegrationsTest do
  use ExUnit.Case, async: true
  import Plug.Conn
  import Plug.Test

  import Kiwicaptcha.TestSupport

  # The Plug router integration and the Phoenix component helpers: the
  # auto-verify and auto-outcomes surface of the shared server SDK
  # contract, exercised over the golden records.
  def store_of(name) do
    row = golden_record(name)
    record = record_from_row(row)
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    Kiwicaptcha.Stores.Memory.store(pid, record)
    {store, record, row}
  end

  def verifier_fun(name) do
    fn _conn ->
      {store, record, row} = store_of(name)
      golden_options(row["verify_opts"], record, store)
    end
  end

  def post_with_token(token, field \\ "kiwi__token") do
    conn(:post, "/login", %{field => token})
  end

  def call(conn, opts) do
    Kiwicaptcha.Plug.call(conn, Kiwicaptcha.Plug.init(opts))
  end

  test "a verified request rides the decision into the assigns" do
    {_store, _record, row} = store_of("sha_plain")
    conn = call(post_with_token(row["token_b64"]), verify: verifier_fun("sha_plain"))

    refute conn.halted
    assert conn.assigns.kiwi.ok
    assert conn.assigns.kiwi.disposition == :allow
    assert is_binary(conn.assigns.kiwi.decision_handle)
  end

  test "a missing token answers the typed json failure" do
    conn = conn(:post, "/login", %{}) |> call(verify: verifier_fun("sha_plain"))

    assert conn.halted
    assert 422 == conn.status
    assert ["application/json; charset=utf-8"] == get_resp_header(conn, "content-type")

    {:ok, body} = Kiwicaptcha.Json.decode(conn.resp_body)
    assert "malformed_token" == body["error"]["code"]
    assert body["error"]["detail"] =~ "missing"
  end

  test "a failing token answers its verify code" do
    # A consumed record replays to already_consumed; a bad counter is
    # insufficient_work; a garbage string is malformed_token.
    {store, record, row} = store_of("sha_plain")

    failing = fn _conn ->
      golden_options(row["verify_opts"], record, store)
    end

    wrong = "not-a-token"
    conn = call(post_with_token(wrong), verify: failing)
    assert 422 == conn.status
    {:ok, body} = Kiwicaptcha.Json.decode(conn.resp_body)
    assert "malformed_token" == body["error"]["code"]

    wrong_counter =
      row["token_b64"]
      |> Kiwicaptcha.Token.decode!()
      |> Map.merge(%{counter: 12_345})
      |> Kiwicaptcha.Token.encode()

    conn = call(post_with_token(wrong_counter), verify: failing)
    {:ok, body} = Kiwicaptcha.Json.decode(conn.resp_body)
    assert "insufficient_work" == body["error"]["code"]
  end

  test "a storage outage answers storage unavailable fail closed" do
    failing_store = %{
      runtime_state: fn _ -> raise "down" end,
      find: fn _ -> raise "down" end,
      consume: fn _, _ -> nil end,
      commit_result: fn _, _, _, _ -> false end,
      delete_if_pending: fn _ -> %{kind: :missing, consumed: nil} end,
      store: fn _ -> :ok end,
      authenticated_result_commit?: fn -> true end
    }

    {_store, record, row} = store_of("sha_plain")

    conn =
      call(
        post_with_token(row["token_b64"]),
        verify: fn _conn -> golden_options(row["verify_opts"], record, failing_store) end
      )

    assert 422 == conn.status
    {:ok, body} = Kiwicaptcha.Json.decode(conn.resp_body)
    assert "storage_unavailable" == body["error"]["code"]
  end

  test "the token rides the header too" do
    {_store, _record, row} = store_of("sha_plain")

    conn =
      conn(:post, "/login", %{})
      |> put_req_header("x-kiwi-token", row["token_b64"])
      |> call(verify: verifier_fun("sha_plain"))

    refute conn.halted
    assert conn.assigns.kiwi.ok
  end

  test "the redirect failure mode answers 303 with a location" do
    conn =
      call(post_with_token("junk"),
        verify: verifier_fun("sha_plain"),
        failure_redirect: "/blocked"
      )

    assert conn.halted
    assert 303 == conn.status
    assert ["/blocked"] == get_resp_header(conn, "location")
  end

  test "the failure status is configurable" do
    conn = call(post_with_token("junk"), verify: verifier_fun("sha_plain"), failure_status: 403)
    assert 403 == conn.status
  end

  test "the mfa and map option resolvers work" do
    {store, record, row} = store_of("sha_plain")

    # A static options map verifies directly.
    opts = golden_options(row["verify_opts"], record, store)
    conn = call(post_with_token(row["token_b64"]), verify: opts)
    assert conn.assigns.kiwi.ok

    # An MFA tuple resolves per request.
    conn =
      call(post_with_token(row["token_b64"]),
        verify: {Kiwicaptcha.IntegrationsTest.StaticOptions, :build, []}
      )

    refute conn.assigns[:kiwi]
    assert conn.status == 422
  end

  test "the phoenix form helpers emit the drop in fragments" do
    field = Kiwicaptcha.PhoenixComponent.form_field("login")
    {:safe, iodata} = field
    html = IO.iodata_to_binary(iodata)
    assert html =~ ~s(<script src="/kiwi.js" defer></script>)
    assert html =~ ~s(<input type="hidden" name="kiwi__token" data-kiwi="login">)

    custom =
      Kiwicaptcha.PhoenixComponent.form_field("signup",
        token_field: "my_token",
        script: "/static/kiwi.js"
      )

    {:safe, custom_io} = custom
    custom_html = IO.iodata_to_binary(custom_io)
    assert custom_html =~ ~s(<script src="/static/kiwi.js" defer></script>)
    assert custom_html =~ ~s(name="my_token" data-kiwi="signup")

    attrs = Kiwicaptcha.PhoenixComponent.form_attributes("login")
    {:safe, attrs_io} = attrs
    assert IO.iodata_to_binary(attrs_io) == ~s(data-kiwi="login")
  end
end
