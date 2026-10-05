defmodule Kiwicaptcha.DoctorTest do
  use ExUnit.Case, async: false

  import Kiwicaptcha.TestSupport

  alias Kiwicaptcha.Doctor
  alias Kiwicaptcha.Settings

  def memory_store do
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start()
    Kiwicaptcha.Stores.Memory.adapter(pid)
  end

  test "the doctor passes a sound memory deployment" do
    report = Doctor.run(secret: secret(), store: memory_store())
    assert report.ok, inspect(report.checks)

    assert %{"secret" => _, "region" => _, "issuer" => _, "store" => _} =
             Map.new(report.checks, &{&1.name, &1})
  end

  test "the doctor flags a weak secret and a dead store" do
    report = Doctor.run(secret: "short", store: failing_store())
    refute report.ok
    refute finding(report, "secret").ok
    refute finding(report, "store").ok
  end

  test "the doctor flags identifier shapes" do
    report =
      Doctor.run(secret: secret(), store: memory_store(), region: "has space", issuer: "eu")

    refute finding(report, "region").ok
    assert finding(report, "issuer").ok
  end

  test "the doctor validates the rsw trapdoor" do
    rsw_row = golden_record("rsw")
    rsw_opts = rsw_row["verify_opts"]["rsw"]

    report =
      Doctor.run(
        secret: secret(),
        store: memory_store(),
        rsw: %{
          modulus_n: rsw_opts["modulus_n"],
          lambda: rsw_opts["lambda"],
          verification_keys: %{},
          allow_legacy_identity: false
        }
      )

    assert finding(report, "rsw").ok

    report =
      Doctor.run(
        secret: secret(),
        store: memory_store(),
        rsw: %{
          modulus_n: "QQ==",
          lambda: "Ag==",
          verification_keys: %{},
          allow_legacy_identity: false
        }
      )

    refute finding(report, "rsw").ok
  end

  test "the settings resolve the four setting surface" do
    settings =
      Settings.new(
        secret: secret(),
        store_url: "memory://",
        scopes: "login=critical,comment=low",
        env: %{}
      )

    assert "abuse_first" == settings.profile
    assert %{"login" => "critical", "comment" => "low"} == settings.scopes
    assert Settings.valid_secret?(settings)

    from_env =
      Settings.new(
        env: %{
          "KIWI_PROFILE" => "ease_first",
          "KIWI_SECRET" => secret(),
          "KIWI_STORE" => "memory://",
          "KIWI_SCOPES" => "signup"
        }
      )

    assert "ease_first" == from_env.profile
    assert %{"signup" => ""} == from_env.scopes
    assert Settings.valid_secret?(from_env)
    refute Settings.valid_secret?(Settings.new(env: %{"KIWI_SECRET" => "tiny"}))
  end

  test "the settings open store surface" do
    store = Settings.open_store("memory://")
    assert is_map_key(store, :store)
    assert_raise ArgumentError, fn -> Settings.open_store("mysql://x") end
    assert_raise ArgumentError, fn -> Settings.open_store("sqlite://") end

    # The opened adapter is a working verify store end to end: the
    # doctor probe mints its own fresh record against the live clock.
    report = Doctor.run(secret: secret(), store: store)
    assert finding(report, "store").ok, finding(report, "store").detail
  end

  test "the settings open a working sqlite store when exqlite ships" do
    unless Kiwicaptcha.Support.ExqliteDriver.available?() do
      raise "exqlite missing"
    end

    dir = Path.join(System.tmp_dir!(), "kiwi-settings-#{System.unique_integer()}")
    File.mkdir_p!(dir)
    store = Settings.open_store("sqlite://#{Path.join(dir, "kiwi.db")}")

    # The doctor probe mints its own fresh record, so the live clock
    # works: reachability and the exactly-once semantics end to end
    # through the settings-opened adapter.
    report = Doctor.run(secret: secret(), store: store)
    assert finding(report, "store").ok, finding(report, "store").detail

    File.rm_rf!(dir)
  end

  test "the doctor mix task reports a sound deployment" do
    System.put_env("KIWI_SECRET", secret())
    System.put_env("KIWI_STORE", "memory://")

    try do
      Mix.Tasks.Kiwicaptcha.Doctor.run([])
    after
      System.delete_env("KIWI_SECRET")
      System.delete_env("KIWI_STORE")
    end
  end

  test "the doctor mix task fails a weak secret" do
    System.put_env("KIWI_SECRET", "tiny")
    System.put_env("KIWI_STORE", "memory://")

    try do
      assert catch_exit(Mix.Tasks.Kiwicaptcha.Doctor.run([]))
    after
      System.delete_env("KIWI_SECRET")
      System.delete_env("KIWI_STORE")
    end
  end

  defp finding(report, name), do: Enum.find(report.checks, &(&1.name == name))

  # A store whose every read raises: the doctor must report it, not
  # crash.
  defp failing_store do
    %{
      store: fn _ -> raise "store down" end,
      find: fn _ -> raise "store down" end,
      runtime_state: fn _ -> raise "store down" end,
      consume: fn _, _ -> raise "store down" end,
      commit_result: fn _, _, _, _ -> raise "store down" end,
      delete_if_pending: fn _ -> raise "store down" end,
      authenticated_result_commit?: fn -> true end
    }
  end
end
