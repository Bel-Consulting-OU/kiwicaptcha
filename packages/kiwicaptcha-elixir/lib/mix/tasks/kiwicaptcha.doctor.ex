if Code.ensure_loaded?(Mix) do
  defmodule Mix.Tasks.Kiwicaptcha.Doctor do
    @moduledoc """
    The doctor task: validates config, secrets and the store of one
    deployment from the four-setting environment surface. Exit status
    is zero only when every check passes.

        KIWI_SECRET=... KIWI_STORE=redis://localhost mix kiwicaptcha.doctor
    """

    use Mix.Task

    @shortdoc "Validates the KiwiCaptcha deployment surface"

    @impl Mix.Task
    def run(_args) do
      secret = System.get_env("KIWI_SECRET") || ""
      store_url = System.get_env("KIWI_STORE") || "memory://"

      store =
        try do
          {:ok, Kiwicaptcha.Settings.open_store(store_url)}
        rescue
          e -> {:error, Exception.message(e)}
        end

      rsw =
        case {System.get_env("KIWI_RSW_MODULUS"), System.get_env("KIWI_RSW_LAMBDA")} do
          {m, l} when is_binary(m) and is_binary(l) ->
            %{modulus_n: m, lambda: l, verification_keys: %{}, allow_legacy_identity: false}

          _ ->
            nil
        end

      case store do
        {:error, message} ->
          Mix.shell().error(
            "kiwicaptcha.doctor: cannot open store #{inspect(store_url)}: #{message}"
          )

          exit({:shutdown, 1})

        {:ok, store} ->
          report =
            Kiwicaptcha.Doctor.run(
              secret: secret,
              store: store,
              rsw: rsw,
              region: System.get_env("KIWI_REGION"),
              issuer: System.get_env("KIWI_ISSUER")
            )

          Enum.each(report.checks, fn check ->
            mark = if check.ok, do: "ok  ", else: "FAIL"
            Mix.shell().info("#{mark} #{check.name}: #{check.detail}")
          end)

          if report.ok do
            Mix.shell().info("doctor: deployment is sound")
          else
            Mix.shell().error("doctor: findings above must be resolved")
            exit({:shutdown, 1})
          end
      end
    end
  end
end
