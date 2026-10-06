defmodule Kiwicaptcha.Settings do
  @moduledoc """
  The four-setting quickstart surface: the profile is an adoption
  choice, so the deployable settings are the secret, the store URL and
  the scopes. Settings resolves a store URL into the shipped adapter
  without any other configuration.
  """

  defstruct [:profile, :secret, :store_url, :scopes]

  # Profiles whose work ladder prices Argon2id rungs (the explicit
  # argon budgets and the full-stack adoption profiles). A deployment
  # that names one must run a verifier that can recompute them: the
  # argon2_elixir package carries the native binding, and an absent
  # binding is a loud configuration error — never a silent downgrade.
  @argon_rung_profiles ["argon16", "argon32", "argon64", "abuse_first", "high_abuse"]

  @type t :: %__MODULE__{
          profile: String.t(),
          secret: String.t() | nil,
          store_url: String.t(),
          scopes: %{optional(String.t()) => String.t()}
        }

  @doc """
  Build settings from explicit values or environment variables
  (KIWI_PROFILE, KIWI_SECRET, KIWI_STORE, KIWI_SCOPES). The scopes
  string is name=value pairs joined by commas. Raises ArgumentError
  when the profile issues Argon2id rungs this runtime cannot verify.
  """
  @spec new(keyword()) :: t() | no_return()
  def new(opts \\ []) do
    env = Keyword.get(opts, :env, %{})
    profile = opts[:profile] || env["KIWI_PROFILE"] || "abuse_first"
    assert_argon_rung_verifiable!(profile)

    %__MODULE__{
      profile: profile,
      secret: opts[:secret] || env["KIWI_SECRET"],
      store_url: opts[:store_url] || env["KIWI_STORE"] || "memory://",
      scopes:
        case opts[:scopes] || env["KIWI_SCOPES"] || "" do
          scopes when is_map(scopes) -> scopes
          scopes when is_binary(scopes) -> parse_scopes(scopes)
        end
    }
  end

  @doc """
  The issuer guard: a profile whose ladder issues Argon2id rungs this
  runtime cannot verify refuses to boot.
  """
  @spec assert_argon_rung_verifiable!(String.t()) :: :ok | no_return()
  def assert_argon_rung_verifiable!(profile) when is_binary(profile) do
    if profile in @argon_rung_profiles and not Kiwicaptcha.Pow.argon2_available?() do
      raise ArgumentError,
            "profile #{inspect(profile)} issues Argon2id rungs this runtime cannot " <>
              "verify: add the optional argon2_elixir dependency for the native " <>
              "binding (or choose a sha-only profile). The rung is never silently " <>
              "downgraded"
    end

    :ok
  end

  def assert_argon_rung_verifiable!(_), do: :ok

  @doc "Whether the configured secret meets the 32-byte floor."
  @spec valid_secret?(t()) :: boolean()
  def valid_secret?(%__MODULE__{secret: secret}) do
    is_binary(secret) and byte_size(secret) >= Kiwicaptcha.Keys.min_secret_bytes()
  end

  @doc """
  Build the store adapter the URL names: memory, sqlite (path) or
  redis (host and port). Raises ArgumentError on an unknown scheme and
  explains the optional dependency when a backend package is missing.
  """
  @spec open_store(String.t()) :: map() | no_return()
  def open_store(url) when is_binary(url) do
    case URI.parse(url) do
      %{scheme: "memory"} ->
        case Kiwicaptcha.Stores.Memory.start() do
          {:ok, store} -> Kiwicaptcha.Stores.Memory.adapter(store)
          other -> raise ArgumentError, "cannot start the memory store: #{inspect(other)}"
        end

      %{scheme: "sqlite", path: path} ->
        if path in [nil, ""] do
          raise ArgumentError, "a sqlite store URL needs a file path"
        end

        case Kiwicaptcha.Stores.SqliteDriver.Exqlite.open(path) do
          {:ok, store} ->
            store

          {:error, reason} ->
            raise ArgumentError, "cannot open the sqlite store: #{inspect(reason)}"
        end

      %{scheme: scheme} when scheme in ["redis", "rediss"] ->
        unless Code.ensure_loaded?(Redix) do
          raise ArgumentError, "the redis backend needs the optional redix dependency"
        end

        case Redix.start_link(url) do
          {:ok, client} -> Kiwicaptcha.Stores.Redis.new(client)
          {:error, reason} -> raise ArgumentError, "cannot connect to redis: #{inspect(reason)}"
        end

      _ ->
        raise ArgumentError, "unsupported store URL scheme: #{url}"
    end
  end

  defp parse_scopes(value) do
    value
    |> String.split(",", trim: true)
    |> Map.new(fn pair ->
      case String.split(pair, "=", parts: 2) do
        [name, class] -> {String.trim(name), String.trim(class)}
        [name] -> {String.trim(name), ""}
      end
    end)
  end
end
