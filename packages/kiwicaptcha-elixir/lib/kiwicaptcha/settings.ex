defmodule Kiwicaptcha.Settings do
  @moduledoc """
  The four-setting quickstart surface: the profile is an adoption
  choice, so the deployable settings are the secret, the store URL and
  the scopes. Settings resolves a store URL into the shipped adapter
  without any other configuration.
  """

  defstruct [:profile, :secret, :store_url, :scopes]

  @type t :: %__MODULE__{
          profile: String.t(),
          secret: String.t() | nil,
          store_url: String.t(),
          scopes: %{optional(String.t()) => String.t()}
        }

  @doc """
  Build settings from explicit values or environment variables
  (KIWI_PROFILE, KIWI_SECRET, KIWI_STORE, KIWI_SCOPES). The scopes
  string is name=value pairs joined by commas.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    env = Keyword.get(opts, :env, %{})

    %__MODULE__{
      profile: opts[:profile] || env["KIWI_PROFILE"] || "abuse_first",
      secret: opts[:secret] || env["KIWI_SECRET"],
      store_url: opts[:store_url] || env["KIWI_STORE"] || "memory://",
      scopes:
        case opts[:scopes] || env["KIWI_SCOPES"] || "" do
          scopes when is_map(scopes) -> scopes
          scopes when is_binary(scopes) -> parse_scopes(scopes)
        end
    }
  end

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
