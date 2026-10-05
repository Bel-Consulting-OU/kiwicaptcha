defmodule Kiwicaptcha.Json do
  @moduledoc """
  The JSON seam: the standard library JSON module when present, with
  Jason as the optional fallback for older Elixir releases. Every
  encode and decode in the SDK funnels through here.
  """

  @doc "Decode a JSON document to terms, or :error on any failure."
  @spec decode(String.t()) :: {:ok, term()} | :error
  def decode(value) when is_binary(value) do
    cond do
      json_loaded?() ->
        try do
          JSON.decode(value)
        rescue
          _ -> :error
        end

      Code.ensure_loaded?(Jason) and function_exported?(Jason, :decode, 1) ->
        try do
          Jason.decode(value)
        rescue
          _ -> :error
        end

      true ->
        :error
    end
  end

  @doc "Encode terms to a JSON document, or :error on any failure."
  @spec encode(term()) :: {:ok, String.t()} | :error
  def encode(value) do
    cond do
      json_loaded?() ->
        try do
          {:ok, IO.iodata_to_binary(JSON.encode_to_iodata!(value))}
        rescue
          _ -> :error
        end

      Code.ensure_loaded?(Jason) and function_exported?(Jason, :encode, 1) ->
        try do
          Jason.encode(value)
        rescue
          _ -> :error
        end

      true ->
        :error
    end
  end

  @doc "Like encode/1 but raises on failure."
  @spec encode!(term()) :: String.t()
  def encode!(value) do
    case encode(value) do
      {:ok, doc} -> doc
      :error -> raise "no JSON encoder available"
    end
  end

  defp json_loaded? do
    if {:json_loaded, true} == :persistent_term.get({:kiwicaptcha, :json}, :unset) do
      true
    else
      loaded = Code.ensure_loaded?(JSON) and function_exported?(JSON, :decode, 1)
      if loaded, do: :persistent_term.put({:kiwicaptcha, :json}, {:json_loaded, true})
      loaded
    end
  end
end
