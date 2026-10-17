defmodule Kiwicaptcha.TokenSource do
  @moduledoc """
  The shared token authority rule of the server SDKs, pinned by
  protocol/decision-v1/corpus.json.

  Every non-empty value is collected from all three sources (the
  x-kiwi-token header, the configured form field, the same-named query
  parameter), repeated values included. One distinct value verifies,
  however many sources carry it. Two or more distinct values refuse the
  request with `:token_source_conflict` before any candidate is
  verified, so a trusted gateway's header can never be shadowed by an
  attacker-controlled body field.
  """

  @doc """
  Resolve the collected source values. Returns `{token, nil}` for one
  agreed value and `{nil, failure_code}` otherwise.
  """
  @spec resolve_values([String.t()], [String.t()], [String.t()]) ::
          {String.t(), nil} | {nil, :token_source_conflict | :malformed_token}
  def resolve_values(header_values, form_values, query_values) do
    result =
      Enum.reduce_while(header_values ++ form_values ++ query_values, [], fn value, acc ->
        cond do
          not is_binary(value) or value == "" -> {:cont, acc}
          value in acc -> {:cont, acc}
          acc == [] -> {:cont, [value]}
          true -> {:halt, :conflict}
        end
      end)

    case result do
      :conflict -> {nil, :token_source_conflict}
      [] -> {nil, :malformed_token}
      [token | _] -> {token, nil}
    end
  end

  @doc "Every header candidate of the merged header lines."
  @spec split_header([String.t()]) :: [String.t()]
  def split_header(values) do
    values
    |> Enum.flat_map(&String.split(&1, ","))
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  @doc "The decoded name/value pairs of a urlencoded string, duplicates preserved."
  @spec form_pairs(String.t() | nil) :: [{String.t(), String.t()}]
  def form_pairs(nil), do: []

  def form_pairs(encoded) when is_binary(encoded) do
    encoded
    |> String.split("&", trim: true)
    |> Enum.map(fn pair ->
      case String.split(pair, "=", parts: 2) do
        [name, value] -> {decode_component(name), decode_component(value)}
        [name] -> {decode_component(name), ""}
      end
    end)
  end

  @doc "The non-empty values of one field, repeated values included."
  @spec values_for([{String.t(), String.t()}], String.t()) :: [String.t()]
  def values_for(pairs, field) do
    for {name, value} <- pairs, name == field, value != "", do: value
  end

  defp decode_component(text) do
    text |> String.replace("+", " ") |> URI.decode()
  rescue
    ArgumentError -> text
  end
end
