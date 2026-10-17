defmodule Kiwicaptcha.Json do
  @moduledoc """
  The JSON seam: the standard library JSON module when present, with
  Jason as the optional fallback for older Elixir releases. Every
  encode and decode in the SDK funnels through here.
  """

  # Maximum nesting depth of the token telemetry object, the
  # protocol/limits.json token_max_telemetry_depth register row. The
  # scalar level is zero, so the 32nd nested container is accepted and
  # the 33rd is outside the wire language.
  @max_telemetry_depth 32

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

  @doc """
  Decode a telemetry document with the wire contract's duplicate-key
  resolution: the last value for a repeated key wins at every nesting
  level, the same resolution every other hosted decoder applies. The
  generic decode/1 keeps the first value, so it must never be used for
  the solution token.
  """
  @spec decode_telemetry(String.t()) :: {:ok, term()} | :error
  def decode_telemetry(value) when is_binary(value) do
    result =
      cond do
        json_loaded?() ->
          decode_telemetry_stdlib(value)

        Code.ensure_loaded?(Jason) and function_exported?(Jason, :decode, 2) ->
          decode_telemetry_jason(value)

        true ->
          :error
      end

    case result do
      {:ok, parsed} ->
        if depth_exceeds?(parsed, @max_telemetry_depth), do: :error, else: {:ok, parsed}

      :error ->
        :error
    end
  end

  # True when the parsed telemetry tree nests deeper than max
  # containers. The walk is iterative so hostile nesting cannot turn the
  # check itself into a stack overflow.
  defp depth_exceeds?(value, max), do: depth_walk([{value, 1}], max)

  defp depth_walk([], _max), do: false

  defp depth_walk([{value, depth} | rest], max) when is_map(value) or is_list(value) do
    if depth > max do
      true
    else
      children = if is_map(value), do: Map.values(value), else: value
      depth_walk(Enum.map(children, &{&1, depth + 1}) ++ rest, max)
    end
  end

  defp depth_walk([_leaf | rest], max), do: depth_walk(rest, max)

  defp decode_telemetry_stdlib(value) do
    # The stdlib decoder accumulates object members in reverse wire
    # order; reversing restores the wire order and Map.new keeps the
    # last value for a repeated key.
    finish = fn acc, old -> {Map.new(Enum.reverse(acc)), old} end

    try do
      case :json.decode(value, :ok, %{object_finish: finish}) do
        {parsed, :ok, <<>>} -> {:ok, parsed}
        _ -> :error
      end
    rescue
      _ -> :error
    end
  end

  defp decode_telemetry_jason(value) do
    try do
      case Jason.decode(value, objects: :ordered_objects) do
        {:ok, parsed} -> {:ok, last_wins(parsed)}
        :error -> :error
      end
    rescue
      _ -> :error
    end
  end

  defp last_wins(%Jason.OrderedObject{values: values}) do
    Map.new(values, fn {key, value} -> {key, last_wins(value)} end)
  end

  defp last_wins(value) when is_list(value), do: Enum.map(value, &last_wins/1)
  defp last_wins(value), do: value

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
