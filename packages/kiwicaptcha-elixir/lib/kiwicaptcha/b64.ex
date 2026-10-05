defmodule Kiwicaptcha.B64 do
  @moduledoc """
  Strict base64 and hex helpers. The BEAM decoder is lenient: it skips
  invalid characters and accepts every padding spelling. The wire
  protocols here require exactly one canonical spelling per value,
  mirroring the PHP strict decoder plus the re-encode equality check.
  """

  @standard_re ~r/\A[A-Za-z0-9+\/]*={0,2}\z/
  @unpadded_url_re ~r/\A[A-Za-z0-9_-]+\z/

  @doc "Encode to standard base64, padded, no newlines."
  @spec encode_std(binary()) :: String.t()
  def encode_std(bytes) when is_binary(bytes), do: Base.encode64(bytes)

  @doc """
  Decode canonical standard base64. Accepts exactly one spelling and
  returns `{:ok, bytes}` or `:error`.
  """
  @spec decode_std(String.t()) :: {:ok, binary()} | :error
  def decode_std(value) when is_binary(value) do
    if rem(byte_size(value), 4) == 0 and Regex.match?(@standard_re, value) do
      bytes = Base.decode64!(value)

      if encode_std(bytes) == value, do: {:ok, bytes}, else: :error
    else
      :error
    end
  end

  @doc "Encode to unpadded base64url, the driver trace wire format."
  @spec encode_url(binary()) :: String.t()
  def encode_url(bytes) when is_binary(bytes) do
    bytes
    |> Base.encode64()
    |> String.replace("+", "-")
    |> String.replace("/", "_")
    |> String.trim_trailing("=")
  end

  @doc "Decode canonical unpadded base64url, or `:error`."
  @spec decode_url(String.t()) :: {:ok, binary()} | :error
  def decode_url(value) when is_binary(value) do
    if String.contains?(value, "=") or not Regex.match?(@unpadded_url_re, value) do
      :error
    else
      standard = value |> String.replace("-", "+") |> String.replace("_", "/")

      standard =
        String.pad_trailing(
          standard,
          rem(4 - rem(byte_size(standard), 4), 4) + byte_size(standard),
          "="
        )

      case Base.decode64(standard) do
        {:ok, bytes} ->
          if encode_url(bytes) == value, do: {:ok, bytes}, else: :error

        :error ->
          :error
      end
    end
  end

  @doc "Whether a value is lowercase hex of an exact length."
  @spec lowercase_hex?(term(), non_neg_integer() | nil) :: boolean()
  def lowercase_hex?(value, length \\ nil)

  def lowercase_hex?(value, length) when is_binary(value) do
    base = value != "" and String.match?(value, ~r/\A[0-9a-f]*\z/)

    case length do
      nil -> base
      n -> base and String.length(value) == n
    end
  end

  def lowercase_hex?(_, _), do: false
end
