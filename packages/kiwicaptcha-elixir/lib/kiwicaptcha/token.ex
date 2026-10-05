defmodule Kiwicaptcha.Token do
  @moduledoc """
  The client-submitted solution, decoded from the kiwi__token hidden
  input. Wire format: base64(nonce "." counter "." duration_ms "."
  telemetry_json ["." execution_digest[":" execution_trace]] ["."
  rsw_proof]). The telemetry segment may contain dots, so decoding
  splits on all dots and peels the optional suffix segments right to
  left, independently.
  """

  @solver_max_hashes 20_000_000
  @max_duration_ms 3_600_000
  @max_raw_bytes 32_768
  @rsw_proof_re ~r/\A[0-9a-f]{512}\z/
  @digest_re ~r/\A[0-9a-f]{64}\z/

  defstruct [
    :nonce,
    :counter,
    :duration_ms,
    :telemetry,
    :execution_digest,
    :execution_trace,
    :rsw_proof
  ]

  @type t :: %__MODULE__{
          nonce: String.t(),
          counter: non_neg_integer(),
          duration_ms: non_neg_integer(),
          telemetry: map(),
          execution_digest: String.t() | nil,
          execution_trace: String.t() | nil,
          rsw_proof: String.t() | nil
        }

  @doc "The browser and wasm solver search ceiling."
  @spec solver_max_hashes :: pos_integer()
  def solver_max_hashes, do: @solver_max_hashes

  @doc "Hard ceiling for the client-reported duration (telemetry only)."
  @spec max_duration_ms :: pos_integer()
  def max_duration_ms, do: @max_duration_ms

  @doc """
  Encode a solution token to its canonical base64 wire form. The
  telemetry object is always rendered as a JSON object, never an array,
  and the trace rides in its wire spelling, so a decode and encode
  round trip is byte identical.
  """
  @spec encode(t()) :: String.t()
  def encode(%__MODULE__{} = token) do
    plain =
      IO.iodata_to_binary([
        token.nonce,
        ".",
        Integer.to_string(token.counter),
        ".",
        Integer.to_string(token.duration_ms),
        ".",
        json_encode!(token.telemetry),
        execution_segment(token),
        rsw_segment(token)
      ])

    Kiwicaptcha.B64.encode_std(plain)
  end

  defp execution_segment(%__MODULE__{execution_digest: nil}), do: ""
  defp execution_segment(%__MODULE__{execution_digest: d, execution_trace: nil}), do: ".#{d}"

  defp execution_segment(%__MODULE__{execution_digest: d, execution_trace: t}), do: ".#{d}:#{t}"

  defp rsw_segment(%__MODULE__{rsw_proof: nil}), do: ""
  defp rsw_segment(%__MODULE__{rsw_proof: p}), do: ".#{p}"

  defp json_encode!(value) do
    case Kiwicaptcha.Json.encode(value) do
      {:ok, encoded} -> encoded
      :error -> raise Kiwicaptcha.DecodeError, code: :malformed
    end
  end

  @doc """
  Decode a raw token string with the exact acceptance split of the PHP
  and Rust decoders: canonical base64, UTF-8 plaintext, at least four
  segments, the canonical decimal rules, the solver counter ceiling,
  the duration ceiling and a JSON-object telemetry segment.
  """
  @spec decode(String.t()) :: {:ok, t()} | {:error, atom()}
  def decode(raw) when is_binary(raw) do
    if byte_size(raw) > @max_raw_bytes do
      {:error, :malformed}
    else
      case Kiwicaptcha.B64.decode_std(raw) do
        :error ->
          {:error, :invalid_base64}

        {:ok, plain_bytes} ->
          case decode_plain(plain_bytes) do
            {:ok, token} -> {:ok, token}
            {:error, reason} -> {:error, reason}
          end
      end
    end
  end

  @doc "Like decode/1 but raises on any structural failure."
  @spec decode!(String.t()) :: t()
  def decode!(raw) do
    case decode(raw) do
      {:ok, token} -> token
      {:error, reason} -> raise Kiwicaptcha.DecodeError, code: reason
    end
  end

  defp decode_plain(plain_bytes) do
    plain = :binary.copy(plain_bytes)

    unless String.valid?(plain) do
      throw_decode(:invalid_utf8)
    end

    parts = String.split(plain, ".", parts: :infinity)

    if length(parts) < 4 do
      throw_decode(:malformed)
    end

    with {:ok, peeled} <- peel_suffixes(parts),
         {:ok, fields} <- check_core(peeled) do
      telemetry_result = Kiwicaptcha.Json.decode(fields.telemetry_str)

      with {:ok, parsed} <- telemetry_result,
           true <- is_map(parsed) and not Map.has_key?(parsed, :__struct__),
           {:ok, digest} <- check_digest(fields.execution_digest) do
        {:ok,
         %__MODULE__{
           nonce: fields.nonce,
           counter: fields.counter,
           duration_ms: fields.duration_ms,
           telemetry: parsed,
           execution_digest: digest,
           execution_trace: fields.execution_trace,
           rsw_proof: fields.rsw_proof
         }}
      else
        _ -> {:error, :malformed}
      end
    end
  catch
    {:decode_error, reason} -> {:error, reason}
  end

  defp throw_decode(reason), do: throw({:decode_error, reason})

  # Peel the optional suffix segments right to left, independently.
  defp peel_suffixes(parts) do
    {parts, rsw_proof} =
      case List.last(parts) do
        last when length(parts) >= 5 and is_binary(last) ->
          if Regex.match?(@rsw_proof_re, last) do
            {Enum.drop(parts, -1), last}
          else
            {parts, nil}
          end

        _ ->
          {parts, nil}
      end

    {parts, digest, trace} =
      if length(parts) >= 5 do
        segment = List.last(parts)

        case String.split(segment, ":", parts: 2) do
          [digest_part] ->
            if Regex.match?(@digest_re, digest_part) do
              {Enum.drop(parts, -1), digest_part, nil}
            else
              {parts, nil, nil}
            end

          [digest_part, trace_part] ->
            cond do
              Regex.match?(@digest_re, digest_part) ->
                case Kiwicaptcha.B64.decode_url(trace_part) do
                  {:ok, _} -> {Enum.drop(parts, -1), digest_part, trace_part}
                  :error -> throw_decode(:malformed)
                end

              true ->
                {parts, nil, nil}
            end
        end
      else
        {parts, nil, nil}
      end

    {:ok, %{parts: parts, rsw_proof: rsw_proof, execution_digest: digest, execution_trace: trace}}
  end

  defp check_core(%{parts: parts} = peeled) do
    [nonce, counter_str, duration_str | telemetry_rest] = parts
    telemetry_str = Enum.join(telemetry_rest, ".")

    nonce_ok = String.length(nonce) == 44 and Regex.match?(~r/\A[A-Za-z0-9+\/]{43}=\z/, nonce)

    nonce_bytes_ok =
      case Kiwicaptcha.B64.decode_std(nonce) do
        {:ok, bytes} -> byte_size(bytes) == 32
        :error -> false
      end

    unless nonce_ok and nonce_bytes_ok do
      throw_decode(:malformed)
    end

    unless canonical_decimal?(counter_str) do
      throw_decode(:invalid_counter)
    end

    counter = String.to_integer(counter_str)

    if String.length(counter_str) > 8 or counter >= @solver_max_hashes do
      throw_decode(:counter_exceeds_solver_maximum)
    end

    unless canonical_decimal?(duration_str) do
      throw_decode(:invalid_duration)
    end

    duration_ms = String.to_integer(duration_str)

    if duration_ms > @max_duration_ms do
      throw_decode(:invalid_duration)
    end

    {:ok,
     %{nonce: nonce, counter: counter, duration_ms: duration_ms, telemetry_str: telemetry_str}
     |> Map.merge(Map.take(peeled, [:execution_digest, :execution_trace, :rsw_proof]))}
  end

  defp canonical_decimal?(segment) do
    segment != "" and Regex.match?(~r/\A\d+\z/, segment) and
      (String.length(segment) == 1 or not String.starts_with?(segment, "0"))
  end

  defp check_digest(nil), do: {:ok, nil}

  defp check_digest(digest) do
    if Regex.match?(~r/\A[0-9a-f]{64}\z/, digest), do: {:ok, digest}, else: {:error, :malformed}
  end
end
