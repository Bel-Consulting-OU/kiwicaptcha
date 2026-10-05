defmodule Kiwicaptcha.Mac do
  @moduledoc """
  Authentication of the server written state that the challenge
  signature does not cover: the record metadata (issued_at_ns and the
  hostname) and the committed consumed result. The MAC input binds the
  full challenge string, so a MAC can never be transplanted to another
  record. Every variable-length field is length-prefixed and every
  optional field carries a presence tag, mirroring the Rust
  record_meta_mac and consumed_result_mac byte layout.
  """

  import Bitwise, only: [bor: 2, bxor: 2]

  @record_meta_domain "kiwi/record-meta/v1"
  @consumed_result_domain "kiwi/consumed-result/v1"

  @doc "The record-metadata domain string."
  @spec record_meta_domain :: String.t()
  def record_meta_domain, do: @record_meta_domain

  @doc "The consumed-result domain string."
  @spec consumed_result_domain :: String.t()
  def consumed_result_domain, do: @consumed_result_domain

  @doc "The wire shape of every server-state MAC: 64 lowercase hex."
  @spec server_state_mac_pattern :: Regex.t()
  def server_state_mac_pattern, do: ~r/\A[0-9a-f]{64}\z/

  @doc "The server-state key for a kid secret and the deployment tenant."
  @spec server_state_key(binary() | String.t(), String.t() | nil) :: binary()
  def server_state_key(secret, tenant_id \\ nil),
    do: Kiwicaptcha.Keys.derived_keys(secret, tenant_id).server_state_key

  defp lp(value), do: "#{byte_size(value)}:#{value}"
  defp opt(nil), do: "0"
  defp opt(value), do: "1:#{lp(value)}"

  @doc "The exact record-metadata MAC input bytes, pinned by the shared vectors."
  @spec record_meta_input(String.t(), non_neg_integer(), String.t() | nil) :: String.t()
  def record_meta_input(challenge, issued_at_ns, hostname) do
    Enum.join(
      [@record_meta_domain, lp(challenge), Integer.to_string(issued_at_ns), opt(hostname)],
      "\n"
    )
  end

  @doc "The exact consumed-result MAC input bytes, pinned by the shared vectors."
  @spec consumed_result_input(String.t(), boolean(), String.t() | nil, String.t() | nil) ::
          String.t()
  def consumed_result_input(challenge, valid, binding, operation_identity) do
    Enum.join(
      [
        @consumed_result_domain,
        lp(challenge),
        if(valid, do: "1", else: "0"),
        opt(binding),
        opt(operation_identity)
      ],
      "\n"
    )
  end

  @doc "Hex HMAC-SHA256 keyed helper shared across the SDK."
  @spec hmac_hex(binary(), iodata()) :: String.t()
  def hmac_hex(key, message),
    do:
      Base.encode16(:crypto.mac(:hmac, :sha256, key, IO.iodata_to_binary(message)), case: :lower)

  @doc "The record-metadata MAC over the challenge, issuance clock and hostname."
  @spec record_meta_mac(binary(), String.t(), non_neg_integer(), String.t() | nil) :: String.t()
  def record_meta_mac(key, challenge, issued_at_ns, hostname) do
    hmac_hex(key, record_meta_input(challenge, issued_at_ns, hostname))
  end

  @doc "The consumed-result MAC over the challenge, verdict, binding and identity."
  @spec consumed_result_mac(binary(), String.t(), boolean(), String.t() | nil, String.t() | nil) ::
          String.t()
  def consumed_result_mac(key, challenge, valid, binding, operation_identity) do
    hmac_hex(key, consumed_result_input(challenge, valid, binding, operation_identity))
  end

  @doc """
  Constant-time comparison over equal-length binaries; false on any
  length mismatch. The fold runs over every byte position regardless
  of where a difference sits.
  """
  @spec timing_safe_equals(term(), term()) :: boolean()
  def timing_safe_equals(a, b)

  def timing_safe_equals(a, b) when is_binary(a) and is_binary(b) do
    if byte_size(a) == byte_size(b) do
      ba = :binary.bin_to_list(a)
      bb = :binary.bin_to_list(b)
      diff = Enum.zip(ba, bb) |> Enum.reduce(0, fn {x, y}, acc -> bor(acc, bxor(x, y)) end)
      diff == 0
    else
      false
    end
  end

  def timing_safe_equals(_, _), do: false
end
