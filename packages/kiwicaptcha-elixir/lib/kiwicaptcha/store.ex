defmodule Kiwicaptcha.Store do
  @moduledoc """
  The store adapter behaviour of the verifier: the atomic one-shot
  surface verify needs, implementable over any backend whose
  transitions are atomic. The three shipped adapters (memory, Redis,
  SQLite) each hold the exactly-once guarantee: two racing consumers of
  one nonce cannot both win the pending-to-consumed transition.
  """

  @default_ttl_margin_secs 60
  @operation_identity_re ~r/\A[A-Za-z0-9_-]{1,128}\z/

  @typedoc "The committed deterministic result of a consumed record."
  @type consumed_result :: %{valid: boolean(), binding: String.t() | nil, mac: String.t() | nil}

  @typedoc "The consume transition result plus the retained record."
  @type consumed_snapshot :: %{
          record: Kiwicaptcha.Record.t(),
          consumed_now: boolean(),
          consumed_before: boolean(),
          consumed_result: consumed_result() | nil,
          operation_identity: String.t() | nil
        }

  @typedoc "The single-snapshot terminal-state classification of one nonce."
  @type runtime_state :: %{
          kind: :missing | :pending | :consumed | :cancelled,
          record: Kiwicaptcha.Record.t() | nil,
          consumed: consumed_snapshot() | nil
        }

  @typedoc "The fused cleanup outcome."
  @type delete_if_pending_outcome :: %{
          kind: :missing | :deleted_pending | :cancelled | :corrupt | :consumed,
          consumed: consumed_snapshot() | nil
        }

  @doc "The default retention margin past the signed expiry (the Redis mirror)."
  @spec default_ttl_margin_secs :: pos_integer()
  def default_ttl_margin_secs, do: @default_ttl_margin_secs

  @doc """
  Validate a logical-operation identity: 1 to 128 bytes of
  [A-Za-z0-9_-], or nil. The validation runs before any transition so a
  malformed identity never lands in storage.
  """
  @spec validated_operation_identity(term()) :: String.t() | nil
  def validated_operation_identity(nil), do: nil

  def validated_operation_identity(""),
    do: raise(Kiwicaptcha.RangeError, "operation identity must be 1..128 bytes of [A-Za-z0-9_-]")

  def validated_operation_identity(identity) when is_binary(identity) do
    if Regex.match?(@operation_identity_re, identity) do
      identity
    else
      raise Kiwicaptcha.RangeError, "operation identity must be 1..128 bytes of [A-Za-z0-9_-]"
    end
  end

  def validated_operation_identity(_),
    do: raise(Kiwicaptcha.RangeError, "operation identity must be 1..128 bytes of [A-Za-z0-9_-]")

  @doc """
  Decode the flat storage envelope the core writes: the record's wire
  fields plus the top-level state, consumed_result and
  operation_identity runtime fields. The record parse is strict; a
  corrupt committed result degrades to absent. `:error` on any
  structural failure (fail closed, never partially trusted).
  """
  @spec decode_envelope(String.t()) ::
          {:ok,
           %{
             state: String.t(),
             record: Kiwicaptcha.Record.t(),
             result: consumed_result() | nil,
             identity: String.t() | nil
           }}
          | :error
  def decode_envelope(raw) when is_binary(raw) do
    case json_decode(raw) do
      {:ok, %{} = envelope} ->
        state = envelope["state"]

        if is_binary(state) do
          record_fields =
            Map.drop(envelope, ["state", "consumed_result", "operation_identity"])

          case Kiwicaptcha.Record.from_json(record_fields) do
            {:ok, record} ->
              {:ok,
               %{
                 state: state,
                 record: record,
                 result: decode_result(envelope["consumed_result"]),
                 identity: identity(envelope)
               }}

            {:error, _} ->
              :error
          end
        else
          :error
        end

      _ ->
        :error
    end
  end

  def decode_envelope(_), do: :error

  defp json_decode(value), do: Kiwicaptcha.Json.decode(value)

  # A non-object committed result degrades to absent, never to a
  # partially trusted one.
  defp decode_result(nil), do: nil

  defp decode_result(raw) when is_map(raw) do
    unknown_keys = Map.keys(raw) -- ["valid", "binding", "mac"]
    valid = raw["valid"]

    if unknown_keys == [] and is_boolean(valid) do
      %{
        valid: valid,
        binding: if(is_binary(raw["binding"]), do: raw["binding"], else: nil),
        mac: if(is_binary(raw["mac"]), do: raw["mac"], else: nil)
      }
    end
  end

  defp decode_result(_), do: nil

  defp identity(envelope) do
    case envelope["operation_identity"] do
      identity when is_binary(identity) and identity != "" -> identity
      _ -> nil
    end
  end
end

defmodule Kiwicaptcha.Store.Behaviour do
  @moduledoc """
  The atomic store adapter callbacks. Every transition is one-shot; a
  failed transition raises Kiwicaptcha.StoreUnavailableError (fail
  closed as retryable) and never silently passes.

  * `authenticated_result_commit?/0` returns true when the backend
    commits consumed results carrying the server-state MAC.
  * `store/2` stores a pending record, replacing any record with the
    same nonce.
  * `find/2` peeks a record, or nil when the nonce is unknown or
    expired.
  * `runtime_state/2` returns the terminal-state snapshot: one read,
    never two.
  * `consume/3` is the one-shot consume transition. Nil answers
    missing, cancelled or corrupt; a nil identity records none.
    Raises Kiwicaptcha.StoreWriteError when a non-nil identity could
    not be recorded on a fresh flip.
  * `commit_result/5` commits the deterministic result of a consumed
    record, exactly once. False answers missing, not consumed, or
    already committed.
  * `delete_if_pending/2` is the fused cleanup: only the exact pending
    record is deleted.
  """

  @callback authenticated_result_commit?() :: boolean()
  @callback store(atom(), Kiwicaptcha.Record.t()) :: :ok
  @callback find(atom(), String.t()) :: Kiwicaptcha.Record.t() | nil
  @callback runtime_state(atom(), String.t()) :: Kiwicaptcha.Store.runtime_state()
  @callback consume(atom(), String.t(), String.t() | nil) ::
              Kiwicaptcha.Store.consumed_snapshot() | nil
  @callback commit_result(atom(), String.t(), boolean(), String.t() | nil, String.t() | nil) ::
              boolean()
  @callback delete_if_pending(atom(), String.t()) :: Kiwicaptcha.Store.delete_if_pending_outcome()
end
