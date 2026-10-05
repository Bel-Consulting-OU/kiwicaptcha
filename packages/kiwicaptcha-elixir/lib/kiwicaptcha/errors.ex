defmodule Kiwicaptcha.VerifyError do
  @moduledoc """
  Verify error codes: the machine readable snake_case vocabulary shared
  with the PHP and Rust cores. Values are stable wire tokens; logs,
  metrics and cross-service consumers switch on them without parsing
  prose.
  """

  @codes %{
    bad_signature: "challenge signature is invalid",
    expired: "challenge has expired",
    wrong_scope: "challenge was issued for a different scope",
    ip_mismatch: "challenge was issued to a different client IP",
    missing_client_ip: "challenge is IP-bound but no client IP was supplied",
    wrong_region: "challenge was issued for a different region",
    wrong_issuer: "challenge was issued by a different deployment",
    wrong_policy_version: "challenge was issued under a different security-policy epoch",
    unknown_kid: "unknown signing key id",
    too_fast: "solution arrived faster than the theoretical minimum (server-measured)",
    insufficient_work: "solution does not meet the difficulty target",
    malformed_record: "stored challenge record is malformed",
    record_not_found: "challenge record not found (unknown or already deleted)",
    malformed_token: "solution token is malformed",
    unsupported_argon2_params: "Argon2id parameters exceed the supported process ceilings",
    too_many_attempts: "too many verification attempts",
    telemetry_rejected: "bot-signal telemetry rejected the solution",
    capacity_exceeded: "verification capacity exceeded, try again shortly",
    admission_unavailable: "verification admission backend unavailable, try again shortly",
    storage_unavailable: "verification storage backend unavailable, try again shortly",
    consume_indeterminate:
      "verification storage response indeterminate, the challenge may or may not have been consumed",
    already_consumed: "the challenge was already consumed by a different logical operation",
    request_binding_mismatch:
      "the challenge is not bound to the expected application transaction",
    execution_mismatch:
      "the execution digest does not match the expected program trace of the challenge",
    unsupported_rsw_params:
      "the rsw challenge cannot be verified: this verifier lacks the matching trapdoor, or the signed sequential cost is out of bounds"
  }

  @type t :: atom()

  @doc "Every code in the shared vocabulary."
  @spec all() :: [atom()]
  def all, do: Map.keys(@codes)

  @doc "Whether a failure is exempt from the one-shot policy on a consumed record."
  @spec replay_exempt?(t()) :: boolean()
  def replay_exempt?(code),
    do: code in [:expired, :ip_mismatch, :missing_client_ip, :telemetry_rejected]

  @doc "Operator facing description of one failure code."
  @spec describe(t()) :: String.t()
  def describe(code), do: Map.fetch!(@codes, code)
end

defmodule Kiwicaptcha.MalformedRecordError do
  @moduledoc "Raised by the strict record parser on any structural violation."
  defexception [:message]
end

defmodule Kiwicaptcha.RangeError do
  @moduledoc """
  The local range violation: the Elixir spelling of the range
  rejections the PHP and Rust cores raise. Raised on short master
  secrets, malformed identities and out-of-bounds rsw material.
  """
  defexception [:message]
end

defmodule Kiwicaptcha.DecodeError do
  @moduledoc "Raised by the strict token decoder; carries the stable wire reason."
  defexception [:code]

  @impl true
  def message(%__MODULE__{code: code}), do: "token decode failed: #{code}"
end

defmodule Kiwicaptcha.StoreWriteError do
  @moduledoc "Raised when a store write could not be recorded atomically."
  defexception [:message]
end

defmodule Kiwicaptcha.StoreUnavailableError do
  @moduledoc "Raised on backend failure: the verifier answers storage_unavailable."
  defexception [:message]
end
