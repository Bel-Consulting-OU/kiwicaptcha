defmodule Kiwicaptcha.ExecutionPolicy do
  @moduledoc """
  The execution delegation plane of the elixir SDK: an execution-armed
  record demands the browser-trace walker, an oracle this SDK does not
  carry. The default policy fails every armed record closed
  (`:execution_mismatch`, documented). The sidecar policy delegates
  that single verification to a co-located kiwicaptcha-verifier sidecar
  over HTTP: the sidecar carries the full Rust core with the real
  execution verifier, consumes the record (single-use semantics
  preserved: the sidecar consumes, this SDK never double-consumes) and
  answers the provider-shaped verdict mapped back into this SDK's
  vocabulary.

  Trust boundary: the sidecar decides acceptances, so it must be
  co-located and trusted to the same standard as the verifier itself.
  The bearer credential is sent per request, and a refused credential
  denies instead of retrying into an untrusted verifier.
  """

  alias Kiwicaptcha.Sidecar

  defstruct sidecar_url: nil, bearer_token: nil, timeout_ms: 5000

  @type t :: %__MODULE__{
          sidecar_url: String.t() | nil,
          bearer_token: String.t() | nil,
          timeout_ms: pos_integer()
        }

  @doc "Whether the policy delegates the execution-armed dimension."
  @spec enabled?(t() | nil) :: boolean()
  def enabled?(nil), do: false

  def enabled?(%__MODULE__{sidecar_url: url}) when is_binary(url) do
    String.trim(url) != ""
  end

  def enabled?(%__MODULE__{}), do: false

  @doc """
  Hands one execution-armed verification to the sidecar. Answers
  `{:ok, :ok}` or `{:deny, code}` where the code is the shared wire
  vocabulary carried verbatim; the transport failures fail closed
  (`:storage_unavailable` keeps the retry disposition with the record
  intact). The caller's telemetry posture and operation identity ride
  along so a sidecar that enforces either never sees a watered-down
  request.
  """
  @spec delegate(t(), String.t(), String.t(), String.t() | nil, boolean(), String.t() | nil) ::
          {:ok, :ok} | {:deny, atom() | String.t()}
  def delegate(
        %__MODULE__{} = policy,
        raw_token,
        scope,
        client_ip,
        enforce_telemetry \\ false,
        operation_identity \\ nil
      ) do
    Sidecar.post_verify(policy, raw_token, scope, client_ip, enforce_telemetry, operation_identity)
  end
end

defmodule Kiwicaptcha.Sidecar do
  @moduledoc false

  def post_verify(policy, raw_token, scope, client_ip, enforce_telemetry \\ false, operation_identity \\ nil) do
    base = String.trim_trailing(String.trim(policy.sidecar_url || ""), "/")
    url = base <> "/verify"

    body =
      Kiwicaptcha.Json.encode!(%{
        token: raw_token,
        scope: scope,
        remoteip: client_ip,
        enforce_telemetry: enforce_telemetry == true,
        operation_identity: operation_identity
      })

    headers =
      [{~c"content-type", ~c"application/json"}] ++
        if(policy.bearer_token in [nil, ""],
          do: [],
          else: [{~c"authorization", String.to_charlist("Bearer " <> policy.bearer_token)}]
        )

    request = {String.to_charlist(url), headers, ~c"application/json", body}

    http_options = [
      timeout: policy.timeout_ms,
      connect_timeout: policy.timeout_ms
    ]

    case :httpc.request(:post, request, http_options, body_format: :binary) do
      {:ok, {{_, status, _}, _headers, response_body}} ->
        case status do
          status when status in [401, 403] ->
            # The sidecar refused the credential: never retry into an
            # untrusted verifier, fail closed with a deny.
            {:deny, :execution_mismatch}

          status when status >= 500 ->
            {:deny, :storage_unavailable}

          200 ->
            payload = decode(response_body)

            cond do
              payload["success"] == true ->
                {:ok, :ok}

              is_binary(payload["kiwi-code"]) and payload["kiwi-code"] != "" ->
                # The kiwi-code is the shared wire vocabulary; the atom
                # already exists in the errors module, so the existing-
                # atom conversion stays inside the known vocabulary.
                {:deny, String.to_existing_atom(payload["kiwi-code"])}

              true ->
                {:deny, :execution_mismatch}
            end

          _ ->
            {:deny, :execution_mismatch}
        end

      {:error, _reason} ->
        {:deny, :storage_unavailable}
    end
  end

  defp decode(body) when is_binary(body) do
    case Kiwicaptcha.Json.decode(body) do
      {:ok, map} -> map
      _ -> %{}
    end
  end
end
