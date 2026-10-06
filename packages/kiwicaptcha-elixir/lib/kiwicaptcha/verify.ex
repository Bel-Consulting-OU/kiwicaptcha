defmodule Kiwicaptcha.Verify do
  @moduledoc """
  The verifier: the exact cheap-gate order and the consumed resolution
  of the PHP Verifier, over the storage seam.

  The gate order is normative and mirrors Verifier::verify(): nonce
  match, structure, protocol gate, kid revocation, kid resolution,
  signature, Argon2id ceilings, rsw bounds, TTL, scope, request
  binding, IP binding, region, policy epoch (with the rollout floor
  window), issuer, execution binding and minimum duration. Then comes
  the opt-in telemetry gate, the terminal-state resolution, the
  one-shot consume, the proof re-derivation, the post-derive final
  revalidation and the result commit.

  Verify is pure local: it never calls out to any network service. The
  only side effects are the storage transitions the one-shot model
  requires. Execution-armed records (the signed e= commitment) are
  refused deterministically with :execution_mismatch: the browser
  trace walker is a browser-behavior oracle this SDK does not carry,
  and an armed record must never pass without it. Argon2id records are
  authentic but unrepresentable without a native Argon2id runtime, and
  fail closed with the cores' unsupported mapping.
  """

  @max_ttl_secs 300
  @max_clock_skew 60
  @skew_tolerance_us 5_000_000

  @min_argon_memory_kib 8
  @max_argon_memory_kib 65_536
  @min_argon_time 3
  @max_argon_time 16
  @min_parallelism 1
  @max_parallelism 4

  @min_difficulty 1
  @max_difficulty 20

  @typedoc """
  The verification result of the shared server SDK contract: ok,
  disposition, decision_handle and price, with the additive evidence
  fields the cores expose.
  """
  @type result :: %{
          ok: boolean(),
          disposition: :allow | :deny,
          decision_handle: String.t() | nil,
          price: String.t() | nil,
          code: atom(),
          detail: String.t() | nil,
          request_binding: String.t() | nil,
          from_stored_result: boolean(),
          solve_duration_ms: non_neg_integer() | nil,
          decoy_field: String.t() | nil
        }

  @typedoc "The rsw trapdoor configuration of one deployment."
  @type rsw_config :: %{
          optional(:modulus_n) => String.t() | nil,
          optional(:lambda) => String.t() | nil,
          optional(:verification_keys) => %{
            optional(String.t()) => %{modulus_n: String.t(), lambda: String.t()}
          },
          optional(:allow_legacy_identity) => boolean()
        }

  @typedoc "The verify options of one call."
  @type options :: %{
          storage: module(),
          secret_key: binary() | String.t(),
          expected_scope: String.t() | nil,
          client_ip: String.t() | nil,
          now_ns: non_neg_integer() | nil,
          now: (-> non_neg_integer()) | nil,
          enforce_telemetry: boolean(),
          operation_identity: String.t() | nil,
          expected_request_binding: String.t() | nil,
          binding_expectation: :exact | :legacy,
          expected_policy_version: pos_integer() | nil,
          policy_version_floor: pos_integer() | nil,
          region: String.t() | nil,
          expected_issuer: String.t() | nil,
          secrets_by_kid: %{optional(pos_integer()) => binary() | String.t()},
          revoked_kids: [pos_integer()],
          tenant_id: String.t() | nil,
          accept_legacy_v1: boolean(),
          rsw: rsw_config() | nil
        }

  @doc "The wire ceilings the verifier enforces."
  def max_ttl_secs, do: @max_ttl_secs
  def max_clock_skew, do: @max_clock_skew
  def skew_tolerance_us, do: @skew_tolerance_us

  def min_argon_memory_kib, do: @min_argon_memory_kib
  def max_argon_memory_kib, do: @max_argon_memory_kib
  def min_argon_time, do: @min_argon_time
  def max_argon_time, do: @max_argon_time
  def min_parallelism, do: @min_parallelism
  def max_parallelism, do: @max_parallelism
  def min_difficulty, do: @min_difficulty
  def max_difficulty, do: @max_difficulty

  @doc "The default options, merged under whatever the caller supplies."
  @spec default_options() :: map()
  def default_options do
    %{
      storage: nil,
      secret_key: nil,
      expected_scope: nil,
      client_ip: nil,
      now_ns: nil,
      now: nil,
      enforce_telemetry: false,
      operation_identity: nil,
      expected_request_binding: nil,
      binding_expectation: :exact,
      expected_policy_version: nil,
      policy_version_floor: nil,
      region: nil,
      expected_issuer: nil,
      secrets_by_kid: %{},
      revoked_kids: [],
      tenant_id: nil,
      accept_legacy_v1: false,
      rsw: nil
    }
  end

  defp invalid(code) do
    %{
      ok: false,
      disposition: :deny,
      decision_handle: nil,
      price: nil,
      code: code,
      detail: Kiwicaptcha.VerifyError.describe(code),
      request_binding: nil,
      from_stored_result: false,
      solve_duration_ms: nil,
      decoy_field: nil
    }
  end

  defp valid(nonce, price, request_binding, from_stored, duration_ms, decoy_field) do
    %{
      ok: true,
      disposition: :allow,
      decision_handle: nonce,
      price: price,
      code: :"",
      detail: nil,
      request_binding: request_binding,
      from_stored_result: from_stored,
      solve_duration_ms: duration_ms,
      decoy_field: decoy_field
    }
  end

  @doc "The work-ladder rung name of a verified record's signed parameters."
  @spec ladder_rung(Kiwicaptcha.Record.t()) :: String.t()
  def ladder_rung(%Kiwicaptcha.Record{} = record) do
    cond do
      record.algorithm == "rsw" ->
        "rsw"

      record.algorithm == "argon2id" ->
        mib = div(record.m_kib, 1024)
        if mib in [16, 32, 64], do: "argon#{mib}", else: "argon#{record.m_kib}kib"

      record.target_bits in [16, 18, 20] ->
        "sha#{record.target_bits}"

      true ->
        "sha#{record.target_bits}bit"
    end
  end

  defp resolved_secrets(options) do
    by_kid =
      Map.new(options.secrets_by_kid, fn {kid, secret} ->
        kid = if is_integer(kid), do: kid, else: String.to_integer(to_string(kid))
        {kid, normalize_secret(secret)}
      end)

    %{by_kid: by_kid, revoked: MapSet.new(options.revoked_kids)}
  end

  defp normalize_secret(secret) when is_binary(secret), do: secret
  defp normalize_secret(secret), do: IO.iodata_to_binary([secret])

  defp now_secs(options) do
    if options.now, do: options.now.(), else: System.system_time(:second)
  end

  @doc """
  Verify a client-submitted solution token against the store: the pure
  local operation of the shared server SDK contract. The cheap-gate
  order mirrors the PHP and Rust verifiers exactly.
  """
  @spec verify(String.t(), map()) :: result()
  def verify(raw_token, options) when is_binary(raw_token) and is_map(options) do
    options = Map.merge(default_options(), options)
    secrets = resolved_secrets(options)
    legacy_secret = normalize_secret(options.secret_key)

    case Kiwicaptcha.Token.decode(raw_token) do
      {:error, _} -> invalid(:malformed_token)
      {:ok, token} -> run_verify(token, raw_token, options, secrets, legacy_secret)
    end
  end

  defp run_verify(token, raw_token, options, secrets, legacy_secret) do
    case snapshot(options.storage, token.nonce) do
      {:error, :storage} -> invalid(:storage_unavailable)
      {:ok, %{kind: :missing}} -> invalid(:record_not_found)
      {:ok, state} -> peeked(state, token, raw_token, options, secrets, legacy_secret)
    end
  end

  # The storage surface: a module implementing the behaviour, a struct
  # adapter whose module implements it over the struct, or a plain map
  # of funs (tests and tools). Every call funnels through here.
  defp call_storage(storage, fun, args)

  defp call_storage(storage, fun, args) when is_atom(storage) do
    apply(storage, fun, args)
  end

  defp call_storage(storage, fun, args)
       when is_map(storage) and is_map_key(storage, :__struct__) do
    apply(storage.__struct__, fun, [storage | args])
  end

  defp call_storage(storage, fun, args) when is_map(storage) do
    case Map.fetch(storage, fun) do
      {:ok, fun2} when is_function(fun2) -> apply(fun2, args)
      _ -> raise "the storage map carries no #{inspect(fun)} fun"
    end
  end

  defp snapshot(storage, nonce) do
    {:ok, call_storage(storage, :runtime_state, [nonce])}
  rescue
    _ -> {:error, :storage}
  end

  defp peeked(state, token, raw_token, options, secrets, legacy_secret) do
    peek =
      if state.record do
        {:found, state.record}
      else
        find_record(options.storage, token.nonce)
      end

    case peek do
      {:storage_error, _} -> invalid(:storage_unavailable)
      {:missing, _} -> invalid(:record_not_found)
      {:found, record} -> cheap_phase(state, record, token, raw_token, options, secrets, legacy_secret)
    end
  end

  defp find_record(storage, nonce) do
    case call_storage(storage, :find, [nonce]) do
      nil -> {:missing, nil}
      record -> {:found, record}
    end
  rescue
    _ -> {:storage_error, nil}
  end

  defp cheap_phase(state, peek, token, raw_token, options, secrets, legacy_secret) do
    # The execution delegation plane: an armed record under a sidecar
    # policy delegates the execution dimension after the cheap phase
    # proved everything the SDK checks locally.
    policy = if is_map(options), do: Map.get(options, :execution_policy), else: nil
    delegate_execution = Kiwicaptcha.ExecutionPolicy.enabled?(policy) and peek.execution_program != nil

    case cheap_phase_check(
           options,
           secrets,
           legacy_secret,
           peek,
           token,
           true,
           now_micros(options),
           delegate_execution
         ) do
      nil ->
        if delegate_execution do
          case Kiwicaptcha.ExecutionPolicy.delegate(policy, raw_token, Map.get(options, :expected_scope), Map.get(options, :client_ip)) do
            {:ok, :ok} ->
              valid(peek.nonce, ladder_rung(peek), peek.request_binding, true, nil, peek.decoy_field)

            {:deny, code} ->
              # A known wire code maps onto the vocabulary atoms; an
              # unknown one stays the deterministic deny (never widened).
              if is_atom(code) and code != nil do
                invalid(code)
              else
                invalid(:execution_mismatch)
              end
          end
        else
          telemetry_gate(state, peek, token, options, secrets, legacy_secret)
        end

      failure ->
        handle_failure(state, failure, peek, token, options, secrets, legacy_secret)
    end
  end

  defp now_micros(options) do
    options.now_ns || System.system_time(:microsecond)
  end

  defp handle_failure(state, failure, peek, token, options, secrets, legacy_secret) do
    if failure == :missing_client_ip do
      # MissingClientIp never deletes: the caller can retry with the
      # IP. A consumed record resolves through the compositional
      # replay gate, exactly like the fused path.
      if state.kind == :consumed and state.consumed do
        case replay_security_check(
               options,
               secrets,
               legacy_secret,
               peek,
               token,
               now_micros(options)
             ) do
          nil ->
            resolve_consumed_record(
              options,
              secrets,
              legacy_secret,
              state.consumed,
              token.nonce,
              options.operation_identity
            )

          hard ->
            invalid(hard)
        end
      else
        invalid(failure)
      end
    else
      one_shot_failure(failure, peek, token, options, secrets, legacy_secret)
    end
  end

  defp one_shot_failure(failure, peek, token, options, secrets, legacy_secret) do
    case delete_if_pending(options.storage, token.nonce) do
      {:error, :storage} ->
        invalid(:storage_unavailable)

      {:ok, %{kind: :consumed, consumed: consumed}} ->
        if Kiwicaptcha.VerifyError.replay_exempt?(failure) do
          # Consumed plus an exempt circumstance: the exempt failure
          # may not mask a hard verdict on the same request.
          case replay_security_check(
                 options,
                 secrets,
                 legacy_secret,
                 peek,
                 token,
                 now_micros(options)
               ) do
            nil ->
              resolve_consumed_record(
                options,
                secrets,
                legacy_secret,
                consumed,
                token.nonce,
                options.operation_identity
              )

            hard ->
              invalid(hard)
          end
        else
          # A hard security verdict on a consumed record: the failure
          # stands and the evidence stays preserved.
          invalid(failure)
        end

      {:ok, _} ->
        # Missing, deleted pending, cancelled or corrupt: the one-shot
        # verdict stands.
        invalid(failure)
    end
  end

  defp delete_if_pending(storage, nonce) do
    {:ok, call_storage(storage, :delete_if_pending, [nonce])}
  rescue
    _ -> {:error, :storage}
  end

  defp telemetry_gate(state, peek, token, options, secrets, legacy_secret) do
    bot_signal =
      token.telemetry == %{} or
        Kiwicaptcha.Telemetry.bot_signal?(token.telemetry, token.duration_ms)

    if options.enforce_telemetry and bot_signal and state.kind != :consumed do
      case delete_if_pending(options.storage, token.nonce) do
        {:error, :storage} ->
          invalid(:storage_unavailable)

        {:ok, %{kind: :consumed, consumed: consumed}} ->
          case replay_security_check(
                 options,
                 secrets,
                 legacy_secret,
                 peek,
                 token,
                 now_micros(options)
               ) do
            nil ->
              resolve_consumed_record(
                options,
                secrets,
                legacy_secret,
                consumed,
                token.nonce,
                options.operation_identity
              )

            hard ->
              invalid(hard)
          end

        {:ok, _} ->
          invalid(:telemetry_rejected)
      end
    else
      terminal_state(state, token, options, secrets, legacy_secret)
    end
  end

  defp terminal_state(state, token, options, secrets, legacy_secret) do
    cond do
      state.kind == :cancelled ->
        invalid(:record_not_found)

      state.kind == :consumed and state.consumed ->
        resolve_consumed_record(
          options,
          secrets,
          legacy_secret,
          state.consumed,
          token.nonce,
          options.operation_identity
        )

      true ->
        consume_and_prove(token, options, secrets, legacy_secret)
    end
  end

  defp consume_and_prove(token, options, secrets, legacy_secret) do
    consumed =
      try do
        Kiwicaptcha.Store.validated_operation_identity(options.operation_identity)
        {:ok, call_storage(options.storage, :consume, [token.nonce, options.operation_identity])}
      rescue
        _ -> {:error, :indeterminate}
      end

    case consumed do
      {:error, :indeterminate} ->
        # A lost transition response is ambiguous: the challenge may
        # or may not have been consumed.
        invalid(:consume_indeterminate)

      {:ok, nil} ->
        invalid(:record_not_found)

      {:ok, %{consumed_before: true} = consumed} ->
        resolve_consumed_record(
          options,
          secrets,
          legacy_secret,
          consumed,
          token.nonce,
          options.operation_identity
        )

      {:ok, consumed} ->
        prove(
          consumed.record,
          token,
          options,
          secrets,
          legacy_secret,
          consumed.operation_identity
        )
    end
  end

  defp prove(record, token, options, secrets, legacy_secret, operation_identity) do
    consumed_secret = secret_for_key(secrets, record, legacy_secret)

    # The consumed instance must be the challenge that was validated
    # and signed-checked via the peek: a swapped record fails closed.
    if record.nonce != token.nonce or consumed_secret == nil or
         not validate_record(record) or
         not verify_record_signature(options, record, consumed_secret) do
      invalid(:malformed_record)
    else
      cond do
        not argon2_ceilings_ok?(record) ->
          invalid(:unsupported_argon2_params)

        not rsw_params_ok?(record) ->
          invalid(:unsupported_rsw_params)

        not policy_version_accepted?(options, record.policy_version || 1) ->
          invalid(:wrong_policy_version)

        options.expected_issuer != nil and record.issuer != options.expected_issuer ->
          invalid(:wrong_issuer)

        true ->
          derive_proof(record, token, options, legacy_secret, consumed_secret, operation_identity)
      end
    end
  end

  defp derive_proof(record, token, options, _legacy_secret, consumed_secret, operation_identity) do
    case recompute_valid_proof(options.rsw, record, token) do
      :unsupported ->
        # Authentic but unrepresentable by this verifier: the
        # per-algorithm mapping of the cores.
        mapped =
          case record.algorithm do
            "rsw" -> :unsupported_rsw_params
            "argon2id" -> :unsupported_argon2_params
            _ -> :malformed_record
          end

        invalid(mapped)

      valid_proof ->
        consumed = %{
          record: record,
          operation_identity: operation_identity,
          secret: consumed_secret
        }

        # Post-derive final revalidation against the current clock and
        # the current expectations, for both valid and invalid
        # derivations.
        now = now_secs(options)

        cond do
          now >= record.expires_at ->
            invalid(:expired)

          not policy_version_accepted?(options, record.policy_version || 1) ->
            invalid(:wrong_policy_version)

          options.region != nil and record.region != options.region ->
            invalid(:wrong_region)

          options.expected_issuer != nil and record.issuer != options.expected_issuer ->
            invalid(:wrong_issuer)

          not valid_proof ->
            commit_and_answer(consumed, options, :insufficient_work, false)

          true ->
            commit_and_answer(consumed, options, :ok, true)
        end
    end
  end

  defp commit_and_answer(consumed, options, outcome, valid_proof) do
    best_effort_commit(consumed, options, valid_proof)

    record = consumed.record

    if outcome == :ok do
      receipt = options.now_ns || System.system_time(:microsecond)

      valid(
        record.nonce,
        ladder_rung(record),
        record.request_binding,
        false,
        measurable_solve_duration_ms(record, receipt),
        record.decoy_field
      )
    else
      invalid(outcome)
    end
  end

  defp best_effort_commit(consumed, options, valid_proof) do
    secret = consumed.secret

    if secret do
      mac =
        Kiwicaptcha.Mac.consumed_result_mac(
          Kiwicaptcha.Mac.server_state_key(secret, options.tenant_id),
          consumed.record.challenge,
          valid_proof,
          consumed.record.request_binding,
          consumed.operation_identity
        )

      try do
        call_storage(options.storage, :commit_result, [
          consumed.record.nonce,
          valid_proof,
          consumed.record.request_binding,
          mac
        ])
      rescue
        _ -> :ok
      catch
        _ -> :ok
      end
    end

    :ok
  end

  # Whether the storage commits authenticated results: a behaviour
  # module or a fun-map adapter answers; a surface that stays silent
  # counts as not committing (fail closed).
  defp storage_module_option?(storage) when is_atom(storage) do
    function_exported?(storage, :authenticated_result_commit?, 0) and
      storage.authenticated_result_commit?()
  end

  defp storage_module_option?(storage) when is_map(storage) do
    case Map.fetch(storage, :authenticated_result_commit?) do
      {:ok, fun} when is_function(fun, 0) -> fun.()
      _ -> false
    end
  end

  defp storage_module_option?(_), do: false

  defp secret_for_key(secrets, record, legacy_secret) do
    if map_size(secrets.by_kid) == 0 do
      legacy_secret
    else
      newest = Enum.max(Map.keys(secrets.by_kid))

      if record.kid > newest, do: nil, else: secrets.by_kid[record.kid]
    end
  end

  defp cheap_phase_check(options, secrets, legacy_secret, record, token, check_timing, now_ns, delegate_execution \\ false) do
    # 0. The record must carry the nonce it was loaded under. A nil
    # result means every gate passed.
    if record.nonce != token.nonce do
      :malformed_record
    else
      gate =
        with :ok <- check_authenticated_shape(options, secrets, legacy_secret, record),
             :ok <- if(check_timing, do: check_ttl(options, record), else: :ok),
             :ok <- check_scope_and_binding(options, record),
             :ok <-
               check_ip_binding(options, record, secret_for_key(secrets, record, legacy_secret)),
             :ok <- check_deployment_expectations(options, record),
             :ok <- if(delegate_execution, do: :ok, else: check_execution_binding(record, token)) do
          if check_timing, do: check_min_duration(record, now_ns), else: :ok
        end

      if gate == :ok, do: nil, else: gate
    end
  end

  defp replay_security_check(options, secrets, legacy_secret, record, token, receipt_ns) do
    gate =
      with :ok <- check_authenticated_shape(options, secrets, legacy_secret, record),
           :ok <- check_scope_and_binding(options, record),
           :ok <- check_deployment_expectations(options, record),
           :ok <- check_execution_binding(record, token) do
        check_min_duration(record, receipt_ns)
      end

    if gate == :ok, do: nil, else: gate
  end

  defp check_authenticated_shape(options, secrets, legacy_secret, record) do
    cond do
      not validate_record(record) ->
        :malformed_record

      record.protocol_version == 1 and not options.accept_legacy_v1 ->
        :malformed_record

      MapSet.member?(secrets.revoked, record.kid) ->
        :unknown_kid

      true ->
        case secret_for_key(secrets, record, legacy_secret) do
          nil ->
            :unknown_kid

          signing_secret ->
            if verify_record_signature(options, record, signing_secret) do
              cond do
                not argon2_ceilings_ok?(record) -> :unsupported_argon2_params
                not rsw_params_ok?(record) -> :unsupported_rsw_params
                true -> :ok
              end
            else
              :bad_signature
            end
        end
    end
  end

  defp check_ttl(options, record) do
    now = now_secs(options)

    cond do
      now >= record.expires_at -> :expired
      record.issued_at > now + @max_clock_skew -> :expired
      true -> :ok
    end
  end

  defp check_scope_and_binding(options, record) do
    cond do
      # The scope option is required: an empty option refuses with the
      # typed code instead of accepting any scope.
      options.expected_scope in [nil, ""] ->
        :required_scope

      record.scope != options.expected_scope ->
        :wrong_scope

      true ->
        check_request_binding(options, record)
    end
  end

  defp check_request_binding(options, record) do
    # Exact option equality by default: a bound record must present
    # its binding, an unbound record under a presented expectation is
    # refused; the legacy mode permits an unbound record regardless
    # of the expectation.
    cond do
      record.request_binding == nil and options.binding_expectation == :legacy ->
        :ok

      record.request_binding == nil or options.expected_request_binding == nil ->
        if record.request_binding == options.expected_request_binding,
          do: :ok,
          else: :request_binding_mismatch

      Kiwicaptcha.Mac.timing_safe_equals(
        record.request_binding,
        options.expected_request_binding
      ) ->
        :ok

      true ->
        :request_binding_mismatch
    end
  end

  defp check_ip_binding(options, record, signing_secret) do
    cond do
      record.binding_tag == "" ->
        :ok

      options.client_ip == nil ->
        :missing_client_ip

      true ->
        expected_tag =
          try do
            if record.protocol_version == 1 do
              Kiwicaptcha.Canonical.hash_ip(options.client_ip, signing_secret)
            else
              Kiwicaptcha.Canonical.binding_tag(
                record.nonce,
                options.client_ip,
                signing_secret,
                options.tenant_id
              )
            end
          rescue
            _ -> nil
          end

        if expected_tag && Kiwicaptcha.Mac.timing_safe_equals(expected_tag, record.binding_tag),
          do: :ok,
          else: :ip_mismatch
    end
  end

  @doc """
  Whether the record's policy epoch satisfies the configured window:
  strict equality by default, or the declared rollout floor through the
  expected epoch, inclusive on both ends. A floor above the expected
  epoch accepts nothing (fail closed).
  """
  @spec policy_version_accepted?(map(), pos_integer()) :: boolean()
  def policy_version_accepted?(options, record_version) do
    cond do
      options.expected_policy_version == nil ->
        true

      options.policy_version_floor == nil ->
        record_version == options.expected_policy_version

      true ->
        options.policy_version_floor <= record_version and
          record_version <= options.expected_policy_version
    end
  end

  defp check_deployment_expectations(options, record) do
    cond do
      options.region != nil and record.region != options.region -> :wrong_region
      not policy_version_accepted?(options, record.policy_version || 1) -> :wrong_policy_version
      options.expected_issuer != nil and record.issuer != options.expected_issuer -> :wrong_issuer
      true -> :ok
    end
  end

  defp check_execution_binding(record, token) do
    if record.execution_program == nil do
      # Stray execution evidence on an unarmed record is never ignored.
      if token.execution_digest == nil and token.execution_trace == nil,
        do: :ok,
        else: :execution_mismatch
    else
      # An armed record demands the browser-trace walker, a
      # browser-behavior oracle this SDK does not carry. The armed
      # dimension fails closed: the record's own authenticated program
      # and commitment still verify, but no submission can satisfy the
      # armed binding, so a missing capability never widens acceptance.
      :execution_mismatch
    end
  end

  defp check_min_duration(record, now_ns) do
    cond do
      record.issued_at_ns <= 0 ->
        :malformed_record

      max(0, record.min_duration_ms) == 0 ->
        :ok

      record.server_mac == nil ->
        # An unauthenticated issuance clock cannot drive the floor.
        :malformed_record

      true ->
        floor = record.min_duration_ms
        receipt = now_ns || System.system_time(:microsecond)

        cond do
          receipt >= record.issued_at_ns and receipt - record.issued_at_ns < floor * 1000 ->
            :too_fast

          receipt < record.issued_at_ns and record.issued_at_ns - receipt > @skew_tolerance_us ->
            :too_fast

          true ->
            :ok
        end
    end
  end

  @doc "Structural validation of the stored record, in the canonical order."
  @spec validate_record(Kiwicaptcha.Record.t()) :: boolean()
  def validate_record(%Kiwicaptcha.Record{} = record) do
    scope_ok =
      byte_size(record.scope) in 1..128 and Regex.match?(~r/\A[A-Za-z0-9._:-]+\z/, record.scope)

    execution_ok =
      if record.execution_program == nil do
        record.execution_version == nil and record.execution_commitment == nil
      else
        record.execution_version != nil and record.execution_version >= 1 and
          record.execution_version <= Kiwicaptcha.Record.max_execution_version() and
          is_binary(record.execution_commitment) and
          Regex.match?(~r/\A[0-9a-f]{64}\z/, record.execution_commitment) and
          Kiwicaptcha.Mac.timing_safe_equals(
            Kiwicaptcha.Canonical.execution_commitment(record.execution_program),
            record.execution_commitment
          )
      end

    rsw_ok =
      record.rsw_modulus_sha256 == nil or
        (record.algorithm == "rsw" and
           Regex.match?(~r/\A[0-9a-f]{64}\z/, record.rsw_modulus_sha256))

    nonce_ok =
      match?({:ok, bytes} when byte_size(bytes) == 32, Kiwicaptcha.B64.decode_std(record.nonce))

    salt_ok =
      match?({:ok, bytes} when byte_size(bytes) == 16, Kiwicaptcha.B64.decode_std(record.salt))

    ttl_ok =
      record.expires_at > record.issued_at and
        record.expires_at - record.issued_at <= @max_ttl_secs

    prefix_ok =
      Kiwicaptcha.Mac.timing_safe_equals(
        IO.iodata_to_binary([record.challenge, "|", record.salt, "|"]),
        record.prefix
      )

    record.protocol_version >= 1 and
      record.protocol_version <= Kiwicaptcha.Record.max_protocol_version() and
      Kiwicaptcha.Record.protocol_extension_grammar_ok?(
        record.protocol_version,
        record.decoy_field != nil,
        record.execution_program != nil,
        record.rsw_modulus_sha256 != nil
      ) and
      scope_ok and
      (record.decoy_field == nil or Kiwicaptcha.Record.valid_decoy_field_name?(record.decoy_field)) and
      execution_ok and rsw_ok and nonce_ok and salt_ok and ttl_ok and prefix_ok and
      record.target_bits >= @min_difficulty and record.target_bits <= @max_difficulty
  end

  defp argon2_ceilings_ok?(record) do
    record.algorithm != "argon2id" or
      (record.m_kib >= @min_argon_memory_kib and record.m_kib <= @max_argon_memory_kib and
         record.t >= @min_argon_time and record.t <= @max_argon_time and
         record.p >= @min_parallelism and record.p <= @max_parallelism)
  end

  defp rsw_params_ok?(record) do
    record.algorithm != "rsw" or
      (record.t >= Kiwicaptcha.Rsw.t_min() and record.t <= Kiwicaptcha.Rsw.t_max())
  end

  @doc """
  Recompute the expected HMAC signature for a record per its protocol
  version and compare constant time against the challenge's embedded
  tag. The v2+ canonical covers every immutable parameter and the
  tagged armed-extension segments; a signed m=1 marker requires a valid
  record-metadata MAC.
  """
  @spec verify_record_signature(map(), Kiwicaptcha.Record.t(), binary()) :: boolean()
  def verify_record_signature(options, record, secret_key) do
    commits_mac = Kiwicaptcha.Canonical.signed_canonical_commits_record_meta?(record.challenge)

    expected =
      if record.protocol_version == 1 do
        Kiwicaptcha.Canonical.sign_payload_v1(
          Enum.join([record.nonce, record.scope, record.binding_tag, record.issued_at], "|"),
          secret_key
        )
      else
        Kiwicaptcha.Canonical.sign_payload_v2(
          Kiwicaptcha.Canonical.canonical_payload(%Kiwicaptcha.Canonical.Args{
            protocol_version: record.protocol_version,
            nonce: record.nonce,
            scope: record.scope,
            binding_tag: record.binding_tag,
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            algorithm: record.algorithm,
            m_kib: record.m_kib,
            t: record.t,
            p: record.p,
            target_bits: record.target_bits,
            salt: record.salt,
            min_duration_ms: record.min_duration_ms,
            region: record.region,
            policy_version: record.policy_version || 1,
            request_binding: record.request_binding,
            issuer: record.issuer,
            kid: record.kid || 1,
            decoy_field: record.decoy_field,
            execution_version: record.execution_version,
            execution_commitment: record.execution_commitment,
            rsw_modulus_sha256: record.rsw_modulus_sha256,
            server_mac_committed: commits_mac
          }),
          secret_key,
          options.tenant_id
        )
      end

    if Kiwicaptcha.Mac.timing_safe_equals(expected, signature_from_challenge(record.challenge)) do
      key = Kiwicaptcha.Mac.server_state_key(secret_key, options.tenant_id)

      meta =
        Kiwicaptcha.Mac.record_meta_mac(
          key,
          record.challenge,
          record.issued_at_ns,
          record.hostname
        )

      if commits_mac do
        record.server_mac != nil and Kiwicaptcha.Mac.timing_safe_equals(meta, record.server_mac)
      else
        record.server_mac == nil or Kiwicaptcha.Mac.timing_safe_equals(meta, record.server_mac)
      end
    else
      false
    end
  end

  defp signature_from_challenge(challenge) do
    case String.split(challenge, ".", parts: 2) do
      [_payload, sig] -> sig
      [whole] -> whole
    end
  end

  @doc """
  The deterministic proof verdict of a presented token against a
  record. SHA-256 re-derives the hash and compares leading zero bits;
  rsw compares the trapdoor expectation; an argon2id record is
  authentic but unrepresentable by this runtime and fails closed with
  the cores' unsupported mapping (:unsupported).
  """
  @spec recompute_valid_proof(rsw_config() | nil, Kiwicaptcha.Record.t(), Kiwicaptcha.Token.t()) ::
          :unsupported | boolean()
  def recompute_valid_proof(rsw_config, %Kiwicaptcha.Record{algorithm: "rsw"} = record, token) do
    trapdoor = resolve_trapdoor(rsw_config, record)

    cond do
      trapdoor == nil ->
        :unsupported

      token.counter != 0 or token.rsw_proof == nil ->
        false

      true ->
        Kiwicaptcha.Mac.timing_safe_equals(
          Kiwicaptcha.Rsw.expected_proof_hex(trapdoor, record.prefix, record.nonce, record.t),
          token.rsw_proof
        )
    end
  end

  def recompute_valid_proof(_rsw_config, %Kiwicaptcha.Record{} = record, token) do
    cond do
      token.rsw_proof != nil ->
        # An rsw final value is rsw evidence only; the hash is never
        # derived for a record it does not belong to.
        false

      record.algorithm == "argon2id" ->
        :unsupported

      true ->
        case Kiwicaptcha.B64.decode_std(record.salt) do
          {:ok, salt_bytes} ->
            hash = Kiwicaptcha.Pow.derive_sha256_hash(record.prefix, token.counter, salt_bytes)
            Kiwicaptcha.Pow.meets_target?(hash, record.target_bits)

          :error ->
            :unsupported
        end
    end
  end

  @doc "Resolve the trapdoor for a record: the active pair or the rotation keyring."
  @spec resolve_trapdoor(rsw_config() | nil, Kiwicaptcha.Record.t()) :: Kiwicaptcha.Rsw.t() | nil
  def resolve_trapdoor(rsw_config, record) do
    active =
      if rsw_config && rsw_config[:modulus_n] not in [nil, ""] &&
           rsw_config[:lambda] not in [nil, ""] do
        safe_trapdoor(rsw_config.modulus_n, rsw_config.lambda)
      else
        nil
      end

    allow_legacy = get_in(rsw_config || %{}, [:allow_legacy_identity]) == true

    {keyring, modulus_by_hash} =
      build_keyring(rsw_config, active, allow_legacy)

    cond do
      record.rsw_modulus_sha256 == nil ->
        active

      true ->
        identity = record.rsw_modulus_sha256
        keyring_modulus = modulus_by_hash[identity]

        cond do
          keyring_modulus &&
              Kiwicaptcha.Rsw.identity_matches?(identity, keyring_modulus, allow_legacy) ->
            keyring[identity]

          active &&
              Kiwicaptcha.Rsw.identity_matches?(
                identity,
                (rsw_config && rsw_config.modulus_n) || "",
                allow_legacy
              ) ->
            active

          true ->
            nil
        end
    end
  end

  defp build_keyring(nil, _active, _allow_legacy), do: {%{}, %{}}

  defp build_keyring(rsw_config, active, allow_legacy) do
    {ring, mods} =
      Enum.reduce(rsw_config.verification_keys || %{}, {%{}, %{}}, fn {hash, pair},
                                                                      {ring, mods} ->
        with true <- is_binary(hash) and Regex.match?(~r/\A[0-9a-f]{64}\z/, hash),
             %Kiwicaptcha.Rsw{} = trapdoor <- safe_trapdoor(pair.modulus_n, pair.lambda),
             true <- Kiwicaptcha.Rsw.identity_matches?(hash, pair.modulus_n, allow_legacy) do
          {Map.put(ring, hash, trapdoor), Map.put(mods, hash, pair.modulus_n)}
        else
          _ -> {ring, mods}
        end
      end)

    if active && rsw_config.modulus_n not in [nil, ""] do
      Enum.reduce(fingerprints_of(rsw_config.modulus_n, allow_legacy), {ring, mods}, fn identity,
                                                                                        {r, m} ->
        {Map.put(r, identity, active), Map.put(m, identity, rsw_config.modulus_n)}
      end)
    else
      {ring, mods}
    end
  end

  defp safe_trapdoor(m, l) do
    Kiwicaptcha.Rsw.new_trapdoor(m, l)
  rescue
    _ -> nil
  end

  defp fingerprints_of(modulus_n, allow_legacy) do
    case Kiwicaptcha.B64.decode_std(modulus_n) do
      {:ok, bytes} ->
        legacy = if allow_legacy, do: [Kiwicaptcha.Canonical.sha256_hex(modulus_n)], else: []
        [Kiwicaptcha.Canonical.sha256_hex(bytes) | legacy]

      :error ->
        []
    end
  end

  @doc "The server-measured solve duration of a fresh valid outcome."
  @spec measurable_solve_duration_ms(Kiwicaptcha.Record.t(), non_neg_integer() | nil) ::
          non_neg_integer() | nil
  def measurable_solve_duration_ms(record, receipt_ns) do
    if record.server_mac == nil or record.issued_at_ns <= 0 or receipt_ns == nil or
         receipt_ns < record.issued_at_ns do
      nil
    else
      div(receipt_ns - record.issued_at_ns, 1000)
    end
  end

  @doc """
  Resolve an already-consumed record's retained state. A stored invalid
  outcome replays to any caller; a stored success replays only under
  the exact logical operation identity with an authentic MAC; a
  resultless consumed record is consume_indeterminate.
  """
  @spec resolve_consumed_record(map(), map(), binary(), map(), String.t(), String.t() | nil) ::
          result()
  def resolve_consumed_record(
        options,
        secrets,
        legacy_secret,
        consumed,
        token_nonce,
        operation_identity
      ) do
    cond do
      consumed.record.nonce != token_nonce ->
        invalid(:malformed_record)

      consumed.consumed_result == nil ->
        invalid(:consume_indeterminate)

      not consumed.consumed_result.valid ->
        invalid(:insufficient_work)

      operation_identity != nil and consumed.operation_identity != nil and
          Kiwicaptcha.Mac.timing_safe_equals(consumed.operation_identity, operation_identity) ->
        if stored_success_authentic?(options, secrets, legacy_secret, consumed) do
          valid(
            consumed.record.nonce,
            ladder_rung(consumed.record),
            consumed.consumed_result.binding,
            true,
            nil,
            consumed.record.decoy_field
          )
        else
          invalid(:malformed_record)
        end

      true ->
        invalid(:already_consumed)
    end
  end

  defp stored_success_authentic?(options, secrets, legacy_secret, consumed) do
    result = consumed.consumed_result

    if result == nil or not result.valid do
      false
    else
      if result.mac == nil do
        commits = storage_module_option?(options.storage)

        not commits
      else
        secret = secret_for_key(secrets, consumed.record, legacy_secret)

        if secret == nil do
          false
        else
          expected =
            Kiwicaptcha.Mac.consumed_result_mac(
              Kiwicaptcha.Mac.server_state_key(secret, options.tenant_id),
              consumed.record.challenge,
              result.valid,
              result.binding,
              consumed.operation_identity
            )

          Kiwicaptcha.Mac.timing_safe_equals(expected, result.mac)
        end
      end
    end
  end
end
