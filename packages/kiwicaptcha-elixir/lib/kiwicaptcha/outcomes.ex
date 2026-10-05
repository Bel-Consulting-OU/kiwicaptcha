defmodule Kiwicaptcha.Outcomes do
  @moduledoc """
  The typed outcomes client: the eight application outcomes resolved
  through the one versioned mapping table, mirroring the PHP
  OutcomeMap. The table is the polarity authority: only the
  server-confirmed trust outcomes may subtract risk, and exactly the
  abuse outcomes write long-memory marks. The client carries the
  mapping, the handle acceptance rules, the mark keys and the
  idempotency keys; a host binds its own sink through the behaviour.
  """

  @map_version 1
  @outcomes ~w[
    confirmedLegitimate stepUpCompleted authenticationSuccess
    authenticationFailure spamReported chargeback accountBanned
    fraudConfirmed
  ]

  @handle_dimensions ~w[nonce decisionId principal target session agent]
  @ledger_dimensions ~w[nonce decisionId]
  @identity_dimensions ~w[principal target session agent]
  @every_dimension @ledger_dimensions ++ @identity_dimensions

  @pseudonym_re ~r/\A[0-9a-f]{32}\z/
  @unsafe_handle_chars ~r/[\x00-\x1F\x7F:}]/

  @risk_event_kinds %{
    "ProtectedActionSuccess" => 8,
    "ProtectedActionFailure" => 9,
    "AuthenticationSuccess" => 10,
    "AuthenticationFailure" => 11,
    "ConfirmedLegitimate" => 12,
    "ConfirmedAbuse" => 13
  }

  defstruct []

  @doc "The version of the mapping table."
  @spec map_version :: pos_integer()
  def map_version, do: @map_version

  @doc "The outcome vocabulary, in table order."
  @spec outcomes() :: [String.t()]
  def outcomes, do: @outcomes

  @doc "The handle dimensions, in table order."
  @spec handle_dimensions() :: [String.t()]
  def handle_dimensions, do: @handle_dimensions

  @doc "The ledger dimensions in table order (nonce before decision id)."
  @spec ledger_dimensions() :: [String.t()]
  def ledger_dimensions, do: @ledger_dimensions

  @doc "The identity dimensions in table order."
  @spec identity_dimensions() :: [String.t()]
  def identity_dimensions, do: @identity_dimensions

  @doc "The risk-v1 feedback channel each outcome books."
  @spec risk_event_kinds() :: map()
  def risk_event_kinds, do: @risk_event_kinds

  defp row(
         outcome,
         channel,
         ledger_legitimate,
         writes_mark,
         server_confirmed,
         may_subtract,
         accepted
       ) do
    %{
      outcome: outcome,
      channel: channel,
      ledger_legitimate: ledger_legitimate,
      writes_abuse_mark: writes_mark,
      server_confirmed: server_confirmed,
      may_subtract_risk: may_subtract,
      accepted_handles: accepted
    }
  end

  # Built at runtime: the row builder is a plain function, not a
  # macro, so the table cannot live in a module attribute.
  defp table do
    %{
      "confirmedLegitimate" =>
        row("confirmedLegitimate", 12, true, false, true, true, @every_dimension),
      "stepUpCompleted" =>
        row("stepUpCompleted", 8, nil, false, true, true, @identity_dimensions),
      "authenticationSuccess" =>
        row("authenticationSuccess", 10, nil, false, true, true, @identity_dimensions),
      "authenticationFailure" =>
        row("authenticationFailure", 11, nil, false, false, false, @identity_dimensions),
      "spamReported" => row("spamReported", 9, nil, true, true, false, @identity_dimensions),
      "chargeback" => row("chargeback", 13, false, true, true, false, @every_dimension),
      "accountBanned" => row("accountBanned", 13, false, true, true, false, @every_dimension),
      "fraudConfirmed" => row("fraudConfirmed", 13, false, true, true, false, @every_dimension)
    }
  end

  @doc "The mapping row of one outcome. The table is total over the vocabulary."
  @spec outcome_mapping(String.t()) :: map()
  def outcome_mapping(outcome), do: Map.fetch!(table(), outcome)

  @doc "Every row, in vocabulary order (the completeness oracle)."
  @spec all_outcome_mappings() :: [map()]
  def all_outcome_mappings, do: Enum.map(@outcomes, &table()[&1])

  @doc "Whether a mapping accepts one handle dimension."
  @spec accepts?(map(), String.t()) :: boolean()
  def accepts?(mapping, dimension), do: dimension in mapping.accepted_handles

  @doc "The mark kind an outcome writes on identity handles, nil when none."
  @spec mark_kind(map()) :: String.t() | nil
  def mark_kind(mapping), do: if(mapping.writes_abuse_mark, do: mapping.outcome, else: nil)

  @doc "Whether the mapping carries ledger semantics."
  @spec ledger_action?(map()) :: boolean()
  def ledger_action?(mapping), do: mapping.ledger_legitimate != nil

  @doc """
  The handle id grammar of the cores: principal, target and session
  carry the 32-char lowercase hex pseudonym, never a raw identifier;
  the ledger ids and agent keys carry a 32-hex id or a non-empty
  key-safe string. Raises Kiwicaptcha.RangeError on a violation.
  """
  @spec validate_outcome_handle!(%{dimension: String.t(), id: String.t()}) :: :ok
  def validate_outcome_handle!(handle)

  def validate_outcome_handle!(%{dimension: dimension, id: id})
      when dimension in ["principal", "target", "session"] do
    unless Regex.match?(@pseudonym_re, id) do
      raise Kiwicaptcha.RangeError,
            "#{dimension} handle must carry the 32-char lowercase hex pseudonym, never a raw identifier"
    end

    :ok
  end

  def validate_outcome_handle!(%{dimension: _dimension, id: id}) do
    cond do
      Regex.match?(@pseudonym_re, id) ->
        :ok

      id == "" or Regex.match?(@unsafe_handle_chars, id) ->
        raise Kiwicaptcha.RangeError,
              "handle id must be a 32-char lowercase hex id or a non-empty key-safe string"

      true ->
        :ok
    end
  end

  @doc "The long-memory mark key of one identity handle."
  @spec mark_key(String.t(), String.t(), String.t()) :: String.t()
  def mark_key(namespace, dimension, id), do: "mark:{kiwi:#{namespace}}:#{dimension}:#{id}"

  @doc "The idempotency key of a handle report: a bounded HMAC of the request id."
  @spec default_idempotency_key(%{dimension: String.t(), id: String.t()}, String.t() | nil) ::
          String.t()
  def default_idempotency_key(handle, secret \\ nil) do
    value = "#{handle.dimension}:#{handle.id}"
    key = secret || "kiwicaptcha/outcomes-idem/v1"
    binary_part(Kiwicaptcha.Mac.hmac_hex(key, value), 0, 32)
  end

  defmodule MemorySink do
    @moduledoc "The bundled sink: an in-memory ledger, feedback log and mark map, for tests and tools."

    defstruct [:ledger, :marks, :feedback]

    def new do
      %__MODULE__{ledger: %{}, marks: %{}, feedback: []}
    end

    def confirm_ledger(%__MODULE__{} = sink, id, legitimate) do
      status = if legitimate, do: 1, else: 0
      {status, %{sink | ledger: Map.put(sink.ledger, id, status)}}
    end

    def record_feedback(%__MODULE__{} = sink, channel, idempotency_key, handle) do
      entry = %{channel: channel, key: idempotency_key, handle: handle}
      {nil, %{sink | feedback: [entry | sink.feedback]}}
    end

    def write_mark(%__MODULE__{} = sink, key, kind) do
      existed = Map.has_key?(sink.marks, key)
      {if(existed, do: 0, else: 1), %{sink | marks: Map.put(sink.marks, key, kind)}}
    end

    def forget_mark(%__MODULE__{} = sink, key) do
      {if(Map.has_key?(sink.marks, key), do: 1, else: 0),
       %{sink | marks: Map.delete(sink.marks, key)}}
    end
  end

  @doc """
  Report one typed outcome for one handle. Raises Kiwicaptcha.RangeError when the
  mapping accepts no such handle dimension for the outcome. The sink
  callbacks are applied as `sink_module.fun(sink, ...)` returning
  `{reply, new_sink}`.
  """
  @spec report(
          %{sink: term(), module: atom(), namespace: String.t()},
          String.t(),
          %{
            dimension: String.t(),
            id: String.t()
          },
          String.t() | nil
        ) :: {:ok, map(), term()}
  def report(
        %{sink: sink, module: module, namespace: namespace},
        outcome,
        handle,
        idempotency_key \\ nil
      ) do
    mapping = outcome_mapping(outcome)
    validate_outcome_handle!(handle)

    unless accepts?(mapping, handle.dimension) do
      raise Kiwicaptcha.RangeError,
            "outcome #{outcome} cannot be reported on a #{handle.dimension} handle (accepted: #{Enum.join(mapping.accepted_handles, ", ")})"
    end

    ledger_status = nil
    marks_written = 0

    if handle.dimension in @ledger_dimensions do
      {ledger_status, sink} =
        module.confirm_ledger(sink, handle.id, mapping.ledger_legitimate == true)

      key = idempotency_key || default_idempotency_key(handle)
      {nil, sink} = module.record_feedback(sink, mapping.channel, key, handle)

      {:ok,
       %{
         outcome: outcome,
         mapping: mapping,
         ledger_status: ledger_status,
         marks_written: marks_written
       }, sink}
    else
      kind = mark_kind(mapping)

      {marks_written, sink} =
        if kind do
          module.write_mark(sink, mark_key(namespace, handle.dimension, handle.id), kind)
        else
          {0, sink}
        end

      key = idempotency_key || default_idempotency_key(handle)
      {nil, sink} = module.record_feedback(sink, mapping.channel, key, handle)

      {:ok,
       %{
         outcome: outcome,
         mapping: mapping,
         ledger_status: ledger_status,
         marks_written: marks_written
       }, sink}
    end
  end

  @doc """
  Remove the long-memory marks of the handle's dimension (the erasure
  path). Ledger dimensions carry no marks.
  """
  @spec forget(%{sink: term(), module: atom(), namespace: String.t()}, %{
          dimension: String.t(),
          id: String.t()
        }) :: {non_neg_integer(), term()}
  def forget(%{sink: sink, module: module, namespace: namespace}, handle) do
    if handle.dimension in @ledger_dimensions do
      {0, sink}
    else
      module.forget_mark(sink, mark_key(namespace, handle.dimension, handle.id))
    end
  end
end
