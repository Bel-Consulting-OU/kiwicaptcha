defmodule Kiwicaptcha.ArgonAdmissionGate do
  @moduledoc """
  The shipped default Argon2id admission gate: bounded concurrency
  plus a hard params budget, mirroring the other server SDKs.

  A 16-64 MiB derivation costs real memory per request, so the gate
  refuses any profile whose memory or time cost leaves the configured
  budget before a slot is handed out (`admits?` is false; the verifier
  answers `:unsupported_argon2_params`, never a silent downgrade).
  Exhaustion of the bounded pool answers `:capacity_exceeded` and the
  record stays retryable.

  The slot pool rides an `:atomics` counter shared by every process of
  the VM (the plain struct travels inside the verify options), so one
  deployment's concurrent derivations stay bounded across request
  processes.
  """

  defstruct [:slots, :max_concurrent, :max_memory_kib, :max_time_cost]

  # Worst-case tight budget when no native binding is present.
  @pure_max_memory_kib 8192
  @pure_max_time 3

  @type t :: %__MODULE__{
          slots: :atomics.atomics_ref(),
          max_concurrent: pos_integer(),
          max_memory_kib: pos_integer(),
          max_time_cost: pos_integer()
        }

  @doc """
  Build a gate with the bounded slot pool and the params budget. The
  default budget is the protocol ceiling with a native binding and the
  tight pure ceiling without one.
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    max_concurrent = Keyword.get(opts, :max_concurrent, 2)
    if max_concurrent < 1, do: raise(ArgumentError, "max_concurrent must be at least 1")

    {budget_memory, budget_time} = budget_of(opts)

    if budget_memory < 1 or budget_time < 1 do
      raise(ArgumentError, "the argon gate budget must be positive")
    end

    slots = :atomics.new(1, signed: true)
    :atomics.put(slots, 1, max_concurrent)

    %__MODULE__{
      slots: slots,
      max_concurrent: max_concurrent,
      max_memory_kib: budget_memory,
      max_time_cost: budget_time
    }
  end

  defp budget_of(opts) do
    memory = Keyword.get(opts, :max_memory_kib)
    time = Keyword.get(opts, :max_time_cost)

    if memory == nil or time == nil do
      if Kiwicaptcha.Pow.argon2_available?() do
        {Kiwicaptcha.Verify.max_argon_memory_kib(), Kiwicaptcha.Verify.max_argon_time()}
      else
        {@pure_max_memory_kib, @pure_max_time}
      end
    else
      {memory, time}
    end
  end

  @default_key {__MODULE__, :default}

  @doc """
  The process-wide default gate shared by the verifications of one
  deployment (the bounded pool spans concurrent request processes).
  """
  @spec default() :: t()
  def default do
    case :persistent_term.get(@default_key, nil) do
      nil ->
        gate = new([])
        :persistent_term.put(@default_key, gate)
        gate

      gate ->
        gate
    end
  end

  @doc "Whether the gate's budget covers a record's signed parameters."
  @spec admits?(t(), map()) :: boolean()
  def admits?(%__MODULE__{} = gate, record) do
    admits_params?(gate, record.m_kib, record.t)
  end

  @spec admits_params?(t(), integer(), integer()) :: boolean()
  def admits_params?(%__MODULE__{max_memory_kib: memory, max_time_cost: time}, m_kib, t_cost) do
    m_kib <= memory and t_cost <= time
  end

  @doc "Take a slot without blocking: `{:ok, lease}` or `:error`."
  @spec acquire(t()) :: {:ok, reference()} | :error
  def acquire(%__MODULE__{slots: slots} = gate) do
    free = :atomics.get(slots, 1)

    cond do
      free <= 0 ->
        :error

      :atomics.compare_exchange(slots, 1, free, free - 1) == :ok ->
        {:ok, make_ref()}

      true ->
        # Lost the race for the last slot(s): re-read and retry.
        acquire(gate)
    end
  end

  @doc "Return the lease; a failing release never breaks verification."
  @spec release(t(), reference()) :: :ok
  def release(%__MODULE__{slots: slots}, _lease) do
    :atomics.add(slots, 1, 1)
    :ok
  rescue
    _ -> :ok
  end
end
