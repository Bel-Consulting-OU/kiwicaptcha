defmodule Kiwicaptcha.ArgonAdmissionGateTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  alias Kiwicaptcha.ArgonAdmissionGate

  # The default Argon2id admission gate: absurd profiles refuse loudly
  # before a slot is taken, exhaustion answers capacity and keeps the
  # record retryable, and the budgeted pool admits small rungs.
  def store_of(name) do
    row = golden_record(name)
    record = record_from_row(row)
    {:ok, pid} = Kiwicaptcha.Stores.Memory.start(now: fn -> record.issued_at + 10 end)
    store = Kiwicaptcha.Stores.Memory.adapter(pid)
    Kiwicaptcha.Stores.Memory.store(pid, record)
    {pid, store, record, row}
  end

  def options_for(record, row, storage, extra \\ %{}) do
    row["verify_opts"]
    |> golden_options(record, storage)
    |> Map.merge(Map.new(extra))
  end

  test "the default gate is installed and bounded" do
    gate = ArgonAdmissionGate.new()
    assert gate.max_concurrent >= 1
    assert gate.max_memory_kib > 0
    assert gate.max_time_cost > 0
    shared = ArgonAdmissionGate.default()
    assert ArgonAdmissionGate.default().slots == shared.slots,
           "the default gate is process-wide, never per call"
  end

  test "gate refuses out-of-budget params loudly" do
    {pid, storage, record, row} = store_of("argon2id")
    # A gate whose budget cannot cover the golden record's 64 KiB rung:
    # the refuse is loud and typed, never a silent downgrade or a
    # derivation.
    gate = ArgonAdmissionGate.new(max_memory_kib: 8, max_time_cost: 3)

    result =
      Kiwicaptcha.verify(row["token_b64"], options_for(record, row, storage, %{argon_gate: gate}))

    refute result.ok
    assert result.code == :unsupported_argon2_params
    # The refusal never consumes: the record stays intact and retryable.
    refute is_nil(Kiwicaptcha.Stores.Memory.find(pid, record.nonce))
  end

  test "exhaustion answers capacity_exceeded" do
    {pid, storage, record, row} = store_of("argon2id")
    gate = ArgonAdmissionGate.new(max_concurrent: 1)
    {:ok, lease} = ArgonAdmissionGate.acquire(gate)

    result =
      Kiwicaptcha.verify(row["token_b64"], options_for(record, row, storage, %{argon_gate: gate}))

    refute result.ok
    assert result.code == :capacity_exceeded
    # The record stays intact under the capacity refusal.
    refute is_nil(Kiwicaptcha.Stores.Memory.find(pid, record.nonce))
    ArgonAdmissionGate.release(gate, lease)
  end

  test "budgeted gate admits small rungs" do
    gate = ArgonAdmissionGate.new(max_memory_kib: 8192, max_time_cost: 3)
    assert ArgonAdmissionGate.admits_params?(gate, 64, 3)
    refute ArgonAdmissionGate.admits_params?(gate, 64 * 1024, 16)
    refute ArgonAdmissionGate.admits_params?(gate, gate.max_memory_kib, gate.max_time_cost + 1)
  end

  test "release returns the slot to the pool" do
    gate = ArgonAdmissionGate.new(max_concurrent: 1)
    {:ok, first} = ArgonAdmissionGate.acquire(gate)
    assert ArgonAdmissionGate.acquire(gate) == :error, "the pool is bounded"
    ArgonAdmissionGate.release(gate, first)
    assert {:ok, _second} = ArgonAdmissionGate.acquire(gate),
           "the released slot is handed out again"
  end
end
