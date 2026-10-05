defmodule Kiwicaptcha.RecordTest do
  use ExUnit.Case, async: true

  import Kiwicaptcha.TestSupport

  # The strict record parser: whitelisted keys, exact algorithm
  # values, strict integer ranges, the protocol grammar and the
  # execution triplet equivalence, plus the serialization round trip.
  test "golden records parse and serialize round trip" do
    names = [
      "sha_plain",
      "sha_bound",
      "sha_decoy_v3",
      "sha_execution_v4",
      "argon2id",
      "rsw",
      "tampered_signature"
    ]

    for name <- names do
      record = golden_record(name) |> record_from_row()
      data = Kiwicaptcha.Record.to_json_map(record)
      {:ok, again} = Kiwicaptcha.Record.from_json(data)
      assert Kiwicaptcha.Record.to_json_map(again) == data, name
    end
  end

  test "unknown keys are refused" do
    data = golden_record("sha_plain") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()
    data = Map.put(data, "sneaky", 1)
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end

  test "missing required fields are refused" do
    data = golden_record("sha_plain") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()
    data = Map.delete(data, "scope")
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end

  test "integer ranges are strict" do
    base = golden_record("sha_plain") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()

    for {field, value} <- [
          {"m_kib", -1},
          {"attempts_used", -1},
          {"issued_at_ns", -5},
          {"kid", 2 ** 33}
        ] do
      data = Map.put(base, field, value)
      assert {:error, _} = Kiwicaptcha.Record.from_json(data), field
    end

    # target_bits is range-checked by the verifier's structural gate,
    # not the serde parser (the serde range is the u32 wire bound).
    data = Map.put(base, "target_bits", 99)
    {:ok, parsed} = Kiwicaptcha.Record.from_json(data)
    assert parsed.target_bits == 99
    refute Kiwicaptcha.Verify.validate_record(parsed)
  end

  test "algorithm is exact" do
    data = golden_record("sha_plain") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()
    data = Map.put(data, "algorithm", "sha-256")
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end

  test "the legacy ip hash alias maps and conflicts" do
    record = golden_record("sha_plain") |> record_from_row()

    data =
      Kiwicaptcha.Record.to_json_map(record)
      |> Map.delete("binding_tag")
      |> Map.put("ip_hash", String.duplicate("a", 64))

    {:ok, parsed} = Kiwicaptcha.Record.from_json(data)
    assert parsed.binding_tag == String.duplicate("a", 64)

    data = Map.put(data, "binding_tag", String.duplicate("b", 64))
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end

  test "identifier and decoy grammars" do
    assert Kiwicaptcha.Record.valid_identifier?("login", 128)
    refute Kiwicaptcha.Record.valid_identifier?("has space", 128)
    refute Kiwicaptcha.Record.valid_identifier?(String.duplicate("x", 129), 128)
    assert Kiwicaptcha.Record.valid_decoy_field_name?("decoy_field_a1b2c3d4e5f60718")
    refute Kiwicaptcha.Record.valid_decoy_field_name?("has space")
    refute Kiwicaptcha.Record.valid_decoy_field_name?(String.duplicate("x", 65))
  end

  test "protocol grammar matrix" do
    ok = &Kiwicaptcha.Record.protocol_extension_grammar_ok?/4
    assert ok.(1, false, false, false)
    refute ok.(1, false, false, true)
    assert ok.(2, false, false, false)
    refute ok.(2, true, false, false)
    assert ok.(3, true, false, false)
    refute ok.(3, false, false, false)
    assert ok.(4, false, true, false)
    refute ok.(4, false, false, false)
    assert ok.(5, false, false, true)
    refute ok.(6, false, false, false)
  end

  test "execution triplet must be complete and consistent" do
    record = golden_record("sha_execution_v4") |> record_from_row()
    data = Kiwicaptcha.Record.to_json_map(record)
    {:ok, parsed} = Kiwicaptcha.Record.from_json(data)
    assert parsed.execution_version == 1

    data = Map.delete(data, "execution_commitment")
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)

    data =
      golden_record("sha_execution_v4") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()

    data = Map.put(data, "execution_commitment", String.duplicate("f", 64))
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end

  test "hostname grammar" do
    data = golden_record("sha_plain") |> record_from_row() |> Kiwicaptcha.Record.to_json_map()
    data = Map.put(data, "hostname", "")
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
    data = Map.put(data, "hostname", "bad\x01host")
    assert {:error, _} = Kiwicaptcha.Record.from_json(data)
  end
end
