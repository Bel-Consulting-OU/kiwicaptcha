defmodule Kiwicaptcha.ClientIpTest do
  @moduledoc """
  The shared client-IP test vectors, asserted against the Elixir
  resolver. Every SDK runs the same scenarios from
  tools/client-ip/test-vectors.json, so one request resolves to one
  canonical IP everywhere.
  """

  use ExUnit.Case, async: true

  # __DIR__ is test/: three ups land on the repository root.
  @vectors_path Path.expand("../../../tools/client-ip/test-vectors.json", __DIR__)

  defp vectors do
    doc =
      cond do
        Code.ensure_loaded?(JSON) and function_exported?(JSON, :decode, 1) ->
          {_, doc} = JSON.decode(File.read!(@vectors_path))
          doc

        Code.ensure_loaded?(Jason) and function_exported?(Jason, :decode, 1) ->
          {_, doc} = Jason.decode(File.read!(@vectors_path))
          doc

        true ->
          raise "no JSON decoder available"
      end

    doc
  end

  test "shared cidr cases" do
    for case_row <- vectors()["cidr_cases"] do
      assert Kiwicaptcha.ClientIp.in_trusted?(case_row["ip"], [case_row["cidr"]]) ==
               case_row["matches"],
             "cidr #{case_row["cidr"]} vs #{case_row["ip"]}"
    end
  end

  test "shared scenarios" do
    for scenario <- vectors()["scenarios"] do
      # Plug merges repeated header lines into one comma-joined value,
      # so merged surfaces walk the merged chain.
      xff =
        case scenario["xff_lines"] do
          nil -> nil
          lines -> Enum.join(lines, ",")
        end

      expected =
        if scenario["duplicate_detection"],
          do: scenario["expected_merged"],
          else: scenario["expected"]

      resolved =
        Kiwicaptcha.ClientIp.resolve(
          peer: scenario["peer"],
          xff: xff,
          real_ip: scenario["real_ip"],
          trusted_proxies: scenario["trusted"]
        )

      assert resolved == expected, "scenario #{scenario["id"]}: got #{inspect(resolved)}"
    end
  end

  test "canonical ip edges" do
    accepted = %{
      "192.0.2.10" => "192.0.2.10",
      " 192.0.2.10:4711 " => "192.0.2.10",
      "[2001:DB8::1]" => "2001:db8::1",
      "[2001:db8::1]:4711" => "2001:db8::1",
      "::ffff:198.51.100.5" => "198.51.100.5",
      "2001:0db8:0:0:0:0:0:1" => "2001:db8::1"
    }

    Enum.each(accepted, fn {input, expected} ->
      assert Kiwicaptcha.ClientIp.canonical_ip(input) == expected, "canonical #{input}"
    end)

    rejected = [
      "",
      "unknown",
      "_obfuscated",
      "[2001:db8::1]:notaport",
      "[2001:db8::1]garbage",
      "1.2.3.4:0",
      "0:1.2.3.4",
      "1.2.3.4.5",
      "3232235521",
      "01.2.3.4"
    ]

    Enum.each(rejected, fn input ->
      assert Kiwicaptcha.ClientIp.canonical_ip(input) == nil, "canonical rejects #{input}"
    end)
  end
end
