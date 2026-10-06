# frozen_string_literal: true

require_relative 'helper'
require 'json'

# The shared client-IP test vectors, asserted against the Ruby
# resolver. Every SDK runs the same scenarios from
# tools/client-ip/test-vectors.json, so one request resolves to one
# canonical IP everywhere.
class TestClientIp < Minitest::Test
  VECTORS = File.expand_path('../../../tools/client-ip/test-vectors.json', __dir__)

  def vectors
    @vectors ||= JSON.parse(File.read(VECTORS))
  end

  def test_cidr_cases
    vectors['cidr_cases'].each do |case_row|
      matched = KiwiCaptcha::ClientIp.in_trusted?(case_row['ip'], [case_row['cidr']])
      assert_equal case_row['matches'], matched,
                   "cidr #{case_row['cidr']} vs #{case_row['ip']}"
    end
  end

  def test_scenarios
    vectors['scenarios'].each do |scenario|
      lines = scenario['xff_lines']
      # Rack merges repeated header lines into one comma-joined value,
      # so merged surfaces walk the merged chain.
      xff = lines.nil? ? nil : lines.join(',')
      expected = scenario['duplicate_detection'] ? scenario['expected_merged'] : scenario['expected']
      resolved = KiwiCaptcha::ClientIp.resolve(
        peer: scenario['peer'],
        xff: xff,
        real_ip: scenario['real_ip'],
        trusted_proxies: scenario['trusted']
      )
      assert_equal expected, resolved, "scenario #{scenario['id']}"
    end
  end

  def test_canonical_ip_edges
    {
      '192.0.2.10' => '192.0.2.10',
      ' 192.0.2.10:4711 ' => '192.0.2.10',
      '[2001:DB8::1]' => '2001:db8::1',
      '[2001:db8::1]:4711' => '2001:db8::1',
      '::ffff:198.51.100.5' => '198.51.100.5',
      '2001:0db8:0:0:0:0:0:1' => '2001:db8::1'
    }.each do |input, expected|
      assert_equal expected, KiwiCaptcha::ClientIp.canonical_ip(input), "canonical #{input}"
    end
    ['', 'unknown', '_obfuscated', '[2001:db8::1]:notaport', '[2001:db8::1]garbage',
     '1.2.3.4:0', '0:1.2.3.4', '1.2.3.4.5', '3232235521', '01.2.3.4'].each do |input|
      assert_nil KiwiCaptcha::ClientIp.canonical_ip(input), "canonical rejects #{input}"
    end
  end
end
