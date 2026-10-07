# frozen_string_literal: true

require_relative 'helper'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'tmpdir'

# The sidecar delegation plane: the spawned kiwicaptcha-verifier (the
# full Rust core with the real execution verifier) fronts an
# execution-armed challenge; the SDK's fail-closed default refuses it,
# the sidecar policy delegates and accepts. Skipped where the verifier
# crate is unavailable.
class SidecarDelegationTest < Minitest::Test
  SIDECAR_BIN = File.expand_path('../../../target/debug/kiwicaptcha-verifier', __dir__)
  SECRET = 'ruby-sidecar-delegation-0123456789abcdef'

  def sidecar_available?
    return false unless File.exist?(SIDECAR_BIN)
    # The test-fixtures feature only adds the evidence subcommand, so
    # the same binary serves both the server and the helper roles.
    system('cargo', 'build', '-q', '-p', 'kiwicaptcha-verifier', '--features', 'test-fixtures',
           out: File::NULL, err: File::NULL)
  end

  def skip_unless_sidecar
    skip 'the verifier crate is not built' unless sidecar_available?
  end

  def spawn_sidecar(store_dir)
    probe = TCPServer.new('127.0.0.1', 0)
    port = probe.addr[1]
    probe.close
    env = {
      'KIWI_LISTEN' => "http://127.0.0.1:#{port}",
      'KIWI_SECRET' => SECRET,
      'KIWI_STORE' => "file=#{store_dir}",
      'KIWI_BINDING' => 'none',
      'KIWI_PROFILE' => 'sha16'
    }
    pid = Process.spawn(env, SIDECAR_BIN, out: File::NULL, err: File::NULL)
    url = "http://127.0.0.1:#{port}"
    deadline = Time.now + 10
    while Time.now < deadline
      begin
        answer = Net::HTTP.get_response(URI.parse("#{url}/healthz"))
        return [pid, url] if answer.code.to_i == 200
      rescue StandardError
        sleep 0.15
      end
    end
    Process.kill('KILL', pid)
    flunk 'the sidecar never answered /healthz'
  end

  def evidence_doc(store_dir)
    out, err, status = Open3.capture3(
      SIDECAR_BIN, 'exec-evidence', '--secret', SECRET, '--scope', 'login',
      '--action', 'login-action', '--version', '1', '--store-dir', store_dir
    )
    flunk "the evidence helper failed: #{err}" unless status.success?
    JSON.parse(out)
  end

  def test_fail_closed_default_then_delegation
    skip_unless_sidecar
    store_dir = Dir.mktmpdir('kiwi-sidecar-')
    # The evidence lands before the boot: the file store loads its live
    # envelopes once at open, so an envelope written later would be
    # invisible to the running process.
    doc = evidence_doc(store_dir)
    pid, url = spawn_sidecar(store_dir)
    begin
      record = KiwiCaptcha::Record.from_json(doc['record'])
      refute_nil record.execution_program, 'the minted record is execution-armed'

      verify_with = lambda do |policy|
        storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
        storage.store(record)
        counter = TestSupport.solve_sha(record.prefix, record.salt, record.target_bits)
        token = TestSupport.token_for(
          record.nonce, counter, 5000, {},
          execution_digest: doc['digest'], execution_trace: doc['trace']
        )
        options = TestSupport.verify_options(
          storage: storage, secret_key: SECRET, expected_scope: 'login',
          client_ip: '203.0.113.7'
        )
        options.execution_policy = policy
        KiwiCaptcha.verify(token, options)
      end

      # The fail-closed default: the armed record refuses exactly as
      # before the delegation plane existed.
      refused = verify_with.call(nil)
      assert_equal false, refused.ok
      assert_equal 'execution_mismatch', refused.code

      # The sidecar policy: the delegation accepts.
      accepted = verify_with.call(KiwiCaptcha::ExecutionPolicy.new(sidecar_url: url))
      assert_equal true, accepted.ok, "the delegation must accept: #{accepted.code}"

      # Single-use: the sidecar consumed; a replay never re-accepts.
      replay = verify_with.call(KiwiCaptcha::ExecutionPolicy.new(sidecar_url: url))
      assert_equal false, replay.ok
      assert_includes %w[already_consumed record_not_found], replay.code

      # An unreachable sidecar answers the retry disposition.
      down = verify_with.call(KiwiCaptcha::ExecutionPolicy.new(sidecar_url: 'http://127.0.0.1:1', timeout_ms: 300))
      assert_equal false, down.ok
      assert_equal 'storage_unavailable', down.code
    ensure
      Process.kill('KILL', pid) rescue nil
      Process.wait(pid) rescue nil
      require 'fileutils'
      FileUtils.remove_entry_secure(store_dir)
    end
  end
end

# The delegation verdict contract, without the sidecar binary: a
# fresh acceptance is a fresh result (never a stored-result replay),
# the opt-in telemetry gate runs before the delegation, and the
# caller's telemetry posture and operation identity ride along instead
# of being dropped at the seam.
class DelegationVerdictTest < Minitest::Test
  include TestSupport

  class FakePolicy
    attr_reader :calls

    def initialize(ok: true, code: 'ok')
      @ok = ok
      @code = code
      @calls = []
    end

    def enabled?
      true
    end

    def delegate(*args, **kwargs)
      @calls << [args, kwargs]
      [@ok, @code]
    end
  end

  def armed_setup(telemetry: nil, enforce_telemetry: false, operation_identity: nil, policy: FakePolicy.new)
    row = TestSupport.golden_record('sha_execution_v4')
    record = TestSupport.record_from_row(row)
    storage = KiwiCaptcha::MemoryStore.new(now: -> { record.issued_at + 10 })
    storage.store(record)
    token_b64 = row['token_b64']
    if telemetry
      token = KiwiCaptcha::Token.decode(token_b64)
      token_b64 = token.class.new(**token.to_h.merge(telemetry: telemetry)).encode
    end
    opts = {
      storage: storage, secret_key: SECRET,
      expected_scope: row['verify_opts']['expected_scope'],
      enforce_telemetry: enforce_telemetry, operation_identity: operation_identity,
      execution_policy: policy
    }.merge(TestSupport.frozen_clock(record))
    [token_b64, TestSupport.verify_options(opts), policy]
  end

  def test_fresh_delegation_success_is_a_fresh_result
    token, opts, policy = armed_setup
    result = KiwiCaptcha.verify(token, opts)
    assert result.ok, result.code
    refute result.from_stored_result
    assert_equal 1, policy.calls.length
  end

  def test_delegation_runs_the_telemetry_gate_first
    token, opts, policy = armed_setup(telemetry: { 'wd' => true }, enforce_telemetry: true)
    result = KiwiCaptcha.verify(token, opts)
    refute result.ok
    assert_equal 'telemetry_rejected', result.code
    assert_empty policy.calls
    # Opt-out: the same bot token delegates when the gate is off.
    token2, opts2, = armed_setup(telemetry: { 'wd' => true })
    assert KiwiCaptcha.verify(token2, opts2).ok
  end

  def test_delegation_forwards_telemetry_and_operation_identity
    token, opts, policy = armed_setup(
      telemetry: { 'v' => 1 }, enforce_telemetry: true, operation_identity: 'order-123'
    )
    result = KiwiCaptcha.verify(token, opts)
    assert result.ok, result.code
    _args, kwargs = policy.calls.first
    assert_equal true, kwargs[:enforce_telemetry]
    assert_equal 'order-123', kwargs[:operation_identity]
  end
end
