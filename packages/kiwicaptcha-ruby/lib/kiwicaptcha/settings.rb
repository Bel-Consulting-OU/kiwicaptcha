# frozen_string_literal: true

require 'json'
require 'uri'

module KiwiCaptcha
  # The four-setting quickstart surface: the profile is an adoption
  # choice, so the deployable settings are the secret, the store URL
  # and the scopes. Settings resolves a store URL into the shipped
  # adapter without any other configuration.
  class Settings
    # Profiles whose work ladder prices Argon2id rungs (the explicit
    # argon budgets and the full-stack adoption profiles). A deployment
    # that names one must run a verifier that can recompute them: the
    # argon2 gem carries the native binding, and an absent binding is a
    # loud configuration error — never a silent downgrade.
    ARGON_RUNG_PROFILES = %w[argon16 argon32 argon64 abuse_first high_abuse].freeze

    attr_reader :profile, :secret, :store_url, :scopes

    # Build settings from explicit values or environment variables
    # (KIWI_PROFILE, KIWI_SECRET, KIWI_STORE, KIWI_SCOPES). The scopes
    # string is "name=value" pairs joined by commas.
    def initialize(profile: nil, secret: nil, store_url: nil, scopes: nil, env: ENV)
      @profile = profile || env['KIWI_PROFILE'] || 'abuse_first'
      @secret = secret || env['KIWI_SECRET']
      @store_url = store_url || env['KIWI_STORE'] || 'memory://'
      @scopes = parse_scopes_when_string(scopes) || parse_scopes(env['KIWI_SCOPES'] || '')
      self.class.assert_argon_rung_verifiable!(@profile)
      freeze
    end

    # The issuer guard: a profile whose ladder issues Argon2id rungs
    # this runtime cannot verify refuses to boot.
    def self.assert_argon_rung_verifiable!(profile)
      return unless ARGON_RUNG_PROFILES.include?(profile.to_s)
      return if Pow.argon2_available?

      raise ArgumentError,
            "profile #{profile.inspect} issues Argon2id rungs this runtime cannot " \
            'verify: install the argon2 gem for the native binding (or choose a ' \
            'sha-only profile). The rung is never silently downgraded'
    end

    def valid_secret?
      @secret.is_a?(String) && @secret.bytesize >= Keys::MIN_SECRET_BYTES
    end

    # Build the store adapter the URL names: memory, sqlite (path) or
    # redis (host and port). Raises on an unknown scheme.
    def open_store
      Settings.open_store(@store_url)
    end

    def self.open_store(url)
      uri = URI.parse(url.to_s)
      case uri.scheme
      when 'memory'
        MemoryStore.new
      when 'sqlite'
        require 'sqlite3'
        path = uri.host.to_s.empty? ? uri.path.to_s : "#{uri.host}#{uri.path}"
        raise ArgumentError, 'a sqlite store URL needs a file path' if path.empty?

        SqliteStore.new(SQLite3::Database.new(path))
      when 'redis', 'rediss'
        require 'redis'
        RedisStore.new(Redis.new(url: url.to_s))
      else
        raise ArgumentError, "unsupported store URL scheme: #{uri.scheme.inspect}"
      end
    end

    private

    def parse_scopes_when_string(value)
      value.is_a?(String) ? parse_scopes(value) : value
    end

    def parse_scopes(value)
      scopes = {}
      value.to_s.split(',').each do |pair|
        name, _, class_name = pair.partition('=')
        next if name.strip.empty?

        scopes[name.strip] = class_name.strip
      end
      scopes
    end
  end
end
