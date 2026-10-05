# frozen_string_literal: true

# KiwiCaptcha Ruby server SDK.
#
# Verifies client-submitted proof-of-work solution tokens, byte for byte
# compatible with the PHP and Rust cores. Verification is pure local:
# the signature, the message authentication codes and the store adapter
# are the only inputs, and no call ever reaches a network service.
#
# The public surface mirrors the shared server SDK contract:
#
# * KiwiCaptcha.verify(token, options) resolves to a VerifyResult with
#   ok, disposition, decision_handle and price.
# * KiwiCaptcha::Rack::Verifier is the drop-in Rack middleware; the
#   Rails concern, the form helper and the Sinatra helper wrap it.
# * KiwiCaptcha::Outcomes::Client is the versioned outcomes mapping and
#   client.
# * KiwiCaptcha::MemoryStore, RedisStore and SqliteStore implement one
#   injectable storage interface.
# * bin/kiwicaptcha-doctor validates a deployment.
module KiwiCaptcha
  VERSION = '1.0.0'
end

require_relative 'kiwicaptcha/base64_utils'
require_relative 'kiwicaptcha/errors'
require_relative 'kiwicaptcha/keys'
require_relative 'kiwicaptcha/mac'
require_relative 'kiwicaptcha/canonical'
require_relative 'kiwicaptcha/pow'
require_relative 'kiwicaptcha/token'
require_relative 'kiwicaptcha/record'
require_relative 'kiwicaptcha/rsw'
require_relative 'kiwicaptcha/telemetry'
require_relative 'kiwicaptcha/store'
require_relative 'kiwicaptcha/verify'
require_relative 'kiwicaptcha/stores/memory'
require_relative 'kiwicaptcha/stores/redis'
require_relative 'kiwicaptcha/stores/sqlite'
require_relative 'kiwicaptcha/outcomes'
require_relative 'kiwicaptcha/middleware/rack'
require_relative 'kiwicaptcha/middleware/rails'
require_relative 'kiwicaptcha/middleware/sinatra'
require_relative 'kiwicaptcha/settings'
require_relative 'kiwicaptcha/doctor'
