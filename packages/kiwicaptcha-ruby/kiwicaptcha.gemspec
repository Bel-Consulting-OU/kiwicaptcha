# frozen_string_literal: true

require_relative 'lib/kiwicaptcha'

Gem::Specification.new do |spec|
  spec.name = 'kiwicaptcha'
  spec.version = KiwiCaptcha::VERSION
  spec.authors = ['KiwiCaptcha contributors']
  spec.summary = 'KiwiCaptcha Ruby server SDK: local proof-of-work token verification over an injectable store.'
  spec.description = 'Verifies client-submitted proof-of-work solution tokens, byte for byte ' \
                     'compatible with the PHP and Rust cores. Pure-local verification over a ' \
                     'pluggable store (memory, SQLite, Redis), with Rack, Rails and Sinatra ' \
                     'integrations, a typed outcomes client and a doctor command.'
  spec.homepage = 'https://github.com/kiwicaptcha/kiwicaptcha'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['rubygems_mfa_required'] = 'true'

  # Zero hard runtime dependencies: the standard library carries the
  # whole verify path. The store backends and the web integrations opt
  # into their gems through the optional groups below.
  spec.require_paths = ['lib']
  spec.files = Dir['lib/**/*.rb', 'bin/*', 'README.md', 'LICENSE', 'CHANGELOG.md'].sort
  spec.executables = ['kiwicaptcha-doctor']
  spec.bindir = 'bin'

  # minitest 5.20 or newer; 6.x keeps the classic assertion API.
  spec.add_development_dependency 'minitest', '>= 5.20'
  spec.add_development_dependency 'rake', '~> 13.0'
end
