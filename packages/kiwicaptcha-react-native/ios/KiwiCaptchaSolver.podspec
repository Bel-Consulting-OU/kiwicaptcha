# KiwiCaptchaSolver — the iOS native module of @kiwicaptcha/react-native
# (docs/NATIVE.md is the authoritative contract).
#
# Installed by React Native autolinking from node_modules (or a manual
# `pod 'KiwiCaptchaSolver', :path => '../node_modules/@kiwicaptcha/react-native'`
# — the spec root is this ios/ directory).

require 'json'

kiwi = JSON.parse(File.read(File.join(__dir__, '..', 'package.json')))

Pod::Spec.new do |s|
  s.name             = 'KiwiCaptchaSolver'
  s.version          = kiwi['version']
  s.summary          = 'KiwiCaptcha native proof-of-work solver for React Native (iOS, CryptoKit SHA-256).'
  s.description      = kiwi['description']
  s.homepage         = 'https://github.com/Bel-Consulting-OU/kiwicaptcha'
  s.license          = kiwi['license']
  s.authors          = { 'KiwiCaptcha' => 'packages/kiwicaptcha-react-native' }
  s.source           = { :git => 'https://github.com/Bel-Consulting-OU/kiwicaptcha.git',
                         :tag => "react-native-v#{s.version}" }

  # RN 0.73+ floor (iOS 13.4); CryptoKit SHA-256 needs 13.0+. Apps on
  # RN 0.76+ (iOS 15.1 floor) simply set their own higher minimum.
  s.platforms        = { :ios => '13.4', :tvos => '13.4', :visionos => '1.0' }

  s.source_files     = '*.{swift,h,m,mm}'

  # Swift 5.7+ floor (guard-let shorthand and the rest of the module
  # are authored against 5.7). `post_install` is a Podfile-only hook —
  # the podspec-legal form of that pacing is swift_version plus
  # pod_target_xcconfig, which re-assert the floor after CocoaPods has
  # merged whatever SWIFT_VERSION the consumer set. If an app's Podfile
  # post_install downgrades SWIFT_VERSION globally, re-assert there:
  #   post_install do |installer|
  #     installer.pods_project.targets.each do |target|
  #       next unless target.name == 'KiwiCaptchaSolver'
  #       target.build_configurations.each do |config|
  #         config.build_settings['SWIFT_VERSION'] = '5.7'
  #       end
  #     end
  #   end
  s.swift_version    = '5.7'
  s.pod_target_xcconfig = { 'SWIFT_VERSION' => '5.7' }

  # Classic bridge module (RCTBridgeModule); the interop layer of the
  # New Architecture serves it to TurboModuleRegistry unchanged.
  s.dependency 'React-Core'
end
