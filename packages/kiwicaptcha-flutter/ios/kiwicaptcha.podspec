# The iOS FFI-plugin podspec. It builds the native solver core as a
# STATIC library from the FFI crate at ../native and links it into the
# Flutter framework, so the Dart side reaches it through
# DynamicLibrary.process() (see lib/src/ffi_bindings.dart — a static
# library's symbols live in the app image).
#
# The .a is NOT checked in: the build script below invokes cargo per
# Xcode slice (device arm64, simulator arm64/x86_64) and lipos the
# results together. A machine that builds the app needs the Rust
# toolchain plus the iOS rust targets:
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# NOTE (verification status): this file is declarative and
# correct-by-inspection only. Xcode/CocoaPods were not run in this
# checkout (no iOS toolchain here); the REQUIRED local proof for the
# native core is `cargo test` + `cargo build --release` in ../native,
# and the device-side link is what an app build verifies.

Pod::Spec.new do |s|
  s.name             = 'kiwicaptcha'
  s.version          = '0.1.0'
  s.summary          = 'KiwiCaptcha Flutter FFI plugin (the Rust solver core).'
  s.description      = 'The native solver core of the KiwiCaptcha widget package: ' \
                       'sha256, argon2id and rsw solving over the shared C ABI ' \
                       '(libkiwicaptcha_solver).'
  s.homepage         = 'https://kiwicaptcha.dev'
  s.license          = { :type => 'MIT', :file => '../LICENSE' }
  s.author           = { 'Bel Consulting OÜ' => 'hello@bel.ee' }
  s.source           = { :path => '.' }
  s.dependency 'Flutter'
  s.platform         = :ios, '12.0'

  # FFI only: no Objective-C/Swift sources, no headers — the ABI is the
  # C surface documented in ../src/kiwicaptcha_solver.h.
  s.vendored_libraries = 'native/target/release/libkiwicaptcha_solver.a'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    # A static library is linked per-object: without -force_load the
    # linker drops every kiwi_solve_* symbol (nothing references them
    # from Swift/ObjC), and DynamicLibrary.process() would not find
    # them at runtime. Force-load keeps the whole core in the image.
    'OTHER_LDFLAGS' => '-force_load $(BUILT_PRODUCTS_DIR)/libkiwicaptcha_solver.a',
  }

  # Build the Rust core before the pod compiles: one cargo invocation
  # per Xcode slice, then a fat library into the vendored path.
  s.script_phase = {
    :name => 'Build the Rust solver core (libkiwicaptcha_solver.a)',
    :script => <<-SCRIPT,
      set -e
      POD_ROOT="${PODS_TARGET_SRCROOT}"
      NATIVE_DIR="${POD_ROOT}/../native"
      OUT_DIR="${POD_ROOT}/native/target/release"
      mkdir -p "${OUT_DIR}" "${TMPDIR}/kiwi-rust-slices"
      SLICES=""
      for ARCH in ${ARCHS}; do
        case "${ARCH}" in
          arm64)
            if [[ "${PLATFORM_NAME}" == *simulator ]]; then
              RUST_TARGET="aarch64-apple-ios-sim"
            else
              RUST_TARGET="aarch64-apple-ios"
            fi
            ;;
          x86_64) RUST_TARGET="x86_64-apple-ios" ;;
          *) echo "kiwicaptcha: unsupported Xcode arch ${ARCH}" >&2; exit 1 ;;
        esac
        cargo build --release --target "${RUST_TARGET}" --manifest-path "${NATIVE_DIR}/Cargo.toml"
        cp "${NATIVE_DIR}/target/${RUST_TARGET}/release/libkiwicaptcha_solver.a" \
           "${TMPDIR}/kiwi-rust-slices/libkiwicaptcha_solver_${RUST_TARGET}.a"
        SLICES="${SLICES} ${TMPDIR}/kiwi-rust-slices/libkiwicaptcha_solver_${RUST_TARGET}.a"
      done
      if [[ $(echo ${SLICES} | wc -w) -gt 1 ]]; then
        lipo -create ${SLICES} -output "${OUT_DIR}/libkiwicaptcha_solver.a"
      else
        cp ${SLICES} "${OUT_DIR}/libkiwicaptcha_solver.a"
      fi
    SCRIPT
    :execution_position => :before_compile,
    :output_files => ['$(PODS_TARGET_SRCROOT)/native/target/release/libkiwicaptcha_solver.a'],
  }
end
