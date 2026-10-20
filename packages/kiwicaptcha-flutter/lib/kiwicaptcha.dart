/// Flutter KiwiCaptcha: widget + Dart solver (FFI to the Rust core).
library kiwicaptcha;

export 'src/challenge.dart';
export 'src/lifecycle.dart';
export 'src/solver.dart';
export 'src/token.dart' show encodeKiwiToken, kiwiBase64Encode;
export 'src/widget.dart'
    show
        KiwiCaptcha,
        KiwiCaptchaState,
        KiwiClient,
        KiwiSiteverifyBody,
        KiwiHttpResponse;
export 'src/ffi_bindings.dart'
    show KiwiFfi, debugFfiOverride, kiwiOk, kiwiErrArgonUnavailable;
