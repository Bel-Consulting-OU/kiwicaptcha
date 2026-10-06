//! Coverage-guided no-panic fuzz of the solution-token parse path:
//! every attacker-controlled byte string must yield Ok or Err, never
//! a panic (the same invariant the bounded mutation corpus holds, now
//! explored with libFuzzer's coverage feedback).
#![no_main]

use libfuzzer_sys::fuzz_target;
use kiwicaptcha::token::SolutionToken;

fuzz_target!(|data: &[u8]| {
    // The wire token is a string; invalid UTF-8 is refused at the
    // HTTP boundary before decode, so the fuzz surface is the string
    // form. Bytes that are not UTF-8 exercise the lossy refusal.
    match std::str::from_utf8(data) {
        Ok(s) => {
            let _ = SolutionToken::decode(s);
        }
        Err(_) => {
            let lossy = String::from_utf8_lossy(data);
            let _ = SolutionToken::decode(&lossy);
        }
    }
});
