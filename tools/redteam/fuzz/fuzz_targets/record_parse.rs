//! Coverage-guided no-panic fuzz of the challenge-record JSON parse
//! path: serde deserialization of attacker-shaped documents must
//! return Ok or Err, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use kiwicaptcha::challenge::ChallengeRecord;

fuzz_target!(|data: &[u8]| {
    // Direct bytes (the raw document) and the string round trip.
    let _ = serde_json::from_slice::<ChallengeRecord>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<ChallengeRecord>(s);
    }
});
