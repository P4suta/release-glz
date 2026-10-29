#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../invariants/identifiers.rs"]
mod invariants;

fuzz_target!(|data: &[u8]| {
    invariants::check(data);
});
