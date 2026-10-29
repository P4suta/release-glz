#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../invariants/pr_marker.rs"]
mod invariants;

fuzz_target!(|data: &[u8]| {
    invariants::check(data);
});
