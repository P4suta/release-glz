#![no_main]

use libfuzzer_sys::fuzz_target;
use release_glz::forge::is_managed_release_pr;

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = std::str::from_utf8(data) {
        let _ = is_managed_release_pr(body);
    }
});
