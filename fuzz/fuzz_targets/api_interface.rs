#![no_main]

use libfuzzer_sys::fuzz_target;
use release_glz::api::compare;

fuzz_target!(|data: &[u8]| {
    let midpoint = data.len() / 2;
    let _ = compare(&data[..midpoint], &data[midpoint..]);
    let _ = compare(data, data);
});
