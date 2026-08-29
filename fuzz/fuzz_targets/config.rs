#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use release_glz::config::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = Manifest::parse(PathBuf::from("gleam.toml"), source.to_owned());
    }
});
