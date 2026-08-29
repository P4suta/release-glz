use release_glz::canonical::{canonical_json_bytes, canonical_sha256};
use serde_json::{Value, json};

#[test]
fn canonical_json_follows_utf16_property_order() {
    // RFC 8785 sorts property names by UTF-16 code units. U+10000 therefore
    // sorts before U+E000 even though its Unicode scalar value is greater.
    let value = json!({"\u{10000}": 1, "\u{e000}": 2, "a": 3});
    let canonical = String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap();
    assert_eq!(canonical, "{\"a\":3,\"𐀀\":1,\"\":2}");
}

#[test]
fn canonical_json_uses_ecmascript_number_spelling() {
    let value: Value =
        serde_json::from_str(r#"[333333333.33333329,1e30,4.50,2e-3,1e-27,1e20,1e-6,-0.0]"#)
            .unwrap();
    let canonical = String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap();
    assert_eq!(
        canonical,
        "[333333333.3333333,1e+30,4.5,0.002,1e-27,100000000000000000000,0.000001,0]"
    );
}

#[test]
fn canonical_digest_is_independent_of_object_insertion_order() {
    let left: Value = serde_json::from_str(r#"{"z":1,"nested":{"b":2,"a":1}}"#).unwrap();
    let right: Value = serde_json::from_str(r#"{"nested":{"a":1,"b":2},"z":1}"#).unwrap();
    assert_eq!(
        canonical_sha256(&left).unwrap(),
        canonical_sha256(&right).unwrap()
    );
}

#[test]
fn canonical_json_preserves_the_unsigned_integer_domain() {
    let value = json!({"maximum": u64::MAX, "negative": i64::MIN});
    let canonical = String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap();
    assert_eq!(
        canonical,
        "{\"maximum\":18446744073709551615,\"negative\":-9223372036854775808}"
    );
}
