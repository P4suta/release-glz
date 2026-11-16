use std::collections::BTreeMap;
use std::fmt;

use proptest::prelude::*;
use proptest::sample::select;
use release_glz::canonical::{canonical_json_bytes, canonical_sha256};
use release_glz_core::utf16_cmp;
use release_glz_test_support::property;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::{Number, Value, json};

#[test]
fn canonical_json_follows_utf16_property_order() {
    // RFC 8785 sorts property names by UTF-16 code units.
    // U+10000 therefore sorts before U+E000 even though its Unicode scalar value is greater.
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

proptest! {
    #![proptest_config(property::config(512))]

    /// The canonical bytes of a value depend only on the value, not on how it was spelled.
    #[test]
    fn generated_values_canonicalize_to_bytes_of_the_value_alone(value in json_value()) {
        let canonical = canonical_json_bytes(&value).unwrap();
        prop_assert_eq!(&canonical_json_bytes(&value).unwrap(), &canonical);
        let respelled: Value =
            serde_json::from_slice(&serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        prop_assert_eq!(canonical_json_bytes(&respelled).unwrap(), canonical);
    }

    /// Canonical bytes parse back to the value, and canonicalizing it again changes no byte.
    #[test]
    fn generated_values_parse_back_from_their_canonical_bytes(value in json_value()) {
        let canonical = canonical_json_bytes(&value).unwrap();
        let parsed: Value = serde_json::from_slice(&canonical).unwrap();
        prop_assert!(
            same_value(&parsed, &value),
            "{} parses back as {parsed}",
            String::from_utf8_lossy(&canonical)
        );
        prop_assert_eq!(canonical_json_bytes(&parsed).unwrap(), canonical);
    }

    /// Every object lists its members in the core's key order.
    #[test]
    fn generated_objects_list_their_members_in_the_core_key_order(value in json_value()) {
        let canonical = canonical_json_bytes(&value).unwrap();
        let members: Members = serde_json::from_slice(&canonical).unwrap();
        prop_assert!(
            members.in_key_order(),
            "{} lists members out of order",
            String::from_utf8_lossy(&canonical)
        );
    }

    /// A value that JSON can't represent is refused instead of written.
    #[test]
    fn values_outside_the_json_domain_are_refused(value in outside_json()) {
        let error = canonical_json_bytes(&value).unwrap_err();
        prop_assert_eq!(error.to_string(), "value cannot be represented as JSON");
    }
}

/// Characters that JSON escapes, characters around the surrogate range that the UTF-16 key order separates, and plain letters.
const JSON_CHARACTERS: &[char] = &[
    'a',
    'b',
    'A',
    ' ',
    '"',
    '\\',
    '/',
    '\u{0}',
    '\u{8}',
    '\t',
    '\n',
    '\u{b}',
    '\u{1f}',
    '\u{7f}',
    'é',
    '\u{2028}',
    '\u{d7ff}',
    '\u{e000}',
    '\u{fffd}',
    '\u{ffff}',
    '\u{10000}',
    '\u{1f600}',
    '\u{10ffff}',
];

/// Text that mostly draws on [`JSON_CHARACTERS`], so two members of one object often differ only where the key orders disagree.
fn json_text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::collection::vec(select(JSON_CHARACTERS), 0..4).prop_map(String::from_iter),
        1 => any::<String>(),
    ]
}

/// Finite numbers, including the boundaries where ECMAScript changes its spelling and integral values that canonical JSON writes without a fraction.
fn json_float() -> impl Strategy<Value = f64> {
    use prop::num::f64::{NEGATIVE, NORMAL, POSITIVE, SUBNORMAL, ZERO};
    prop_oneof![
        POSITIVE | NEGATIVE | NORMAL | SUBNORMAL | ZERO,
        any::<i32>().prop_map(f64::from),
        select(vec![
            -0.0,
            5e-324,
            1e-7,
            1e-6,
            0.002,
            4.5,
            333_333_333.333_333_3,
            9_007_199_254_740_992.0,
            1_152_921_504_606_846_976.0,
            1e20,
            1e21,
            f64::MAX,
            f64::MIN,
        ]),
    ]
}

/// JSON values of bounded depth and size, inside the domain that canonical JSON writes.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        json_float().prop_map(Value::from),
        json_text().prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 48, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map(json_text(), inner, 0..5)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

/// Whether two JSON values are the same value, where numbers count as the numbers they denote.
fn same_value(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => same_number(left, right),
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| same_value(l, r))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, l)| right.get(key).is_some_and(|r| same_value(l, r)))
        }
        _ => left == right,
    }
}

/// Integers compare exactly, and a number with a fraction or an exponent compares as the double it denotes.
///
/// Canonical JSON writes an integral double such as `4.0` as `4`, which reads back as an integer.
fn same_number(left: &Number, right: &Number) -> bool {
    if left.is_f64() || right.is_f64() {
        left.as_f64() == right.as_f64()
    } else {
        left == right
    }
}

/// The member names of every object in a JSON document, in document order.
#[derive(Debug)]
enum Members {
    Scalar,
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl Members {
    /// Whether every object names its members in strictly ascending core key order.
    fn in_key_order(&self) -> bool {
        match self {
            Self::Scalar => true,
            Self::Array(items) => items.iter().all(Self::in_key_order),
            Self::Object(members) => {
                members
                    .windows(2)
                    .all(|pair| utf16_cmp(&pair[0].0, &pair[1].0).is_lt())
                    && members.iter().all(|(_, value)| value.in_key_order())
            }
        }
    }
}

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_str<E>(self, _: &str) -> Result<Members, E> {
        Ok(Members::Scalar)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Members, A::Error> {
        let mut output = Vec::new();
        while let Some(item) = items.next_element()? {
            output.push(item);
        }
        Ok(Members::Array(output))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<Members, A::Error> {
        let mut output = Vec::new();
        while let Some(member) = members.next_entry()? {
            output.push(member);
        }
        Ok(Members::Object(output))
    }
}

/// A value that holds one part outside the JSON domain, somewhere inside ordinary JSON.
#[derive(Debug, Clone)]
enum OutsideJson {
    /// An integer outside both the `i64` and the `u64` range.
    Wide(i128),
    /// A map whose keys are byte sequences rather than strings.
    KeyedBySequence(BTreeMap<Vec<u8>, Value>),
    /// An array with the refused part between ordinary items.
    Array(Vec<Value>, Box<Self>, Vec<Value>),
    /// An object with the refused part as the value of its last member.
    Object(BTreeMap<String, Value>, String, Box<Self>),
}

impl Serialize for OutsideJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Wide(value) => value.serialize(serializer),
            Self::KeyedBySequence(members) => members.serialize(serializer),
            Self::Array(before, refused, after) => {
                let mut items = serializer.serialize_seq(Some(before.len() + 1 + after.len()))?;
                for item in before {
                    items.serialize_element(item)?;
                }
                items.serialize_element(refused)?;
                for item in after {
                    items.serialize_element(item)?;
                }
                items.end()
            }
            Self::Object(siblings, key, refused) => {
                let mut members = serializer.serialize_map(Some(siblings.len() + 1))?;
                for (name, value) in siblings {
                    members.serialize_entry(name, value)?;
                }
                members.serialize_entry(key, refused)?;
                members.end()
            }
        }
    }
}

/// Values that canonical JSON refuses, each with its refused part at a generated depth and position.
fn outside_json() -> impl Strategy<Value = OutsideJson> {
    let refused = prop_oneof![
        prop_oneof![
            i128::MIN..i128::from(i64::MIN),
            i128::from(u64::MAX) + 1..=i128::MAX,
        ]
        .prop_map(OutsideJson::Wide),
        prop::collection::btree_map(prop::collection::vec(any::<u8>(), 0..4), json_value(), 1..3)
            .prop_map(OutsideJson::KeyedBySequence),
    ];
    refused.prop_recursive(3, 8, 1, |inner| {
        prop_oneof![
            (
                prop::collection::vec(json_value(), 0..3),
                inner.clone(),
                prop::collection::vec(json_value(), 0..3)
            )
                .prop_map(|(before, refused, after)| OutsideJson::Array(
                    before,
                    Box::new(refused),
                    after
                )),
            (
                prop::collection::btree_map(json_text(), json_value(), 0..3),
                json_text(),
                inner
            )
                .prop_map(|(siblings, key, refused)| OutsideJson::Object(
                    siblings,
                    key,
                    Box::new(refused)
                )),
        ]
    })
}
