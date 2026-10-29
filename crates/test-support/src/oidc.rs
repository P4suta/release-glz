//! GitHub OIDC tokens signed with the RSA example key of RFC 7515, appendix A.2.
//!
//! Only signature verification yields a verified identity, so tests that need one sign their claims here and verify them like a real token.

use base64::Engine;
use ring::rand::SystemRandom;
use ring::rsa::{KeyPairComponents, PublicKeyComponents};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

/// The key id that every token's header names.
pub const KEY_ID: &str = "rfc7515";

/// The public exponent of the key, base64url-encoded.
pub const EXPONENT: &str = "AQAB";

/// The modulus of the key, base64url-encoded.
pub const MODULUS: &str = concat!(
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
    "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
    "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
    "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
    "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
    "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
);

const PRIVATE_EXPONENT: &str = concat!(
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I",
    "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0",
    "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn",
    "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT",
    "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh",
    "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
);
const PRIME_P: &str = concat!(
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi",
    "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG",
    "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
);
const PRIME_Q: &str = concat!(
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa",
    "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA",
    "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
);
const EXPONENT_P: &str = concat!(
    "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q",
    "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb",
    "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
);
const EXPONENT_Q: &str = concat!(
    "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa",
    "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky",
    "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
);
const INVERSE_Q: &str = concat!(
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o",
    "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU",
    "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
);

/// A compact RS256 JWT whose payload is `claims` and whose header names [`KEY_ID`].
pub fn sign_rs256(claims: &impl serde::Serialize) -> String {
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decode = |value: &str| {
        encoder
            .decode(value)
            .expect("the RFC 7515 key is base64url")
    };
    let [n, e, d, p, q, dp, dq, inverse_q] = [
        MODULUS,
        EXPONENT,
        PRIVATE_EXPONENT,
        PRIME_P,
        PRIME_Q,
        EXPONENT_P,
        EXPONENT_Q,
        INVERSE_Q,
    ]
    .map(decode);
    let key = RsaKeyPair::from_components(&KeyPairComponents {
        public_key: PublicKeyComponents { n: &n, e: &e },
        d: &d,
        p: &p,
        q: &q,
        dP: &dp,
        dQ: &dq,
        qInv: &inverse_q,
    })
    .expect("the RFC 7515 key is a valid RSA key");
    let header = encoder.encode(format!(r#"{{"alg":"RS256","kid":"{KEY_ID}"}}"#));
    let payload = encoder.encode(serde_json::to_vec(claims).expect("claims serialize to JSON"));
    let signing_input = format!("{header}.{payload}");
    let mut signature = vec![0_u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .expect("RSA signing succeeds");
    format!("{signing_input}.{}", encoder.encode(signature))
}
