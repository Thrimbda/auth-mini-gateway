use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;

use crate::util::b64_decode;

#[derive(Clone)]
pub struct VerifiedAccessToken {
    pub user_id: String,
    pub auth_session_id: String,
    pub amr: Vec<String>,
    pub exp: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTokenVerificationError {
    AudienceRejected,
    Invalid,
}

impl std::fmt::Display for AccessTokenVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("access token verification failed")
    }
}

impl std::error::Error for AccessTokenVerificationError {}

#[derive(Clone, Debug, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    pub alg: Option<String>,
    pub crv: Option<String>,
    pub kid: Option<String>,
    pub kty: Option<String>,
    pub x: Option<String>,
}

pub fn verify_access_token(
    token: &str,
    jwks: &Jwks,
    expected_issuer: &str,
    expected_audience: &str,
    now_unix: i64,
) -> Result<VerifiedAccessToken, AccessTokenVerificationError> {
    use AccessTokenVerificationError::Invalid;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Invalid);
    }

    let header: Value = decode_json(parts[0]).map_err(|_| Invalid)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(Invalid);
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or(Invalid)?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(kid))
        .ok_or(Invalid)?;
    if jwk.alg.as_deref() != Some("EdDSA")
        || jwk.kty.as_deref() != Some("OKP")
        || jwk.crv.as_deref() != Some("Ed25519")
    {
        return Err(Invalid);
    }

    let public_bytes = b64_decode(jwk.x.as_deref().ok_or(Invalid)?).map_err(|_| Invalid)?;
    let public_bytes: [u8; 32] = public_bytes.try_into().map_err(|_| Invalid)?;
    let signature_bytes = b64_decode(parts[2]).map_err(|_| Invalid)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| Invalid)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes).map_err(|_| Invalid)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Invalid)?;

    let payload: Value = decode_json(parts[1]).map_err(|_| Invalid)?;
    if payload.get("iss").and_then(Value::as_str) != Some(expected_issuer) {
        return Err(Invalid);
    }
    if payload.get("typ").and_then(Value::as_str) != Some("access") {
        return Err(Invalid);
    }
    let exp = payload.get("exp").and_then(Value::as_i64).ok_or(Invalid)?;
    if exp <= now_unix {
        return Err(Invalid);
    }
    let user_id = payload
        .get("sub")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(Invalid)?
        .to_string();
    let auth_session_id = payload
        .get("sid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(Invalid)?
        .to_string();
    let amr = payload
        .get("amr")
        .and_then(Value::as_array)
        .ok_or(Invalid)?
        .iter()
        .map(|item| item.as_str().map(ToOwned::to_owned).ok_or(Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    if !audience_claim_contains(payload.get("aud"), expected_audience) {
        return Err(AccessTokenVerificationError::AudienceRejected);
    }

    Ok(VerifiedAccessToken {
        user_id,
        auth_session_id,
        amr,
        exp,
    })
}

/// auth-mini signs a single audience as a string and a multi-audience session
/// as a canonical array (RFC 7519 section 4.1.3). Either form must name the
/// exact gateway hostname; a malformed array is rejected as a whole.
fn audience_claim_contains(claim: Option<&Value>, expected_audience: &str) -> bool {
    match claim {
        Some(Value::String(audience)) => audience == expected_audience,
        Some(Value::Array(audiences)) => {
            let mut found = false;
            for audience in audiences {
                match audience.as_str() {
                    Some("") | None => return false,
                    Some(audience) => found |= audience == expected_audience,
                }
            }
            found
        }
        _ => false,
    }
}

fn decode_json(segment: &str) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&b64_decode(segment)?)?)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use crate::util::b64_encode;

    use super::*;

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn accepts_only_the_exact_signed_string_audience() {
        let (jwks, signing_key) = fixture_key();
        let token = signed_token(
            &signing_key,
            json!({
                "sub": "user-1",
                "sid": "session-1",
                "iss": "https://auth.example",
                "aud": "app.example",
                "amr": ["email_otp"],
                "typ": "access",
                "exp": NOW + 60
            }),
        );
        let verified =
            verify_access_token(&token, &jwks, "https://auth.example", "app.example", NOW)
                .expect("matching audience");
        assert_eq!(verified.user_id, "user-1");
        assert_eq!(verified.auth_session_id, "session-1");
    }

    #[test]
    fn accepts_signed_audience_arrays_that_name_the_gateway() {
        let (jwks, signing_key) = fixture_key();
        for audience in [
            json!(["app.example"]),
            json!(["app.example", "portal.example"]),
            json!(["other.example", "app.example"]),
        ] {
            let token = signed_token(
                &signing_key,
                json!({
                    "sub": "user-1",
                    "sid": "session-1",
                    "iss": "https://auth.example",
                    "aud": audience,
                    "amr": ["sso", "email_otp"],
                    "typ": "access",
                    "exp": NOW + 60
                }),
            );
            let verified =
                verify_access_token(&token, &jwks, "https://auth.example", "app.example", NOW)
                    .expect("audience array names the gateway");
            assert_eq!(verified.amr, ["sso", "email_otp"]);
        }
    }

    #[test]
    fn rejects_missing_malformed_and_mismatched_signed_audiences() {
        let (jwks, signing_key) = fixture_key();
        for audience in [
            Value::Null,
            json!(""),
            json!("other.example"),
            json!("APP.example"),
            json!([]),
            json!(["other.example"]),
            json!(["app.example", 42]),
            json!(["app.example", ""]),
            json!([["app.example"]]),
            json!({"value": "app.example"}),
            json!(42),
        ] {
            let mut payload = json!({
                "sub": "user-1",
                "sid": "session-1",
                "iss": "https://auth.example",
                "amr": ["email_otp"],
                "typ": "access",
                "exp": NOW + 60
            });
            if !audience.is_null() {
                payload["aud"] = audience;
            }
            let token = signed_token(&signing_key, payload);
            assert!(matches!(
                verify_access_token(&token, &jwks, "https://auth.example", "app.example", NOW,),
                Err(AccessTokenVerificationError::AudienceRejected)
            ));
        }
    }

    #[test]
    fn untrusted_or_other_invalid_claims_are_not_audience_rejections() {
        let (jwks, signing_key) = fixture_key();
        let invalid_issuer = signed_token(
            &signing_key,
            json!({
                "sub": "user-1",
                "sid": "session-1",
                "iss": "https://other.example",
                "aud": "other.example",
                "amr": ["email_otp"],
                "typ": "access",
                "exp": NOW + 60
            }),
        );
        assert!(matches!(
            verify_access_token(
                &invalid_issuer,
                &jwks,
                "https://auth.example",
                "app.example",
                NOW,
            ),
            Err(AccessTokenVerificationError::Invalid)
        ));

        let mut invalid_signature = invalid_issuer;
        invalid_signature.push('x');
        assert!(matches!(
            verify_access_token(
                &invalid_signature,
                &jwks,
                "https://auth.example",
                "app.example",
                NOW,
            ),
            Err(AccessTokenVerificationError::Invalid)
        ));
    }

    fn fixture_key() -> (Jwks, SigningKey) {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let jwks = Jwks {
            keys: vec![Jwk {
                alg: Some("EdDSA".to_string()),
                crv: Some("Ed25519".to_string()),
                kid: Some("fixture".to_string()),
                kty: Some("OKP".to_string()),
                x: Some(b64_encode(signing_key.verifying_key().as_bytes())),
            }],
        };
        (jwks, signing_key)
    }

    fn signed_token(signing_key: &SigningKey, payload: Value) -> String {
        let header = json!({"alg": "EdDSA", "kid": "fixture", "typ": "JWT"});
        let encoded_header = b64_encode(header.to_string().as_bytes());
        let encoded_payload = b64_encode(payload.to_string().as_bytes());
        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64_encode(&signature.to_bytes()))
    }
}
