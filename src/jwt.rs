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
    now_unix: i64,
) -> Result<VerifiedAccessToken, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid jwt segments".into());
    }

    let header: Value = decode_json(parts[0])?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err("invalid jwt alg".into());
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("missing kid")?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid.as_deref() == Some(kid))
        .ok_or("unknown kid")?;
    if jwk.alg.as_deref() != Some("EdDSA")
        || jwk.kty.as_deref() != Some("OKP")
        || jwk.crv.as_deref() != Some("Ed25519")
    {
        return Err("unsupported jwk".into());
    }

    let public_bytes = b64_decode(jwk.x.as_deref().ok_or("missing jwk x")?)?;
    let public_bytes: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| "invalid ed25519 key length")?;
    let signature_bytes = b64_decode(parts[2])?;
    let signature = Signature::from_slice(&signature_bytes)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key.verify(signing_input.as_bytes(), &signature)?;

    let payload: Value = decode_json(parts[1])?;
    if payload.get("iss").and_then(Value::as_str) != Some(expected_issuer) {
        return Err("invalid issuer".into());
    }
    if payload.get("typ").and_then(Value::as_str) != Some("access") {
        return Err("invalid token type".into());
    }
    let exp = payload
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or("missing exp")?;
    if exp <= now_unix {
        return Err("token expired".into());
    }
    let user_id = payload
        .get("sub")
        .and_then(Value::as_str)
        .ok_or("missing sub")?
        .to_string();
    let auth_session_id = payload
        .get("sid")
        .and_then(Value::as_str)
        .ok_or("missing sid")?
        .to_string();
    let amr = payload
        .get("amr")
        .and_then(Value::as_array)
        .ok_or("missing amr")?
        .iter()
        .map(|item| item.as_str().map(ToOwned::to_owned).ok_or("invalid amr"))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VerifiedAccessToken {
        user_id,
        auth_session_id,
        amr,
        exp,
    })
}

fn decode_json(segment: &str) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&b64_decode(segment)?)?)
}
