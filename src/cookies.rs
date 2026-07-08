use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::{Config, SameSite};
use crate::util::{b64_encode, timing_eq};

pub const SESSION_COOKIE: &str = "amg_session";
pub const LOGIN_STATE_COOKIE: &str = "amg_login_state";

type HmacSha256 = Hmac<Sha256>;

pub fn read_signed_cookie(cookie_header: Option<&str>, name: &str, secret: &str) -> Option<String> {
    let value = parse_cookie(cookie_header?, name)?;
    unsign_value(&value, secret)
}

pub fn serialize_signed_cookie(
    name: &str,
    value: &str,
    max_age_seconds: i64,
    config: &Config,
) -> String {
    serialize_cookie(
        name,
        &sign_value(value, &config.cookie_secret),
        max_age_seconds,
        config,
    )
}

pub fn clear_cookie(name: &str, config: &Config) -> String {
    serialize_cookie(name, "", 0, config)
}

pub fn sign_value(value: &str, secret: &str) -> String {
    format!("{}.{}", value, mac(value, secret))
}

pub fn unsign_value(value: &str, secret: &str) -> Option<String> {
    let index = value.rfind('.')?;
    let raw = &value[..index];
    let signature = &value[index + 1..];
    if timing_eq(signature, &mac(raw, secret)) {
        Some(raw.to_string())
    } else {
        None
    }
}

fn parse_cookie(header: &str, name: &str) -> Option<String> {
    for part in header.split(';') {
        let Some((cookie_name, cookie_value)) = part.trim().split_once('=') else {
            continue;
        };
        if cookie_name == name {
            return percent_decode(cookie_value);
        }
    }
    None
}

fn serialize_cookie(name: &str, value: &str, max_age_seconds: i64, config: &Config) -> String {
    let mut parts = vec![
        format!("{}={}", name, percent_encode(value)),
        "Path=/".to_string(),
        "HttpOnly".to_string(),
        format!("SameSite={}", same_site_value(config.cookie_same_site)),
        format!("Max-Age={}", max_age_seconds.max(0)),
    ];
    if config.cookie_secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn mac(value: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    b64_encode(&mac.finalize().into_bytes())
}

fn same_site_value(value: SameSite) -> &'static str {
    match value {
        SameSite::Lax => "Lax",
        SameSite::Strict => "Strict",
        SameSite::None => "None",
    }
}

fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-cookie-secret-that-is-long-enough";

    #[test]
    fn reads_valid_cookie_after_malformed_segment() {
        let signed = sign_value("session-1", SECRET);
        let header = format!("malformed; {}={}", SESSION_COOKIE, signed);

        assert_eq!(
            read_signed_cookie(Some(&header), SESSION_COOKIE, SECRET),
            Some("session-1".to_string())
        );
    }

    #[test]
    fn rejects_tampered_cookie_signature() {
        let signed = sign_value("session-1", SECRET).replace("session-1", "session-2");
        let header = format!("{}={}", SESSION_COOKIE, signed);

        assert_eq!(
            read_signed_cookie(Some(&header), SESSION_COOKIE, SECRET),
            None
        );
    }
}
