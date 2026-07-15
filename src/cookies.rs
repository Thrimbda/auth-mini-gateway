use chrono::{DateTime, Utc};
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
    expires_at: DateTime<Utc>,
    config: &Config,
) -> String {
    serialize_positive_cookie(
        name,
        &sign_value(value, &config.cookie_secret),
        expires_at,
        config,
    )
}

pub fn clear_cookie(name: &str, config: &Config) -> String {
    let mut parts = cookie_prefix(name, "", config);
    parts.push("Max-Age=0".to_string());
    parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string());
    parts.join("; ")
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

fn serialize_positive_cookie(
    name: &str,
    value: &str,
    expires_at: DateTime<Utc>,
    config: &Config,
) -> String {
    let mut parts = cookie_prefix(name, value, config);
    parts.push(format!(
        "Expires={}",
        expires_at.format("%a, %d %b %Y %H:%M:%S GMT")
    ));
    parts.join("; ")
}

fn cookie_prefix(name: &str, value: &str, config: &Config) -> Vec<String> {
    let mut parts = vec![
        format!("{}={}", name, percent_encode(value)),
        "Path=/".to_string(),
        "HttpOnly".to_string(),
        format!("SameSite={}", same_site_value(config.cookie_same_site)),
    ];
    if config.cookie_secure {
        parts.push("Secure".to_string());
    }
    parts
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
    use std::collections::HashSet;
    use std::path::PathBuf;

    use chrono::TimeZone;

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

    #[test]
    fn positive_cookie_uses_absolute_expires_without_max_age() {
        let cookie = serialize_signed_cookie(
            SESSION_COOKIE,
            "session-1",
            Utc.with_ymd_and_hms(2026, 7, 20, 12, 34, 56)
                .single()
                .expect("valid time"),
            &test_config(),
        );

        assert!(cookie.contains("Expires=Mon, 20 Jul 2026 12:34:56 GMT"));
        assert!(!cookie.contains("Max-Age"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn clear_cookie_uses_both_expiry_signals() {
        let cookie = clear_cookie(SESSION_COOKIE, &test_config());
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
    }

    fn test_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 3000,
            public_base_url: "http://localhost:8080".to_string(),
            auth_mini_issuer: "http://localhost:7777".to_string(),
            auth_mini_public_base_url: "http://localhost:7777".to_string(),
            auth_mini_login_url: None,
            database_path: PathBuf::from(":memory:"),
            cookie_secret: SECRET.to_string(),
            cookie_secure: true,
            cookie_same_site: SameSite::Lax,
            session_ttl_seconds: 604_800,
            session_absolute_ttl_seconds: 2_592_000,
            session_touch_interval_seconds: 3_600,
            login_state_ttl_seconds: 600,
            refresh_skew_seconds: 60,
            allow_emails: HashSet::new(),
            allow_user_ids: HashSet::new(),
            logout_redirect: "/".to_string(),
            upstream: None,
            max_downstream_connections: 256,
            max_active_upstreams: 128,
            max_blocking_resolvers: 8,
            trusted_proxy_cidrs: crate::config::TrustedProxySet::default(),
        }
    }
}
