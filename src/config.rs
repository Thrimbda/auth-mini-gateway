use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use url::Url;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub public_base_url: String,
    pub auth_mini_issuer: String,
    pub auth_mini_public_base_url: String,
    pub auth_mini_login_url: Option<String>,
    pub database_path: PathBuf,
    pub cookie_secret: String,
    pub cookie_secure: bool,
    pub cookie_same_site: SameSite,
    pub session_ttl_seconds: i64,
    pub session_absolute_ttl_seconds: i64,
    pub session_touch_interval_seconds: i64,
    pub login_state_ttl_seconds: i64,
    pub refresh_skew_seconds: i64,
    pub allow_emails: HashSet<String>,
    pub allow_user_ids: HashSet<String>,
    pub logout_redirect: String,
    pub upstream: Option<UpstreamBase>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamBase {
    pub scheme: String,
    pub authority: String,
    pub path_prefix: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    Strict,
    None,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let auth_mini_issuer = normalize_base_url(
            &env::var("AUTH_MINI_ISSUER").unwrap_or_else(|_| "http://127.0.0.1:7777".to_string()),
            "AUTH_MINI_ISSUER",
        )?;
        let public_base_url = normalize_base_url(
            &env::var("GATEWAY_PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            "GATEWAY_PUBLIC_BASE_URL",
        )?;
        let auth_mini_public_base_url = normalize_base_url(
            &env::var("AUTH_MINI_PUBLIC_BASE_URL").unwrap_or_else(|_| auth_mini_issuer.clone()),
            "AUTH_MINI_PUBLIC_BASE_URL",
        )?;
        let cookie_secret = env::var("GATEWAY_COOKIE_SECRET").unwrap_or_default();
        if cookie_secret.len() < 32 {
            return Err("GATEWAY_COOKIE_SECRET must be at least 32 characters".into());
        }

        let config = Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: parse_u16("PORT", 3000)?,
            public_base_url,
            auth_mini_issuer,
            auth_mini_public_base_url,
            auth_mini_login_url: env::var("AUTH_MINI_LOGIN_URL")
                .ok()
                .filter(|value| !value.is_empty()),
            database_path: env::var("GATEWAY_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./auth-mini-gateway.sqlite")),
            cookie_secret,
            cookie_secure: parse_bool("COOKIE_SECURE", true)?,
            cookie_same_site: parse_same_site(
                &env::var("COOKIE_SAME_SITE").unwrap_or_else(|_| "lax".to_string()),
            )?,
            session_ttl_seconds: parse_i64("SESSION_TTL_SECONDS", 7 * 24 * 60 * 60)?,
            session_absolute_ttl_seconds: parse_i64(
                "SESSION_ABSOLUTE_TTL_SECONDS",
                30 * 24 * 60 * 60,
            )?,
            session_touch_interval_seconds: parse_i64("SESSION_TOUCH_INTERVAL_SECONDS", 60 * 60)?,
            login_state_ttl_seconds: parse_i64("LOGIN_STATE_TTL_SECONDS", 10 * 60)?,
            refresh_skew_seconds: parse_i64("REFRESH_SKEW_SECONDS", 60)?,
            allow_emails: parse_csv_lower("ALLOW_EMAILS"),
            allow_user_ids: parse_csv("ALLOW_USER_IDS"),
            logout_redirect: env::var("LOGOUT_REDIRECT").unwrap_or_else(|_| "/".to_string()),
            upstream: parse_upstream_url(env::var("UPSTREAM_URL").ok().as_deref())?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        validate_session_lifetimes(
            self.session_touch_interval_seconds,
            self.session_ttl_seconds,
            self.session_absolute_ttl_seconds,
        )
        .map_err(Into::into)
    }
}

pub fn parse_upstream_url(
    value: Option<&str>,
) -> Result<Option<UpstreamBase>, Box<dyn std::error::Error>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = Url::parse(value).map_err(|_| "UPSTREAM_URL must be a valid absolute URL")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("UPSTREAM_URL must use http or https".into());
    }
    if parsed.cannot_be_a_base() || parsed.host().is_none() {
        return Err("UPSTREAM_URL must include an authority".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("UPSTREAM_URL must not include credentials".into());
    }
    if parsed.query().is_some() {
        return Err("UPSTREAM_URL must not include a query".into());
    }
    if parsed.fragment().is_some() {
        return Err("UPSTREAM_URL must not include a fragment".into());
    }

    let authority = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let path_prefix = parsed.path().trim_end_matches('/').to_string();
    Ok(Some(UpstreamBase {
        scheme: parsed.scheme().to_string(),
        authority,
        path_prefix,
    }))
}

fn validate_session_lifetimes(touch: i64, idle: i64, absolute: i64) -> Result<(), &'static str> {
    if touch <= 0 || idle <= 0 || absolute <= 0 {
        return Err("session lifecycle values must be positive");
    }
    if touch > idle {
        return Err("SESSION_TOUCH_INTERVAL_SECONDS must not exceed SESSION_TTL_SECONDS");
    }
    if idle > absolute {
        return Err("SESSION_TTL_SECONDS must not exceed SESSION_ABSOLUTE_TTL_SECONDS");
    }
    Ok(())
}

pub fn normalize_base_url(value: &str, name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut parsed = Url::parse(value).map_err(|_| format!("{name} must be a valid URL"))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(format!("{name} must use http or https").into());
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let path = parsed.path().trim_end_matches('/').to_string();
    parsed.set_path(&path);
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn parse_u16(name: &str, default: u16) -> Result<u16, Box<dyn std::error::Error>> {
    Ok(env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map_or(Ok(default), |v| v.parse())?)
}

fn parse_i64(name: &str, default: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value = env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .map_or(Ok(default), |v| v.parse())?;
    if value <= 0 {
        return Err(format!("{name} must be positive").into());
    }
    Ok(value)
}

fn parse_bool(name: &str, default: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    if value.is_empty() {
        return Ok(default);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{name} must be true or false").into()),
    }
}

fn parse_same_site(value: &str) -> Result<SameSite, Box<dyn std::error::Error>> {
    match value.to_ascii_lowercase().as_str() {
        "lax" => Ok(SameSite::Lax),
        "strict" => Ok(SameSite::Strict),
        "none" => Ok(SameSite::None),
        _ => Err("COOKIE_SAME_SITE must be lax, strict, or none".into()),
    }
}

fn parse_csv(name: &str) -> HashSet<String> {
    env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_csv_lower(name: &str) -> HashSet<String> {
    parse_csv(name)
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_upstream_url, validate_session_lifetimes, UpstreamBase};

    #[test]
    fn lifecycle_validation_enforces_positive_ordering() {
        assert!(validate_session_lifetimes(3_600, 604_800, 2_592_000).is_ok());
        assert!(validate_session_lifetimes(0, 604_800, 2_592_000).is_err());
        assert!(validate_session_lifetimes(604_801, 604_800, 2_592_000).is_err());
        assert!(validate_session_lifetimes(3_600, 2_592_001, 2_592_000).is_err());
    }

    #[test]
    fn upstream_url_is_optional_and_preserves_a_fixed_base_path() {
        assert_eq!(parse_upstream_url(None).expect("missing"), None);
        assert_eq!(parse_upstream_url(Some("")).expect("empty"), None);
        assert_eq!(
            parse_upstream_url(Some("https://app.example:8443/base/")).expect("valid"),
            Some(UpstreamBase {
                scheme: "https".to_string(),
                authority: "app.example:8443".to_string(),
                path_prefix: "/base".to_string(),
            })
        );
    }

    #[test]
    fn upstream_url_rejects_dynamic_or_ambiguous_parts_without_echoing_values() {
        for value in [
            "relative/path",
            "ftp://127.0.0.1/app",
            "http://user@127.0.0.1/app",
            "http://user:password@127.0.0.1/app",
            "http://127.0.0.1/app?",
            "http://127.0.0.1/app#",
            "http://",
            "ws://127.0.0.1/socket",
            "://malformed",
            "   ",
        ] {
            let error = parse_upstream_url(Some(value)).expect_err("invalid upstream");
            assert!(error.to_string().contains("UPSTREAM_URL"));
            assert!(!error.to_string().contains(value));
        }
    }
}
