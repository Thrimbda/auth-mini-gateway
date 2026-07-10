use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

use url::Url;

#[derive(Clone, Debug)]
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
    pub login_state_ttl_seconds: i64,
    pub refresh_skew_seconds: i64,
    pub allow_emails: HashSet<String>,
    pub allow_user_ids: HashSet<String>,
    pub logout_redirect: String,
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

        Ok(Self {
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
            session_ttl_seconds: parse_i64("SESSION_TTL_SECONDS", 8 * 60 * 60)?,
            login_state_ttl_seconds: parse_i64("LOGIN_STATE_TTL_SECONDS", 5 * 60)?,
            refresh_skew_seconds: parse_i64("REFRESH_SKEW_SECONDS", 60)?,
            allow_emails: parse_csv_lower("ALLOW_EMAILS"),
            allow_user_ids: parse_csv("ALLOW_USER_IDS"),
            logout_redirect: env::var("LOGOUT_REDIRECT").unwrap_or_else(|_| "/".to_string()),
        })
    }
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
