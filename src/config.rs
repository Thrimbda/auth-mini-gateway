use std::collections::HashSet;
use std::env;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use ipnet::IpNet;
use url::{Host, Url};

pub const DEFAULT_MAX_DOWNSTREAM_CONNECTIONS: usize = 256;
pub const DEFAULT_MAX_ACTIVE_UPSTREAMS: usize = 128;
pub const DEFAULT_MAX_BLOCKING_RESOLVERS: usize = 8;
pub const MAX_BLOCKING_RESOLVERS: usize = 32;
pub const PROXY_DOWNSTREAM_HEADROOM: usize = 16;

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
    pub upstream_protocol: UpstreamProtocol,
    pub max_downstream_connections: usize,
    pub max_active_upstreams: usize,
    pub max_blocking_resolvers: usize,
    pub trusted_proxy_cidrs: TrustedProxySet,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamProtocol {
    #[default]
    Auto,
    Http1,
    Http2,
}

impl UpstreamProtocol {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http1 => "http1",
            Self::Http2 => "http2",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamBase {
    scheme: String,
    authority: String,
    path_prefix: String,
    dial_target: DialTarget,
}

impl UpstreamBase {
    pub(crate) fn scheme(&self) -> &str {
        &self.scheme
    }

    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn path_prefix(&self) -> &str {
        &self.path_prefix
    }

    pub(crate) fn dial_target(&self) -> &DialTarget {
        &self.dial_target
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DialTarget {
    host: DialHost,
    port: u16,
}

impl DialTarget {
    pub(crate) fn host(&self) -> &DialHost {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DialHost {
    Ip(IpAddr),
    Domain(Box<str>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxySet {
    networks: Vec<IpNet>,
}

impl TrustedProxySet {
    pub fn contains(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(&address))
    }

    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Lax,
    Strict,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError {
    class: &'static str,
    message: &'static str,
}

impl ConfigError {
    const fn new(class: &'static str, message: &'static str) -> Self {
        Self { class, message }
    }

    pub const fn class(self) -> &'static str {
        self.class
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let auth_mini_issuer = normalize_base_url(
            &env::var("AUTH_MINI_ISSUER").unwrap_or_else(|_| "http://127.0.0.1:7777".to_string()),
            "auth_mini_issuer_invalid",
            "AUTH_MINI_ISSUER must be a valid HTTP(S) URL",
        )?;
        let public_base_url = normalize_base_url(
            &env::var("GATEWAY_PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            "public_base_url_invalid",
            "GATEWAY_PUBLIC_BASE_URL must be a valid HTTP(S) URL",
        )?;
        let auth_mini_public_base_url = normalize_base_url(
            &env::var("AUTH_MINI_PUBLIC_BASE_URL").unwrap_or_else(|_| auth_mini_issuer.clone()),
            "auth_mini_public_base_url_invalid",
            "AUTH_MINI_PUBLIC_BASE_URL must be a valid HTTP(S) URL",
        )?;
        let cookie_secret = env::var("GATEWAY_COOKIE_SECRET").unwrap_or_default();
        if cookie_secret.len() < 32 {
            return Err(ConfigError::new(
                "cookie_secret_invalid",
                "GATEWAY_COOKIE_SECRET must be at least 32 characters",
            ));
        }

        let max_downstream_connections = parse_capacity(
            env::var("GATEWAY_MAX_DOWNSTREAM_CONNECTIONS")
                .ok()
                .as_deref(),
            DEFAULT_MAX_DOWNSTREAM_CONNECTIONS,
            "downstream_connection_limit_invalid",
            "GATEWAY_MAX_DOWNSTREAM_CONNECTIONS must be a supported positive integer",
        )?;
        let max_active_upstreams = parse_capacity(
            env::var("GATEWAY_MAX_ACTIVE_UPSTREAMS").ok().as_deref(),
            DEFAULT_MAX_ACTIVE_UPSTREAMS,
            "active_upstream_limit_invalid",
            "GATEWAY_MAX_ACTIVE_UPSTREAMS must be a supported positive integer",
        )?;
        let max_blocking_resolvers = parse_bounded_capacity(
            env::var("GATEWAY_MAX_BLOCKING_RESOLVERS").ok().as_deref(),
            DEFAULT_MAX_BLOCKING_RESOLVERS,
            1,
            MAX_BLOCKING_RESOLVERS,
            "blocking_resolver_limit_invalid",
            "GATEWAY_MAX_BLOCKING_RESOLVERS must be an integer from 1 through 32",
        )?;
        let trusted_proxy_cidrs =
            parse_trusted_proxy_cidrs(env::var("TRUSTED_PROXY_CIDRS").ok().as_deref())?;
        // Parse the URL first so an invalid origin remains the authoritative
        // startup failure when both settings are malformed.
        let upstream = parse_upstream_url(env::var("UPSTREAM_URL").ok().as_deref())?;
        let upstream_protocol =
            parse_upstream_protocol(env::var("UPSTREAM_PROTOCOL").ok().as_deref())?;

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
            upstream,
            upstream_protocol,
            max_downstream_connections,
            max_active_upstreams,
            max_blocking_resolvers,
            trusted_proxy_cidrs,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_session_lifetimes(
            self.session_touch_interval_seconds,
            self.session_ttl_seconds,
            self.session_absolute_ttl_seconds,
        )?;
        validate_capacity(
            self.max_downstream_connections,
            "downstream_connection_limit_invalid",
        )?;
        validate_capacity(self.max_active_upstreams, "active_upstream_limit_invalid")?;
        if !(1..=MAX_BLOCKING_RESOLVERS).contains(&self.max_blocking_resolvers) {
            return Err(ConfigError::new(
                "blocking_resolver_limit_invalid",
                "GATEWAY_MAX_BLOCKING_RESOLVERS must be an integer from 1 through 32",
            ));
        }
        validate_upstream_protocol(self.upstream.as_ref(), self.upstream_protocol)?;
        if self.upstream.is_some() {
            let minimum = self
                .max_active_upstreams
                .checked_add(PROXY_DOWNSTREAM_HEADROOM)
                .ok_or_else(|| {
                    ConfigError::new(
                        "proxy_capacity_headroom_invalid",
                        "proxy mode requires downstream capacity headroom",
                    )
                })?;
            if self.max_downstream_connections < minimum {
                return Err(ConfigError::new(
                    "proxy_capacity_headroom_invalid",
                    "proxy mode requires at least 16 downstream slots beyond active upstreams",
                ));
            }
        }
        Ok(())
    }
}

pub fn parse_upstream_protocol(value: Option<&str>) -> Result<UpstreamProtocol, ConfigError> {
    match value {
        None | Some("") => Ok(UpstreamProtocol::Auto),
        Some("auto") => Ok(UpstreamProtocol::Auto),
        Some("http1") => Ok(UpstreamProtocol::Http1),
        Some("http2") => Ok(UpstreamProtocol::Http2),
        Some(_) => Err(ConfigError::new(
            "upstream_protocol_invalid",
            "UPSTREAM_PROTOCOL must be exactly auto, http1, or http2",
        )),
    }
}

fn validate_upstream_protocol(
    upstream: Option<&UpstreamBase>,
    protocol: UpstreamProtocol,
) -> Result<(), ConfigError> {
    if upstream.is_some_and(|upstream| upstream.scheme() == "http")
        && protocol == UpstreamProtocol::Auto
    {
        return Err(ConfigError::new(
            "upstream_protocol_cleartext_auto",
            "cleartext proxy mode requires UPSTREAM_PROTOCOL=http1 or http2",
        ));
    }
    Ok(())
}

pub fn parse_upstream_url(value: Option<&str>) -> Result<Option<UpstreamBase>, ConfigError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let parsed = Url::parse(value).map_err(|_| upstream_error())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.cannot_be_a_base()
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(upstream_error());
    }

    let host = match parsed.host().ok_or_else(upstream_error)? {
        Host::Ipv4(address) => DialHost::Ip(IpAddr::V4(address)),
        Host::Ipv6(address) => DialHost::Ip(IpAddr::V6(address)),
        Host::Domain(domain) => DialHost::Domain(domain.to_owned().into_boxed_str()),
    };
    let port = parsed.port_or_known_default().ok_or_else(upstream_error)?;
    let authority = parsed[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let path_prefix = parsed.path().trim_end_matches('/').to_string();
    Ok(Some(UpstreamBase {
        scheme: parsed.scheme().to_string(),
        authority,
        path_prefix,
        dial_target: DialTarget { host, port },
    }))
}

pub fn parse_trusted_proxy_cidrs(value: Option<&str>) -> Result<TrustedProxySet, ConfigError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(TrustedProxySet::default());
    };
    let mut networks = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() || !entry.contains('/') {
            return Err(trusted_proxy_error());
        }
        networks.push(IpNet::from_str(entry).map_err(|_| trusted_proxy_error())?);
    }
    Ok(TrustedProxySet { networks })
}

fn upstream_error() -> ConfigError {
    ConfigError::new(
        "upstream_url_invalid",
        "UPSTREAM_URL must be a fixed absolute HTTP(S) URL without credentials, query, or fragment",
    )
}

fn trusted_proxy_error() -> ConfigError {
    ConfigError::new(
        "trusted_proxy_cidrs_invalid",
        "TRUSTED_PROXY_CIDRS must be a comma-separated explicit-prefix CIDR list",
    )
}

fn validate_session_lifetimes(touch: i64, idle: i64, absolute: i64) -> Result<(), ConfigError> {
    if touch <= 0 || idle <= 0 || absolute <= 0 {
        return Err(ConfigError::new(
            "session_lifetime_invalid",
            "session lifecycle values must be positive and ordered",
        ));
    }
    if touch > idle || idle > absolute {
        return Err(ConfigError::new(
            "session_lifetime_invalid",
            "session lifecycle values must be positive and ordered",
        ));
    }
    Ok(())
}

fn normalize_base_url(
    value: &str,
    class: &'static str,
    message: &'static str,
) -> Result<String, ConfigError> {
    let mut parsed = Url::parse(value).map_err(|_| ConfigError::new(class, message))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ConfigError::new(class, message));
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let path = parsed.path().trim_end_matches('/').to_string();
    parsed.set_path(&path);
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn parse_capacity(
    value: Option<&str>,
    default: usize,
    class: &'static str,
    message: &'static str,
) -> Result<usize, ConfigError> {
    let parsed = match value.filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| ConfigError::new(class, message))?,
        None => default,
    };
    validate_capacity(parsed, class).map_err(|_| ConfigError::new(class, message))?;
    Ok(parsed)
}

fn parse_bounded_capacity(
    value: Option<&str>,
    default: usize,
    minimum: usize,
    maximum: usize,
    class: &'static str,
    message: &'static str,
) -> Result<usize, ConfigError> {
    let parsed = match value.filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| ConfigError::new(class, message))?,
        None => default,
    };
    if !(minimum..=maximum).contains(&parsed) {
        return Err(ConfigError::new(class, message));
    }
    Ok(parsed)
}

fn validate_capacity(value: usize, class: &'static str) -> Result<(), ConfigError> {
    if value == 0 || value > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(ConfigError::new(
            class,
            "configured capacity is out of range",
        ));
    }
    Ok(())
}

fn parse_u16(name: &'static str, default: u16) -> Result<u16, ConfigError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|_| ConfigError::new("port_invalid", "PORT must be a valid port"))
        })
}

fn parse_i64(name: &'static str, default: i64) -> Result<i64, ConfigError> {
    let value = env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .map_or(Ok(default), |value| {
            value.parse().map_err(|_| {
                ConfigError::new(
                    "session_lifetime_invalid",
                    "session lifecycle value is invalid",
                )
            })
        })?;
    if value <= 0 {
        return Err(ConfigError::new(
            "session_lifetime_invalid",
            "session lifecycle value must be positive",
        ));
    }
    Ok(value)
}

fn parse_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    if value.is_empty() {
        return Ok(default);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::new(
            "boolean_invalid",
            "boolean configuration value is invalid",
        )),
    }
}

fn parse_same_site(value: &str) -> Result<SameSite, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "lax" => Ok(SameSite::Lax),
        "strict" => Ok(SameSite::Strict),
        "none" => Ok(SameSite::None),
        _ => Err(ConfigError::new(
            "cookie_same_site_invalid",
            "COOKIE_SAME_SITE must be lax, strict, or none",
        )),
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn production_capacity_defaults_and_resolver_max_are_pinned() {
        assert_eq!(DEFAULT_MAX_DOWNSTREAM_CONNECTIONS, 256);
        assert_eq!(DEFAULT_MAX_ACTIVE_UPSTREAMS, 128);
        assert_eq!(DEFAULT_MAX_BLOCKING_RESOLVERS, 8);
        assert_eq!(MAX_BLOCKING_RESOLVERS, 32);
        assert_eq!(PROXY_DOWNSTREAM_HEADROOM, 16);
    }

    #[test]
    fn lifecycle_validation_enforces_positive_ordering() {
        assert!(validate_session_lifetimes(3_600, 604_800, 2_592_000).is_ok());
        assert!(validate_session_lifetimes(0, 604_800, 2_592_000).is_err());
        assert!(validate_session_lifetimes(604_801, 604_800, 2_592_000).is_err());
        assert!(validate_session_lifetimes(3_600, 2_592_001, 2_592_000).is_err());
    }

    #[test]
    fn upstream_url_is_optional_and_preserves_typed_dial_and_canonical_base() {
        assert_eq!(parse_upstream_url(None).expect("missing"), None);
        assert_eq!(parse_upstream_url(Some("")).expect("empty"), None);
        let upstream = parse_upstream_url(Some("https://ExAmPle.COM:8443/base/"))
            .expect("valid")
            .expect("configured");
        assert_eq!(upstream.scheme(), "https");
        assert_eq!(upstream.authority(), "example.com:8443");
        assert_eq!(upstream.path_prefix(), "/base");
        assert_eq!(
            upstream.dial_target(),
            &DialTarget {
                host: DialHost::Domain("example.com".into()),
                port: 8443,
            }
        );
    }

    #[test]
    fn typed_hosts_cover_ip_families_and_default_ports_without_authority_rebuild() {
        for (url, host, port, authority) in [
            (
                "http://192.0.2.10:4096/base",
                DialHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                4096,
                "192.0.2.10:4096",
            ),
            (
                "http://192.0.2.10/base",
                DialHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                80,
                "192.0.2.10",
            ),
            (
                "http://[2001:db8::1]:4096/base",
                DialHost::Ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").expect("IPv6"))),
                4096,
                "[2001:db8::1]:4096",
            ),
            (
                "https://[2001:db8::1]/",
                DialHost::Ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").expect("IPv6"))),
                443,
                "[2001:db8::1]",
            ),
        ] {
            let upstream = parse_upstream_url(Some(url)).expect("valid").expect("some");
            assert_eq!(upstream.dial_target().host(), &host);
            assert_eq!(upstream.dial_target().port(), port);
            assert_eq!(upstream.authority(), authority);
        }

        let default_domain = parse_upstream_url(Some("https://ExAmPle.COM:443/"))
            .expect("valid domain")
            .expect("configured domain");
        assert_eq!(
            default_domain.dial_target(),
            &DialTarget {
                host: DialHost::Domain("example.com".into()),
                port: 443,
            }
        );
        assert_eq!(default_domain.authority(), "example.com");
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

    #[test]
    fn upstream_protocol_has_exact_value_neutral_enum_semantics() {
        assert_eq!(parse_upstream_protocol(None), Ok(UpstreamProtocol::Auto));
        assert_eq!(
            parse_upstream_protocol(Some("")),
            Ok(UpstreamProtocol::Auto)
        );
        assert_eq!(
            parse_upstream_protocol(Some("auto")),
            Ok(UpstreamProtocol::Auto)
        );
        assert_eq!(
            parse_upstream_protocol(Some("http1")),
            Ok(UpstreamProtocol::Http1)
        );
        assert_eq!(
            parse_upstream_protocol(Some("http2")),
            Ok(UpstreamProtocol::Http2)
        );

        for invalid in ["AUTO", "h2", "http/1.1", " http1", "http2 ", "https"] {
            let error = parse_upstream_protocol(Some(invalid)).expect_err("invalid protocol");
            assert_eq!(error.class(), "upstream_protocol_invalid");
        }
        let raw = "raw-protocol-value-marker";
        let error = parse_upstream_protocol(Some(raw)).expect_err("invalid raw protocol");
        assert!(!error.to_string().contains(raw));
    }

    #[test]
    fn upstream_protocol_validation_is_origin_aware_and_adapter_safe() {
        let cleartext = parse_upstream_url(Some("http://127.0.0.1:4096"))
            .expect("valid cleartext URL")
            .expect("cleartext upstream");
        let https = parse_upstream_url(Some("https://upstream.example"))
            .expect("valid HTTPS URL")
            .expect("HTTPS upstream");

        for protocol in [
            UpstreamProtocol::Auto,
            UpstreamProtocol::Http1,
            UpstreamProtocol::Http2,
        ] {
            assert!(validate_upstream_protocol(None, protocol).is_ok());
            assert!(validate_upstream_protocol(Some(&https), protocol).is_ok());
        }
        for protocol in [UpstreamProtocol::Http1, UpstreamProtocol::Http2] {
            assert!(validate_upstream_protocol(Some(&cleartext), protocol).is_ok());
        }
        let error = validate_upstream_protocol(Some(&cleartext), UpstreamProtocol::Auto)
            .expect_err("cleartext auto must fail");
        assert_eq!(error.class(), "upstream_protocol_cleartext_auto");
        assert!(!error.to_string().contains(cleartext.authority()));
    }

    #[test]
    fn resolver_limit_parser_has_exact_value_neutral_bounds() {
        assert_eq!(
            parse_bounded_capacity(None, 8, 1, 32, "class", "fixed"),
            Ok(8)
        );
        assert_eq!(
            parse_bounded_capacity(Some(""), 8, 1, 32, "class", "fixed"),
            Ok(8)
        );
        assert_eq!(
            parse_bounded_capacity(Some("1"), 8, 1, 32, "class", "fixed"),
            Ok(1)
        );
        assert_eq!(
            parse_bounded_capacity(Some("32"), 8, 1, 32, "class", "fixed"),
            Ok(32)
        );
        for invalid in ["0", "33", "invalid", "184467440737095516160"] {
            let error = parse_bounded_capacity(Some(invalid), 8, 1, 32, "class", "fixed")
                .expect_err("invalid");
            assert_eq!(error.to_string(), "fixed");
            assert!(!error.to_string().contains(invalid));
        }
    }

    #[test]
    fn trusted_proxy_list_requires_explicit_prefixes_and_preserves_families() {
        let empty = parse_trusted_proxy_cidrs(None).expect("empty");
        assert!(empty.is_empty());
        let trusted =
            parse_trusted_proxy_cidrs(Some("127.0.0.1/32,2001:db8::/32")).expect("valid CIDRs");
        assert!(trusted.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(trusted.contains(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").expect("IPv6"))));
        assert!(!trusted.contains(IpAddr::V6(
            Ipv6Addr::from_str("::ffff:127.0.0.1").expect("mapped")
        )));
        for invalid in ["127.0.0.1", "127.0.0.1/33", ",127.0.0.1/32"] {
            let error = parse_trusted_proxy_cidrs(Some(invalid)).expect_err("invalid CIDR");
            assert!(!error.to_string().contains(invalid));
        }
    }
}
