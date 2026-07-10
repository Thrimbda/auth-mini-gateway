use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use chrono::{Duration, SecondsFormat, TimeZone, Utc};
use serde::Deserialize;
use serde_json::json;
use url::{form_urlencoded, Url};

use crate::auth_mini::AuthMiniClient;
use crate::config::Config;
use crate::cookies::{
    clear_cookie, read_signed_cookie, serialize_signed_cookie, LOGIN_STATE_COOKIE, SESSION_COOKIE,
};
use crate::db::{GatewaySession, NewSession, RefreshUpdate, Store};
use crate::http::{is_safe_header_value, Request, Response};
use crate::policy::{evaluate, Identity, PolicyDecision};

pub fn run_server(
    config: Config,
    auth_mini: AuthMiniClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(address)?;
    let config = Arc::new(config);
    let store = Arc::new(Store::new(config.database_path.clone()));
    let auth_mini = Arc::new(auth_mini);

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        let config = Arc::clone(&config);
        let store = Arc::clone(&store);
        let auth_mini = Arc::clone(&auth_mini);
        thread::spawn(move || {
            let response = match Request::read(&mut stream) {
                Ok(request) => handle_request(request, &config, &store, &auth_mini)
                    .unwrap_or_else(|_| no_store(Response::text(500, "Internal server error"))),
                Err(_) => no_store(Response::text(400, "Bad request")),
            };
            let _ = response.write_to(&mut stream);
        });
    }

    Ok(())
}

fn handle_request(
    request: Request,
    config: &Config,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<Response, Box<dyn std::error::Error>> {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/healthz") => Ok(Response::empty(204)),
        ("GET", "/login") => handle_login(&request, config, store),
        ("GET", "/auth/callback") => Ok(callback_page()),
        ("POST", "/auth/callback/session") => {
            handle_callback_session(&request, config, store, auth_mini)
        }
        ("GET", "/auth/check") => handle_auth_check(&request, config, store, auth_mini),
        ("GET" | "POST", "/logout") => handle_logout(&request, config, store, auth_mini),
        _ => Ok(no_store(Response::text(404, "Not found"))),
    }
}

fn handle_login(
    request: &Request,
    config: &Config,
    store: &Store,
) -> Result<Response, Box<dyn std::error::Error>> {
    let original_uri = request.header("X-Original-URI");
    let Some(return_to) = normalize_return_to(
        request
            .query
            .get("return_to")
            .map(String::as_str)
            .or(original_uri),
        config,
    ) else {
        return Ok(no_store(Response::text(400, "Invalid return_to")));
    };
    let state = store.create_login_state(&return_to, config.login_state_ttl_seconds)?;
    Ok(
        Response::redirect(&build_auth_mini_login_url(&state.id, config)).with_cookie(
            serialize_signed_cookie(
                LOGIN_STATE_COOKIE,
                &state.id,
                config.login_state_ttl_seconds,
                config,
            ),
        ),
    )
}

fn handle_callback_session(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<Response, Box<dyn std::error::Error>> {
    let clear_state = clear_cookie(LOGIN_STATE_COOKIE, config);
    let Some(state_id) = read_signed_cookie(
        request.header("Cookie"),
        LOGIN_STATE_COOKIE,
        &config.cookie_secret,
    ) else {
        return Ok(no_store(Response::text(400, "Invalid login state")).with_cookie(clear_state));
    };

    let body: CallbackBody = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(_) => return Ok(no_store(Response::text(400, "Invalid JSON")).with_cookie(clear_state)),
    };
    let consumed_state = store.consume_login_state(&state_id)?;
    if consumed_state.is_none() || body.state.as_deref() != Some(&state_id) {
        return Ok(no_store(Response::text(400, "Invalid login state")).with_cookie(clear_state));
    }

    let Some(tokens) = body.into_tokens() else {
        return Ok(no_store(Response::text(400, "Invalid login callback")).with_cookie(clear_state));
    };

    let session = match create_session_from_tokens(tokens, config, store, auth_mini) {
        Ok(session) => session,
        Err(_) => {
            return Ok(
                no_store(Response::text(401, "Invalid auth-mini session")).with_cookie(clear_state)
            )
        }
    };

    let session_cookie = serialize_signed_cookie(
        SESSION_COOKIE,
        &session.id,
        config.session_ttl_seconds,
        config,
    );
    let response = no_store(match evaluate_session_policy(&session, config) {
        PolicyDecision::Allow => Response::json(
            200,
            json!({ "returnTo": consumed_state.unwrap().return_to }),
        ),
        PolicyDecision::Deny => Response::text(403, "Forbidden"),
    })
    .with_cookie(clear_state)
    .with_cookie(session_cookie);
    Ok(response)
}

fn create_session_from_tokens(
    tokens: TokenInput,
    config: &Config,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<GatewaySession, Box<dyn std::error::Error>> {
    let verified = auth_mini.verify_access_token(&tokens.access_token)?;
    if verified.auth_session_id != tokens.session_id {
        return Err("session id mismatch".into());
    }

    let me = auth_mini.fetch_me(&tokens.access_token)?;
    if me.user_id != verified.user_id {
        return Err("user mismatch".into());
    }

    Ok(store.create_session(NewSession {
        auth_session_id: tokens.session_id,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        user_id: verified.user_id,
        email: me.email,
        amr: verified.amr,
        access_expires_at: unix_to_text(verified.exp)?,
        session_ttl_seconds: config.session_ttl_seconds,
    })?)
}

fn handle_auth_check(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<Response, Box<dyn std::error::Error>> {
    let Some(session_id) = read_signed_cookie(
        request.header("Cookie"),
        SESSION_COOKIE,
        &config.cookie_secret,
    ) else {
        return Ok(no_store(Response::text(401, "Unauthenticated")));
    };
    let Some(mut session) = store.get_session(&session_id)? else {
        return Ok(no_store(Response::text(401, "Unauthenticated"))
            .with_cookie(clear_cookie(SESSION_COOKIE, config)));
    };

    if session_needs_refresh(&session, config) {
        match refresh_gateway_session(&session, store, auth_mini) {
            Ok(refreshed) => session = refreshed,
            Err(_) => {
                let current = store.get_session(&session.id)?;
                if let Some(current) = current.filter(|current| {
                    current.refresh_token != session.refresh_token
                        || current.access_expires_at > session.access_expires_at
                }) {
                    session = current;
                } else {
                    store.revoke_session(&session.id)?;
                    return Ok(no_store(Response::text(401, "Session refresh failed"))
                        .with_cookie(clear_cookie(SESSION_COOKIE, config)));
                }
            }
        }
    }

    if evaluate_session_policy(&session, config) == PolicyDecision::Deny {
        return Ok(no_store(Response::text(403, "Forbidden")));
    }

    if !identity_headers_are_safe(&session) {
        return Ok(no_store(Response::text(403, "Forbidden")));
    }

    let mut response = Response::empty(204).with_header("X-Auth-Mini-User-Id", &session.user_id);
    if let Some(email) = session.email.as_deref() {
        response = response.with_header("X-Auth-Mini-Email", email);
    }
    Ok(response)
}

fn refresh_gateway_session(
    session: &GatewaySession,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<GatewaySession, Box<dyn std::error::Error>> {
    let refreshed = auth_mini.refresh(&session.auth_session_id, &session.refresh_token)?;
    if refreshed.session_id != session.auth_session_id {
        return Err("refresh session id mismatch".into());
    }
    let verified = auth_mini.verify_access_token(&refreshed.access_token)?;
    if verified.auth_session_id != session.auth_session_id {
        return Err("refreshed token session id mismatch".into());
    }
    let me = auth_mini.fetch_me(&refreshed.access_token)?;
    if me.user_id != verified.user_id {
        return Err("refreshed user mismatch".into());
    }

    match store.update_after_refresh(
        session,
        &refreshed.access_token,
        &refreshed.refresh_token,
        &verified.user_id,
        me.email.as_deref(),
        &verified.amr,
        &unix_to_text(verified.exp)?,
    )? {
        RefreshUpdate::Updated(session) | RefreshUpdate::Current(session) => Ok(session),
        RefreshUpdate::MissingOrRevoked => Err("session changed during refresh".into()),
    }
}

fn handle_logout(
    request: &Request,
    config: &Config,
    store: &Store,
    auth_mini: &AuthMiniClient,
) -> Result<Response, Box<dyn std::error::Error>> {
    let session_id = read_signed_cookie(
        request.header("Cookie"),
        SESSION_COOKIE,
        &config.cookie_secret,
    );
    let session = match session_id.as_deref() {
        Some(id) => store.get_session(id)?,
        None => None,
    };
    if let Some(id) = session_id.as_deref() {
        store.revoke_session(id)?;
    }
    if let Some(session) = session {
        let _ = auth_mini.logout(&session.access_token);
    }

    let return_to = normalize_return_to(
        request
            .query
            .get("return_to")
            .map(String::as_str)
            .or(Some(config.logout_redirect.as_str())),
        config,
    )
    .unwrap_or_else(|| "/".to_string());
    Ok(Response::redirect(&return_to).with_cookie(clear_cookie(SESSION_COOKIE, config)))
}

fn callback_page() -> Response {
    Response::html(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Completing login</title></head>
<body>
<p>Completing login...</p>
<script>
(async () => {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const payload = Object.fromEntries(params.entries());
  window.history.replaceState(null, '', '/auth/callback');
  const response = await fetch('/auth/callback/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error('Login failed');
  const body = await response.json();
  window.location.assign(body.returnTo || '/');
})().catch(() => {
  document.body.textContent = 'Login failed. Please try again.';
});
</script>
</body>
</html>"#,
    )
}

pub fn normalize_return_to(input: Option<&str>, config: &Config) -> Option<String> {
    let raw = input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    if raw.contains('\n') || raw.contains('\r') {
        return None;
    }

    if raw.starts_with('/') && !raw.starts_with("//") {
        let parsed = Url::parse(&config.public_base_url).ok()?.join(raw).ok()?;
        return Some(format_path(&parsed));
    }

    let parsed = Url::parse(raw).ok()?;
    let public = Url::parse(&config.public_base_url).ok()?;
    if parsed.origin() != public.origin() {
        return None;
    }
    Some(format_path(&parsed))
}

pub fn build_auth_mini_login_url(state: &str, config: &Config) -> String {
    let redirect_uri = Url::parse(&config.public_base_url)
        .and_then(|base| base.join("/auth/callback"))
        .expect("validated public base url")
        .to_string();
    let params = form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", state)
        .finish();

    if let Some(login_url) = config.auth_mini_login_url.as_deref() {
        let separator = if login_url.contains('?') { '&' } else { '?' };
        return format!("{login_url}{separator}{params}");
    }

    format!(
        "{}/web/#/login?{}",
        config.auth_mini_public_base_url, params
    )
}

fn format_path(url: &Url) -> String {
    let mut out = url.path().to_string();
    if let Some(query) = url.query() {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

fn evaluate_session_policy(session: &GatewaySession, config: &Config) -> PolicyDecision {
    evaluate(
        Identity {
            user_id: &session.user_id,
            email: session.email.as_deref(),
        },
        config,
    )
}

fn identity_headers_are_safe(session: &GatewaySession) -> bool {
    is_safe_header_value(&session.user_id)
        && session
            .email
            .as_deref()
            .map(is_safe_header_value)
            .unwrap_or(true)
}

fn session_needs_refresh(session: &GatewaySession, config: &Config) -> bool {
    let Ok(access_expires_at) = chrono::DateTime::parse_from_rfc3339(&session.access_expires_at)
    else {
        return true;
    };
    access_expires_at.with_timezone(&Utc)
        <= Utc::now() + Duration::seconds(config.refresh_skew_seconds)
}

fn unix_to_text(exp: i64) -> Result<String, Box<dyn std::error::Error>> {
    Ok(Utc
        .timestamp_opt(exp, 0)
        .single()
        .ok_or("invalid exp")?
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn no_store(response: Response) -> Response {
    response.with_header("Cache-Control", "no-store")
}

#[derive(Deserialize)]
struct CallbackBody {
    access_token: Option<String>,
    refresh_token: Option<String>,
    session_id: Option<String>,
    token_type: Option<String>,
    state: Option<String>,
}

impl CallbackBody {
    fn into_tokens(self) -> Option<TokenInput> {
        if self.token_type.as_deref()? != "Bearer" {
            return None;
        }
        Some(TokenInput {
            access_token: self.access_token?,
            refresh_token: self.refresh_token?,
            session_id: self.session_id?,
        })
    }
}

struct TokenInput {
    session_id: String,
    access_token: String,
    refresh_token: String,
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use crate::config::SameSite;

    use super::*;

    #[test]
    fn normalizes_safe_return_targets() {
        let config = test_config();

        assert_eq!(
            normalize_return_to(Some("/app?x=1#frag"), &config),
            Some("/app?x=1#frag".to_string())
        );
        assert_eq!(
            normalize_return_to(Some("http://localhost:8080/app"), &config),
            Some("/app".to_string())
        );
        assert_eq!(normalize_return_to(None, &config), Some("/".to_string()));
    }

    #[test]
    fn rejects_unsafe_return_targets() {
        let config = test_config();

        assert_eq!(
            normalize_return_to(Some("https://evil.example/app"), &config),
            None
        );
        assert_eq!(
            normalize_return_to(Some("//evil.example/app"), &config),
            None
        );
        assert_eq!(
            normalize_return_to(Some("/app\r\nlocation: https://evil.example"), &config),
            None
        );
    }

    #[test]
    fn builds_auth_mini_login_url_with_redirect_and_state() {
        let config = test_config();
        let login_url = build_auth_mini_login_url("state-1", &config);

        assert!(login_url.starts_with("http://localhost:7777/web/#/login?"));
        assert!(login_url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback"));
        assert!(login_url.contains("state=state-1"));
    }

    fn test_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 3000,
            public_base_url: "http://localhost:8080".to_string(),
            auth_mini_issuer: "http://127.0.0.1:7777".to_string(),
            auth_mini_public_base_url: "http://localhost:7777".to_string(),
            auth_mini_login_url: None,
            database_path: PathBuf::from(":memory:"),
            cookie_secret: "test-cookie-secret-that-is-long-enough".to_string(),
            cookie_secure: false,
            cookie_same_site: SameSite::Lax,
            session_ttl_seconds: 3600,
            login_state_ttl_seconds: 300,
            refresh_skew_seconds: 60,
            allow_emails: HashSet::new(),
            allow_user_ids: HashSet::new(),
            logout_redirect: "/".to_string(),
        }
    }
}
