use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use reqwest::redirect;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::jwt::{verify_access_token, Jwks, VerifiedAccessToken};
use crate::util::{Clock, SystemClock};

const MAX_AUTH_MINI_BODY: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthMiniOperationError;

impl std::fmt::Display for AuthMiniOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("auth-mini operation failed")
    }
}

impl std::error::Error for AuthMiniOperationError {}

#[derive(Clone, PartialEq, Eq)]
pub struct MeResponse {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone)]
pub struct TokenResponse {
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshRejected {
    Invalidated,
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporaryClass {
    Timeout,
    Transport,
    RateLimited,
    Upstream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndeterminateClass {
    UnexpectedStatus,
    InvalidErrorBody,
    InvalidSuccessBody,
    TokenVerification,
    IdentityMismatch,
    ContractDrift,
    Persistence,
    LeaderAborted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshError {
    Rejected(RefreshRejected),
    Temporary(TemporaryClass),
    Indeterminate(IndeterminateClass),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityUnavailable {
    Temporary(TemporaryClass),
    HttpStatus(u16),
    InvalidBody,
    IdentityMismatch,
    ContractDrift,
}

#[derive(Clone, PartialEq, Eq)]
pub enum IdentityFetchOutcome {
    Fresh(MeResponse),
    Unavailable(IdentityUnavailable),
}

pub trait AuthMini: Send + Sync {
    fn verify_initial_access(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, AuthMiniOperationError>;
    fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError>;
    fn verify_refreshed_access(
        &self,
        token: &str,
        jwks: &Jwks,
    ) -> Result<VerifiedAccessToken, RefreshError>;
    fn fetch_identity(&self, access_token: &str) -> IdentityFetchOutcome;
    fn refresh(&self, session_id: &str, refresh_token: &str)
        -> Result<TokenResponse, RefreshError>;
    fn logout(&self, access_token: &str) -> Result<(), AuthMiniOperationError>;
}

pub struct AuthMiniClient {
    issuer: String,
    client: Client,
    clock: Arc<dyn Clock>,
    jwks_cache: Mutex<Option<(Instant, Jwks)>>,
}

impl AuthMiniClient {
    pub fn new(issuer: String) -> Self {
        Self::with_clock(issuer, Arc::new(SystemClock))
    }

    pub fn with_clock(issuer: String, clock: Arc<dyn Clock>) -> Self {
        Self {
            issuer,
            client: Client::builder()
                .redirect(redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
            clock,
            jwks_cache: Mutex::new(None),
        }
    }

    fn jwks(&self) -> Result<Jwks, RefreshError> {
        {
            let cache = self
                .jwks_cache
                .lock()
                .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::ContractDrift))?;
            if let Some((created, jwks)) = cache.as_ref() {
                if created.elapsed() < Duration::from_secs(300) {
                    return Ok(jwks.clone());
                }
            }
        }

        let response = self
            .client
            .get(self.url("/jwks"))
            .send()
            .map_err(classify_transport)?;
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(RefreshError::Temporary(
                if status == StatusCode::TOO_MANY_REQUESTS {
                    TemporaryClass::RateLimited
                } else {
                    TemporaryClass::Upstream
                },
            ));
        }
        if status != StatusCode::OK {
            return Err(RefreshError::Indeterminate(
                IndeterminateClass::UnexpectedStatus,
            ));
        }
        let body = bounded_body(response)
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::ContractDrift))?;
        let jwks: Jwks = serde_json::from_slice(&body)
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::ContractDrift))?;
        *self
            .jwks_cache
            .lock()
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::ContractDrift))? =
            Some((Instant::now(), jwks.clone()));
        Ok(jwks)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }
}

impl AuthMini for AuthMiniClient {
    fn verify_initial_access(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, AuthMiniOperationError> {
        let jwks = self.jwks().map_err(|_| AuthMiniOperationError)?;
        verify_access_token(token, &jwks, &self.issuer, self.clock.now().timestamp())
            .map_err(|_| AuthMiniOperationError)
    }

    fn prepare_refresh_verifier(&self) -> Result<Jwks, RefreshError> {
        self.jwks()
    }

    fn verify_refreshed_access(
        &self,
        token: &str,
        jwks: &Jwks,
    ) -> Result<VerifiedAccessToken, RefreshError> {
        verify_access_token(token, jwks, &self.issuer, self.clock.now().timestamp())
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::TokenVerification))
    }

    fn fetch_identity(&self, access_token: &str) -> IdentityFetchOutcome {
        let response = match self
            .client
            .get(self.url("/me"))
            .bearer_auth(access_token)
            .send()
        {
            Ok(response) => response,
            Err(error) => {
                let class = if error.is_timeout() {
                    TemporaryClass::Timeout
                } else {
                    TemporaryClass::Transport
                };
                return IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(class));
            }
        };
        if response.status() != StatusCode::OK {
            let status = response.status();
            if status == StatusCode::REQUEST_TIMEOUT {
                return IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(
                    TemporaryClass::Timeout,
                ));
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(
                    TemporaryClass::RateLimited,
                ));
            }
            if status.is_server_error() {
                return IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(
                    TemporaryClass::Upstream,
                ));
            }
            return IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(
                status.as_u16(),
            ));
        }
        let body = match bounded_body(response) {
            Ok(body) => body,
            Err(()) => return IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody),
        };
        let response: MeWire = match serde_json::from_slice(&body) {
            Ok(response) => response,
            Err(_) => return IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody),
        };
        if response.user_id.is_empty() {
            return IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody);
        }
        IdentityFetchOutcome::Fresh(MeResponse {
            user_id: response.user_id,
            email: response.email,
        })
    }

    fn refresh(
        &self,
        session_id: &str,
        refresh_token: &str,
    ) -> Result<TokenResponse, RefreshError> {
        let response = self
            .client
            .post(self.url("/session/refresh"))
            .json(&RefreshRequest {
                session_id,
                refresh_token,
            })
            .send()
            .map_err(classify_transport)?;
        let status = response.status();
        if status == StatusCode::REQUEST_TIMEOUT {
            return Err(RefreshError::Temporary(TemporaryClass::Timeout));
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(RefreshError::Temporary(TemporaryClass::RateLimited));
        }
        if status.is_server_error() {
            return Err(RefreshError::Temporary(TemporaryClass::Upstream));
        }
        if status == StatusCode::UNAUTHORIZED {
            let body = bounded_body(response)
                .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::InvalidErrorBody))?;
            let wire: ErrorWire = serde_json::from_slice(&body)
                .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::InvalidErrorBody))?;
            return match wire.error.as_str() {
                "session_invalidated" => Err(RefreshError::Rejected(RefreshRejected::Invalidated)),
                "session_superseded" => Err(RefreshError::Rejected(RefreshRejected::Superseded)),
                _ => Err(RefreshError::Indeterminate(
                    IndeterminateClass::InvalidErrorBody,
                )),
            };
        }
        if status != StatusCode::OK {
            return Err(RefreshError::Indeterminate(
                IndeterminateClass::UnexpectedStatus,
            ));
        }
        let body = bounded_body(response)
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::InvalidSuccessBody))?;
        let response: TokenWire = serde_json::from_slice(&body)
            .map_err(|_| RefreshError::Indeterminate(IndeterminateClass::InvalidSuccessBody))?;
        response.try_into()
    }

    fn logout(&self, access_token: &str) -> Result<(), AuthMiniOperationError> {
        self.client
            .post(self.url("/session/logout"))
            .bearer_auth(access_token)
            .send()
            .map_err(|_| AuthMiniOperationError)?
            .error_for_status()
            .map_err(|_| AuthMiniOperationError)?;
        Ok(())
    }
}

fn classify_transport(error: reqwest::Error) -> RefreshError {
    RefreshError::Temporary(if error.is_timeout() {
        TemporaryClass::Timeout
    } else {
        TemporaryClass::Transport
    })
}

fn bounded_body(response: Response) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_MINI_BODY)
    {
        return Err(());
    }
    let mut body = Vec::new();
    response
        .take(MAX_AUTH_MINI_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|_| ())?;
    if body.len() as u64 > MAX_AUTH_MINI_BODY {
        return Err(());
    }
    Ok(body)
}

#[derive(Deserialize)]
struct MeWire {
    user_id: String,
    email: Option<String>,
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    session_id: &'a str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorWire {
    error: String,
}

#[derive(Deserialize)]
struct TokenWire {
    session_id: String,
    access_token: String,
    token_type: Option<String>,
    refresh_token: String,
}

impl TryFrom<TokenWire> for TokenResponse {
    type Error = RefreshError;

    fn try_from(value: TokenWire) -> Result<Self, Self::Error> {
        if value.token_type.as_deref().unwrap_or("Bearer") != "Bearer"
            || value.session_id.is_empty()
            || value.access_token.is_empty()
            || value.refresh_token.is_empty()
        {
            return Err(RefreshError::Indeterminate(
                IndeterminateClass::InvalidSuccessBody,
            ));
        }
        Ok(Self {
            session_id: value.session_id,
            access_token: value.access_token,
            refresh_token: value.refresh_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::*;

    #[test]
    fn token_wire_rejects_non_bearer_and_empty_values() {
        let wire = TokenWire {
            session_id: String::new(),
            access_token: String::new(),
            token_type: Some("MAC".to_string()),
            refresh_token: String::new(),
        };
        assert!(matches!(
            TokenResponse::try_from(wire),
            Err(RefreshError::Indeterminate(
                IndeterminateClass::InvalidSuccessBody
            ))
        ));
    }

    #[test]
    fn identity_unavailable_has_no_rejected_variant() {
        let outcome = IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(401));
        assert!(matches!(outcome, IdentityFetchOutcome::Unavailable(_)));
    }

    #[test]
    fn refresh_wire_classifies_only_exact_rejections() {
        let invalidated = refresh_against("401 Unauthorized", r#"{"error":"session_invalidated"}"#);
        assert!(matches!(
            invalidated,
            Err(RefreshError::Rejected(RefreshRejected::Invalidated))
        ));

        let superseded = refresh_against("401 Unauthorized", r#"{"error":"session_superseded"}"#);
        assert!(matches!(
            superseded,
            Err(RefreshError::Rejected(RefreshRejected::Superseded))
        ));

        let unknown = refresh_against("401 Unauthorized", r#"{"error":"invalid_access_token"}"#);
        assert!(matches!(
            unknown,
            Err(RefreshError::Indeterminate(
                IndeterminateClass::InvalidErrorBody
            ))
        ));

        let extra_field = refresh_against(
            "401 Unauthorized",
            r#"{"error":"session_invalidated","detail":"drift"}"#,
        );
        assert!(matches!(
            extra_field,
            Err(RefreshError::Indeterminate(
                IndeterminateClass::InvalidErrorBody
            ))
        ));
    }

    #[test]
    fn refresh_wire_preserves_temporary_and_indeterminate_classes() {
        assert!(matches!(
            refresh_against("429 Too Many Requests", ""),
            Err(RefreshError::Temporary(TemporaryClass::RateLimited))
        ));
        assert!(matches!(
            refresh_against("503 Service Unavailable", ""),
            Err(RefreshError::Temporary(TemporaryClass::Upstream))
        ));
        assert!(matches!(
            refresh_against("400 Bad Request", r#"{"error":"bad_request"}"#),
            Err(RefreshError::Indeterminate(
                IndeterminateClass::UnexpectedStatus
            ))
        ));
        assert!(matches!(
            refresh_against("200 OK", "not-json"),
            Err(RefreshError::Indeterminate(
                IndeterminateClass::InvalidSuccessBody
            ))
        ));
    }

    #[test]
    fn redirect_responses_are_not_followed_or_replayed() {
        for status in [
            "302 Found",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let (issuer, source_hits, target, server) = redirect_server(status);
            let client = AuthMiniClient::new(issuer);
            assert!(matches!(
                client.refresh("fixture-session", "fixture-refresh"),
                Err(RefreshError::Indeterminate(
                    IndeterminateClass::UnexpectedStatus
                ))
            ));
            server.join().expect("redirect source");
            assert_eq!(source_hits.load(Ordering::SeqCst), 1);
            assert_target_not_hit(&target);
        }

        let (issuer, source_hits, target, server) = redirect_server("302 Found");
        let client = AuthMiniClient::new(issuer);
        assert!(matches!(
            client.fetch_identity("fixture-access"),
            IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(302))
        ));
        server.join().expect("redirect source");
        assert_eq!(source_hits.load(Ordering::SeqCst), 1);
        assert_target_not_hit(&target);

        let (issuer, source_hits, target, server) = redirect_server("302 Found");
        let client = AuthMiniClient::new(issuer);
        assert!(matches!(
            client.prepare_refresh_verifier(),
            Err(RefreshError::Indeterminate(
                IndeterminateClass::UnexpectedStatus
            ))
        ));
        server.join().expect("redirect source");
        assert_eq!(source_hits.load(Ordering::SeqCst), 1);
        assert_target_not_hit(&target);
    }

    #[test]
    fn valid_looking_non_200_responses_never_succeed() {
        let token_body = r#"{"session_id":"fixture-session","access_token":"fixture-access","refresh_token":"fixture-refresh","token_type":"Bearer"}"#;
        for status in ["201 Created", "206 Partial Content"] {
            assert!(matches!(
                refresh_against(status, token_body),
                Err(RefreshError::Indeterminate(
                    IndeterminateClass::UnexpectedStatus
                ))
            ));
            assert!(matches!(
                identity_against(status, r#"{"user_id":"fixture-user","email":null}"#),
                IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(201 | 206))
            ));
            assert!(matches!(
                jwks_against(status, r#"{"keys":[]}"#),
                Err(RefreshError::Indeterminate(
                    IndeterminateClass::UnexpectedStatus
                ))
            ));
        }
    }

    #[test]
    fn identity_wire_maps_failures_without_a_rejection_path() {
        assert!(matches!(
            identity_against("404 Not Found", r#"{"error":"not_found"}"#),
            IdentityFetchOutcome::Unavailable(IdentityUnavailable::HttpStatus(404))
        ));
        assert!(matches!(
            identity_against("503 Service Unavailable", ""),
            IdentityFetchOutcome::Unavailable(IdentityUnavailable::Temporary(
                TemporaryClass::Upstream
            ))
        ));
        assert!(matches!(
            identity_against("200 OK", "not-json"),
            IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody)
        ));
        assert!(matches!(
            identity_against("200 OK", r#"{"email":null}"#),
            IdentityFetchOutcome::Unavailable(IdentityUnavailable::InvalidBody)
        ));
    }

    fn refresh_against(
        status: &'static str,
        body: &'static str,
    ) -> Result<TokenResponse, RefreshError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        });
        let client = AuthMiniClient::new(format!("http://{address}"));
        let result = client.refresh("fixture-session", "fixture-refresh");
        server.join().expect("server");
        result
    }

    fn identity_against(status: &'static str, body: &'static str) -> IdentityFetchOutcome {
        let (issuer, server) = response_server(status, body, None);
        let result = AuthMiniClient::new(issuer).fetch_identity("fixture-access");
        server.join().expect("server");
        result
    }

    fn jwks_against(status: &'static str, body: &'static str) -> Result<Jwks, RefreshError> {
        let (issuer, server) = response_server(status, body, None);
        let result = AuthMiniClient::new(issuer).prepare_refresh_verifier();
        server.join().expect("server");
        result
    }

    fn response_server(
        status: &'static str,
        body: &'static str,
        location: Option<String>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let location = location
                .as_deref()
                .map(|value| format!("Location: {value}\r\n"))
                .unwrap_or_default();
            write!(
                stream,
                "HTTP/1.1 {status}\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
        });
        (format!("http://{address}"), server)
    }

    fn redirect_server(
        status: &'static str,
    ) -> (
        String,
        Arc<AtomicUsize>,
        TcpListener,
        thread::JoinHandle<()>,
    ) {
        let target = TcpListener::bind("127.0.0.1:0").expect("target listener");
        target.set_nonblocking(true).expect("nonblocking target");
        let location = format!(
            "http://{}/must-not-receive-credentials",
            target.local_addr().expect("target address")
        );
        let source_hits = Arc::new(AtomicUsize::new(0));
        let source_hits_for_server = Arc::clone(&source_hits);
        let listener = TcpListener::bind("127.0.0.1:0").expect("source listener");
        let address = listener.local_addr().expect("source address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept source");
            source_hits_for_server.fetch_add(1, Ordering::SeqCst);
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("redirect response");
        });
        (format!("http://{address}"), source_hits, target, server)
    }

    fn assert_target_not_hit(target: &TcpListener) {
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
