use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::jwt::{verify_access_token, Jwks, VerifiedAccessToken};

#[derive(Clone, Debug)]
pub struct MeResponse {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TokenResponse {
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct AuthMiniClient {
    issuer: String,
    client: Client,
    jwks_cache: Mutex<Option<(Instant, Jwks)>>,
}

impl AuthMiniClient {
    pub fn new(issuer: String) -> Self {
        Self {
            issuer,
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds"),
            jwks_cache: Mutex::new(None),
        }
    }

    pub fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, Box<dyn std::error::Error>> {
        let jwks = self.jwks()?;
        verify_access_token(token, &jwks, &self.issuer)
    }

    pub fn fetch_me(&self, access_token: &str) -> Result<MeResponse, Box<dyn std::error::Error>> {
        let response: MeWire = self
            .client
            .get(self.url("/me"))
            .bearer_auth(access_token)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(MeResponse {
            user_id: response.user_id,
            email: response.email,
        })
    }

    pub fn refresh(
        &self,
        session_id: &str,
        refresh_token: &str,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let response: TokenWire = self
            .client
            .post(self.url("/session/refresh"))
            .json(&RefreshRequest {
                session_id,
                refresh_token,
            })
            .send()?
            .error_for_status()?
            .json()?;
        response.try_into()
    }

    pub fn logout(&self, access_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .post(self.url("/session/logout"))
            .bearer_auth(access_token)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    fn jwks(&self) -> Result<Jwks, Box<dyn std::error::Error>> {
        {
            let cache = self.jwks_cache.lock().map_err(|_| "jwks cache poisoned")?;
            if let Some((created, jwks)) = cache.as_ref() {
                if created.elapsed() < Duration::from_secs(300) {
                    return Ok(jwks.clone());
                }
            }
        }

        let jwks: Jwks = self
            .client
            .get(self.url("/jwks"))
            .send()?
            .error_for_status()?
            .json()?;
        *self.jwks_cache.lock().map_err(|_| "jwks cache poisoned")? =
            Some((Instant::now(), jwks.clone()));
        Ok(jwks)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }
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
struct TokenWire {
    session_id: String,
    access_token: String,
    token_type: Option<String>,
    refresh_token: String,
}

impl TryFrom<TokenWire> for TokenResponse {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: TokenWire) -> Result<Self, Self::Error> {
        if value.token_type.as_deref().unwrap_or("Bearer") != "Bearer" {
            return Err("invalid token_type".into());
        }
        Ok(Self {
            session_id: value.session_id,
            access_token: value.access_token,
            refresh_token: value.refresh_token,
        })
    }
}
