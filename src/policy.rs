use crate::config::Config;

pub struct Identity<'a> {
    pub user_id: &'a str,
    pub email: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

pub fn evaluate(identity: Identity<'_>, config: &Config) -> PolicyDecision {
    let email_allowed = identity
        .email
        .map(|email| config.allow_emails.contains(&email.to_ascii_lowercase()))
        .unwrap_or(false);
    let user_allowed = config.allow_user_ids.contains(identity.user_id);

    if !email_allowed && !user_allowed {
        return PolicyDecision::Deny;
    }

    PolicyDecision::Allow
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;

    use crate::config::SameSite;

    use super::*;

    #[test]
    fn denies_unknown_users_by_default() {
        let config = test_config(["allowed@example.com"], []);

        assert_eq!(
            evaluate(
                Identity {
                    user_id: "user-1",
                    email: Some("other@example.com"),
                },
                &config,
            ),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn allows_any_authentication_method_for_allowlisted_identity() {
        let config = test_config(["allowed@example.com"], ["allowed-user"]);

        assert_eq!(
            evaluate(
                Identity {
                    user_id: "user-1",
                    email: Some("allowed@example.com"),
                },
                &config,
            ),
            PolicyDecision::Allow
        );
        assert_eq!(
            evaluate(
                Identity {
                    user_id: "allowed-user",
                    email: None,
                },
                &config,
            ),
            PolicyDecision::Allow
        );
    }

    fn test_config<const E: usize, const U: usize>(
        emails: [&str; E],
        user_ids: [&str; U],
    ) -> Config {
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
            session_absolute_ttl_seconds: 7200,
            session_touch_interval_seconds: 600,
            login_state_ttl_seconds: 600,
            refresh_skew_seconds: 60,
            allow_emails: emails
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect::<HashSet<_>>(),
            allow_user_ids: user_ids
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>(),
            logout_redirect: "/".to_string(),
            upstream: None,
        }
    }
}
