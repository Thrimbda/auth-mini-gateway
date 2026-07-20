use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

pub const LEGACY_ROLE_FAILURE_SCHEMA: &str = "amg-http2-perf/role-failure/v1";
pub const ROLE_FAILURE_SCHEMA: &str = "amg-http2-perf/role-failure/v2";

/// Fixed, secret-free lifecycle location for an authenticated role failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleErrorStage {
    Startup,
    Authenticate,
    Prepare,
    Proof,
    Materialize,
    Measure,
    Drain,
    Exit,
}

impl RoleErrorStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Authenticate => "authenticate",
            Self::Prepare => "prepare",
            Self::Proof => "proof",
            Self::Materialize => "materialize",
            Self::Measure => "measure",
            Self::Drain => "drain",
            Self::Exit => "exit",
        }
    }
}

/// Fixed, bounded classification for an authenticated role failure.  Raw
/// error text is deliberately excluded from the control and evidence schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoleErrorCode {
    Authentication,
    ControlIo,
    ControlProtocol,
    InvalidCommand,
    InvalidConfiguration,
    ProcessIdentity,
    PrepareFailed,
    ConnectFailed,
    RequestWriteFailed,
    ResponseHeadReadFailed,
    ResponseHeadInvalid,
    ResponseBodyReadFailed,
    ResponseBodyInvalid,
    ConnectionCloseMissing,
    PeerEofMissing,
    PayloadMismatch,
    LedgerMismatch,
    MaterializeFailed,
    MeasureFailed,
    DrainFailed,
    SamplerFailed,
    Timeout,
    Panic,
    ExitFailed,
    Internal,
}

impl RoleErrorCode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::ControlIo => "control-io",
            Self::ControlProtocol => "control-protocol",
            Self::InvalidCommand => "invalid-command",
            Self::InvalidConfiguration => "invalid-configuration",
            Self::ProcessIdentity => "process-identity",
            Self::PrepareFailed => "prepare-failed",
            Self::ConnectFailed => "connect-failed",
            Self::RequestWriteFailed => "request-write-failed",
            Self::ResponseHeadReadFailed => "response-head-read-failed",
            Self::ResponseHeadInvalid => "response-head-invalid",
            Self::ResponseBodyReadFailed => "response-body-read-failed",
            Self::ResponseBodyInvalid => "response-body-invalid",
            Self::ConnectionCloseMissing => "connection-close-missing",
            Self::PeerEofMissing => "peer-eof-missing",
            Self::PayloadMismatch => "payload-mismatch",
            Self::LedgerMismatch => "ledger-mismatch",
            Self::MaterializeFailed => "materialize-failed",
            Self::MeasureFailed => "measure-failed",
            Self::DrainFailed => "drain-failed",
            Self::SamplerFailed => "sampler-failed",
            Self::Timeout => "timeout",
            Self::Panic => "panic",
            Self::ExitFailed => "exit-failed",
            Self::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleDiagnostic {
    pub stage: RoleErrorStage,
    pub code: RoleErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeRoleAttempt {
    pub starts: u64,
    pub successes: u64,
    pub failures: u64,
    pub reconnects: u64,
    pub retries: u64,
}

/// Secret-free evidence retained when a spawned benchmark role terminates or
/// loses its authenticated control capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeRoleFailure {
    pub schema: String,
    pub role: String,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub parent_pid: u32,
    pub class: String,
    pub terminal_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<RoleErrorStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<RoleErrorCode>,
    pub detail_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<SafeRoleAttempt>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub core_dumped: bool,
}

impl SafeRoleFailure {
    pub fn validate(&self) -> Result<()> {
        let versioned_diagnostic = match self.schema.as_str() {
            ROLE_FAILURE_SCHEMA => self.stage.is_some() && self.code.is_some(),
            LEGACY_ROLE_FAILURE_SCHEMA => self.stage.is_none() && self.code.is_none(),
            _ => false,
        };
        if !versioned_diagnostic
            || self.role.is_empty()
            || self.role.len() > 32
            || self.pid == 0
            || self.start_time_ticks == 0
            || self.parent_pid == 0
            || self.class.is_empty()
            || self.class.len() > 64
            || self
                .terminal_class
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 64)
            || self.detail_sha256.len() != 64
            || !self
                .detail_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.detail_sha256.bytes().all(|byte| byte == b'0')
            || self.attempt.is_some_and(|attempt| {
                attempt
                    .successes
                    .checked_add(attempt.failures)
                    .is_none_or(|total| total != attempt.starts)
                    || attempt.reconnects > attempt.starts
                    || attempt.retries > attempt.starts
            })
            || self.exit_code.is_some() == self.signal.is_some()
        {
            return Err(Error::new("retained role failure evidence is invalid"));
        }
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> String {
        let status = match (self.exit_code, self.signal) {
            (Some(code), None) => format!("exit-code={code}"),
            (None, Some(signal)) => format!("signal={signal}"),
            (None, None) => "exit-status=unavailable".to_owned(),
            (Some(_), Some(_)) => "exit-status=invalid".to_owned(),
        };
        let terminal = self
            .terminal_class
            .as_deref()
            .map_or_else(|| "none".to_owned(), str::to_owned);
        let stage = self.stage.map_or("legacy", RoleErrorStage::label);
        let code = self.code.map_or("legacy", RoleErrorCode::label);
        format!(
            "role-failure class={} role={} pid={} start={} ppid={} status={} core={} terminal={} stage={} code={} detail-sha256={}",
            self.class,
            self.role,
            self.pid,
            self.start_time_ticks,
            self.parent_pid,
            status,
            self.core_dumped,
            terminal,
            stage,
            code,
            self.detail_sha256
        )
    }
}

/// Package-local fail-closed error.
#[derive(Debug)]
pub struct Error {
    message: String,
    role_failure: Option<Box<SafeRoleFailure>>,
    role_diagnostic: Option<RoleDiagnostic>,
    role_code: Option<RoleErrorCode>,
}

impl Error {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            role_failure: None,
            role_diagnostic: None,
            role_code: None,
        }
    }

    #[must_use]
    pub fn context(self, context: impl AsRef<str>) -> Self {
        Self {
            message: format!("{}: {}", context.as_ref(), self.message),
            role_failure: self.role_failure,
            role_diagnostic: self.role_diagnostic,
            role_code: self.role_code,
        }
    }

    #[must_use]
    pub fn with_role_failure(mut self, role_failure: SafeRoleFailure) -> Self {
        self.role_failure = Some(Box::new(role_failure));
        self
    }

    #[must_use]
    pub fn with_role_diagnostic(mut self, stage: RoleErrorStage, code: RoleErrorCode) -> Self {
        self.role_diagnostic = Some(RoleDiagnostic { stage, code });
        self.role_code = Some(code);
        self
    }

    #[must_use]
    pub fn with_role_diagnostic_fallback(
        mut self,
        stage: RoleErrorStage,
        code: RoleErrorCode,
    ) -> Self {
        if self.role_diagnostic.is_none() {
            self.role_diagnostic = Some(RoleDiagnostic { stage, code });
        }
        if self.role_code.is_none() {
            self.role_code = Some(code);
        }
        self
    }

    #[must_use]
    pub fn with_role_code(mut self, code: RoleErrorCode) -> Self {
        self.role_code = Some(code);
        self
    }

    #[must_use]
    pub fn role_failure(&self) -> Option<&SafeRoleFailure> {
        self.role_failure.as_deref()
    }

    #[must_use]
    pub const fn role_diagnostic(&self) -> Option<RoleDiagnostic> {
        self.role_diagnostic
    }

    #[must_use]
    pub const fn role_code(&self) -> Option<RoleErrorCode> {
        self.role_code
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait ResultContext<T> {
    fn context(self, context: impl AsRef<str>) -> Result<T>;
}

impl<T, E> ResultContext<T> for std::result::Result<T, E>
where
    E: Display,
{
    fn context(self, context: impl AsRef<str>) -> Result<T> {
        self.map_err(|error| Error::new(format!("{}: {error}", context.as_ref())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(schema: &str) -> SafeRoleFailure {
        SafeRoleFailure {
            schema: schema.to_owned(),
            role: "load".to_owned(),
            pid: 11,
            start_time_ticks: 12,
            parent_pid: 10,
            class: "authenticated-terminal-error".to_owned(),
            terminal_class: Some("command".to_owned()),
            stage: None,
            code: None,
            detail_sha256: "ce137486024aac087e3a522cdb31433c73e92ec473be89ce092e3bafcf572ce5"
                .to_owned(),
            attempt: None,
            exit_code: Some(2),
            signal: None,
            core_dumped: false,
        }
    }

    #[test]
    fn role_failure_v2_requires_allowlisted_stage_and_code_while_v1_remains_verifiable() {
        let legacy = failure(LEGACY_ROLE_FAILURE_SCHEMA);
        legacy.validate().expect("sealed v1 evidence remains valid");

        let mut current = failure(ROLE_FAILURE_SCHEMA);
        assert!(current.validate().is_err());
        current.stage = Some(RoleErrorStage::Proof);
        current.code = Some(RoleErrorCode::ResponseHeadInvalid);
        current.validate().expect("v2 stage/code evidence");
        let bytes = serde_json::to_vec(&current).expect("role failure JSON");
        let text = String::from_utf8(bytes).expect("role failure UTF-8");
        assert!(text.contains("\"stage\":\"proof\""));
        assert!(text.contains("\"code\":\"response-head-invalid\""));
        assert!(!text.contains("fresh H1 response lacks exact Content-Length"));
    }
}
