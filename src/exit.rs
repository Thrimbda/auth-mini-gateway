use std::sync::Once;

static PANIC_HOOK: Once = Once::new();
const SANITIZED_PANIC_EVENT: &[u8] = b"event=process_panic class=runtime_panic\n";

pub fn install_sanitized_panic_hook() {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {
            write_sanitized_panic_event_direct();
        }));
    });
}

#[cfg(unix)]
fn write_sanitized_panic_event_direct() {
    // SAFETY: the pointer and length refer to an immutable static byte string.
    // libc::write does not use Rust's stderr lock, allocate, format, or inspect
    // the panic payload. This is deliberately best effort.
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            SANITIZED_PANIC_EVENT.as_ptr().cast(),
            SANITIZED_PANIC_EVENT.len(),
        );
    }
}

#[cfg(not(unix))]
fn write_sanitized_panic_event_direct() {}

#[cfg(test)]
fn write_sanitized_panic_event(mut writer: impl std::io::Write) -> std::io::Result<()> {
    writer.write_all(SANITIZED_PANIC_EVENT)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerErrnoClass {
    BadFd,
    Fault,
    Invalid,
    NotSocket,
    Unknown,
}

impl ListenerErrnoClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadFd => "bad_fd",
            Self::Fault => "fault",
            Self::Invalid => "invalid",
            Self::NotSocket => "not_socket",
            Self::Unknown => "unknown",
        }
    }
}

/// Process-level failures contain only allowlisted classes and numeric values.
/// In particular, this type never retains an `io::Error` or another source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanitizedExit {
    ConfigurationInvalid {
        class: &'static str,
    },
    FdBudgetOverflow,
    NofileUnavailable,
    NofileTooLow {
        required: u64,
        effective_soft: u64,
    },
    RuntimeBlockingPlanInvalid,
    RuntimeBuildFailed,
    DatabaseInitializeFailed,
    ListenerBindFailed,
    ProxyInitializeFailed,
    PublicBaseInvalid,
    RuntimeInvariant {
        class: &'static str,
    },
    ListenerFatal {
        errno_class: ListenerErrnoClass,
        errno_code: Option<i32>,
        prior_recoverable_failures: u64,
        suppressed_failures: u64,
    },
}

pub fn emit_process_exit(error: &SanitizedExit) {
    match error {
        SanitizedExit::ConfigurationInvalid { class } => {
            tracing::error!(event = "process_exit", class = *class)
        }
        SanitizedExit::FdBudgetOverflow => {
            tracing::error!(event = "process_exit", class = "fd_budget_overflow")
        }
        SanitizedExit::NofileUnavailable => {
            tracing::error!(event = "process_exit", class = "nofile_unavailable")
        }
        SanitizedExit::NofileTooLow {
            required,
            effective_soft,
        } => tracing::error!(
            event = "process_exit",
            class = "nofile_too_low",
            required = *required,
            effective_soft = *effective_soft
        ),
        SanitizedExit::RuntimeBlockingPlanInvalid => tracing::error!(
            event = "process_exit",
            class = "runtime_blocking_plan_invalid"
        ),
        SanitizedExit::RuntimeBuildFailed => {
            tracing::error!(event = "process_exit", class = "runtime_build_failed")
        }
        SanitizedExit::DatabaseInitializeFailed => {
            tracing::error!(event = "process_exit", class = "database_initialize_failed")
        }
        SanitizedExit::ListenerBindFailed => {
            tracing::error!(event = "process_exit", class = "listener_bind_failed")
        }
        SanitizedExit::ProxyInitializeFailed => {
            tracing::error!(event = "process_exit", class = "proxy_initialize_failed")
        }
        SanitizedExit::PublicBaseInvalid => {
            tracing::error!(event = "process_exit", class = "public_base_invalid")
        }
        SanitizedExit::RuntimeInvariant { class } => {
            tracing::error!(event = "process_exit", class = *class)
        }
        SanitizedExit::ListenerFatal {
            errno_class,
            errno_code,
            prior_recoverable_failures,
            suppressed_failures,
        } => tracing::error!(
            event = "process_exit",
            class = "listener_fatal",
            errno_class = errno_class.as_str(),
            errno_present = errno_code.is_some(),
            errno_code = errno_code.unwrap_or(-1),
            prior_recoverable_failures = *prior_recoverable_failures,
            suppressed_failures = *suppressed_failures
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct TestWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for TestWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn listener_fatal_emits_one_allowlisted_non_source_event() {
        const RAW_SOURCE_MARKER: &str = "raw-os-source-marker-must-not-appear";
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer_buffer = Arc::clone(&buffer);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || TestWriter(Arc::clone(&writer_buffer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            emit_process_exit(&SanitizedExit::ListenerFatal {
                errno_class: ListenerErrnoClass::BadFd,
                errno_code: Some(libc::EBADF),
                prior_recoverable_failures: 37,
                suppressed_failures: 5,
            });
        });
        let output = String::from_utf8(buffer.lock().expect("log output").clone())
            .expect("UTF-8 structured event");
        assert_eq!(output.matches("process_exit").count(), 1);
        assert!(output.contains("listener_fatal"));
        assert!(output.contains("bad_fd"));
        assert!(output.contains("37"));
        assert!(output.contains("5"));
        assert!(!output.contains(RAW_SOURCE_MARKER));
    }

    #[test]
    fn panic_event_writer_never_accepts_payload_or_location_data() {
        let mut output = Vec::new();
        write_sanitized_panic_event(&mut output).expect("panic event");
        let output = String::from_utf8(output).expect("UTF-8 panic event");
        assert_eq!(output, "event=process_panic class=runtime_panic\n");
        for forbidden in ["payload-marker", "src/", "panicked at", "session", "token"] {
            assert!(!output.contains(forbidden));
        }
    }
}
