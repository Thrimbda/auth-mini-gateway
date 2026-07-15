use std::process::ExitCode;
use std::sync::Arc;

#[cfg(debug_assertions)]
use std::io::Write as _;

use auth_mini_gateway::auth_mini::AuthMiniClient;
use auth_mini_gateway::config::Config;
use auth_mini_gateway::db::Store;
#[cfg(debug_assertions)]
use auth_mini_gateway::exit::ListenerErrnoClass;
use auth_mini_gateway::exit::{emit_process_exit, install_sanitized_panic_hook, SanitizedExit};
use auth_mini_gateway::runtime_plan::{
    effective_soft_nofile, required_nofile, validate_nofile, NofileError, RuntimePlan,
};
use auth_mini_gateway::server::run_server;

fn main() -> ExitCode {
    install_sanitized_panic_hook();
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    #[cfg(debug_assertions)]
    if let Some(payload) = std::env::var_os("AMG_TEST_CAUGHT_PANIC") {
        let _ = std::panic::catch_unwind(|| std::panic::panic_any(payload));
        return ExitCode::SUCCESS;
    }

    #[cfg(debug_assertions)]
    if let Some(payload) = std::env::var_os("AMG_TEST_PANIC_WHILE_STDERR_LOCKED") {
        let stderr = std::io::stderr();
        let lock = stderr.lock();
        let panicker = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(|| std::panic::panic_any(payload));
        });
        let _ = panicker.join();
        drop(lock);
        return ExitCode::SUCCESS;
    }

    #[cfg(debug_assertions)]
    if std::env::var_os("AMG_TEST_PANIC_FROM_STDERR_WRITE").is_some() {
        struct PanicDisplay;

        impl std::fmt::Display for PanicDisplay {
            fn fmt(&self, _formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::panic::panic_any("stderr-writing-panic-payload-marker")
            }
        }

        let _ = std::panic::catch_unwind(|| {
            let stderr = std::io::stderr();
            let mut lock = stderr.lock();
            let _ = write!(&mut lock, "{PanicDisplay}");
        });
        return ExitCode::SUCCESS;
    }

    #[cfg(debug_assertions)]
    if let Some(payload) = std::env::var_os("AMG_TEST_PANIC_ON_START") {
        std::panic::panic_any(payload);
    }

    #[cfg(debug_assertions)]
    if std::env::var_os("AMG_TEST_LISTENER_FATAL").is_some() {
        emit_process_exit(&SanitizedExit::ListenerFatal {
            errno_class: ListenerErrnoClass::BadFd,
            errno_code: Some(libc::EBADF),
            prior_recoverable_failures: 37,
            suppressed_failures: 5,
        });
        return ExitCode::FAILURE;
    }

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_process_exit(&error);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), SanitizedExit> {
    let config = Config::from_env().map_err(|error| SanitizedExit::ConfigurationInvalid {
        class: error.class(),
    })?;
    let runtime_plan =
        RuntimePlan::from_config(&config).map_err(|_| SanitizedExit::RuntimeBlockingPlanInvalid)?;
    let required = required_nofile(&config).map_err(map_nofile_error)?;
    let effective = effective_soft_nofile().map_err(map_nofile_error)?;
    validate_nofile(required, effective).map_err(map_nofile_error)?;

    Store::initialize(&config.database_path)
        .map_err(|_| SanitizedExit::DatabaseInitializeFailed)?;

    tracing::info!(
        event = "runtime_blocking_plan",
        mode = if config.upstream.is_some() {
            "proxy"
        } else {
            "adapter"
        },
        auth_workers = runtime_plan.auth_workers,
        resolver_limit = runtime_plan.resolver_limit,
        blocking_margin = runtime_plan.blocking_margin,
        max_blocking_threads = runtime_plan.max_blocking_threads,
        required_nofile = required
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(runtime_plan.max_blocking_threads)
        .enable_all()
        .build()
        .map_err(|_| SanitizedExit::RuntimeBuildFailed)?;
    let auth_mini = Arc::new(AuthMiniClient::new(config.auth_mini_issuer.clone()));
    let terminal_result = runtime.block_on(run_server(config, auth_mini));
    runtime.shutdown_background();
    terminal_result
}

fn map_nofile_error(error: NofileError) -> SanitizedExit {
    match error {
        NofileError::BudgetOverflow => SanitizedExit::FdBudgetOverflow,
        NofileError::Unavailable => SanitizedExit::NofileUnavailable,
        NofileError::TooLow {
            required,
            effective,
        } => SanitizedExit::NofileTooLow {
            required,
            effective_soft: effective,
        },
    }
}
