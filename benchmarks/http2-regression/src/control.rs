//! Versioned, length-framed loopback control protocol for benchmark roles.

use crate::json;
use crate::linux::ProcessIdentity;
use crate::schema::{Arm, Cell, Workload};
use crate::topology::Protocol;
use crate::{Error, Result, ResultContext};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const CONTROL_SCHEMA: &str = "amg-http2-perf/control/v1";
pub const CONTROL_MAX_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Orchestrator,
    Fixture,
    Load,
    Sampler,
    Gateway,
}

impl Role {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Orchestrator => "orchestrator",
            Self::Fixture => "fixture",
            Self::Load => "load",
            Self::Sampler => "sampler",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlContext {
    pub run_id: String,
    pub cell: Cell,
    pub arm: Arm,
    pub block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    pub schema: String,
    pub run_id: String,
    pub cell: Cell,
    pub arm: Arm,
    pub block: u64,
    pub sequence: u64,
    pub body: ControlBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ControlBody {
    Hello {
        role: Role,
        identity: ProcessIdentity,
    },
    Ready {
        role: Role,
        data_address: Option<String>,
        tripwire_address: Option<String>,
    },
    ConfigureFixture {
        target: LoadTarget,
        workload: Workload,
        expected_protocol: Protocol,
        corpus_sha256: String,
    },
    FixtureConfigured,
    PrepareLoad {
        target: LoadTarget,
        workload: Workload,
        protocol: Protocol,
        gateway_address: Option<String>,
        fixture_address: String,
        cookie_header: Option<String>,
        warmup_operations: u64,
        websocket_settle: bool,
    },
    Prepared {
        proof: LoadProof,
    },
    Measure {
        phase: u16,
        operations: u64,
    },
    MeasureCount {
        phase: u16,
        operations: u64,
        retain_latencies: bool,
    },
    MeasureDuration {
        phase: u16,
        duration_ns: u64,
        retain_latencies: bool,
    },
    Measured {
        result: LoadResult,
    },
    FixtureSnapshot,
    FixtureObserved {
        result: FixtureResult,
    },
    RegisterProcesses {
        processes: Vec<ObservedProcess>,
    },
    ProcessesRegistered,
    Inventory,
    InventoryObserved {
        inventories: Vec<ThreadInventory>,
    },
    WaitWebsocketRetirement {
        gateway_pre_auth_tids: Vec<ThreadIdentity>,
        keepalive_ns: u64,
        stability_ns: u64,
        cap_ns: u64,
    },
    WebsocketRetired {
        elapsed_ns: u64,
        inventories: Vec<ThreadInventory>,
    },
    Freeze,
    Frozen {
        report: SamplerReport,
    },
    Release,
    Released {
        monotonic_ns: u64,
    },
    FinalSample,
    Sampled {
        report: SamplerReport,
    },
    Stop,
    Stopped {
        role: Role,
    },
    RoleError {
        class: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadTarget {
    Gateway,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionPolicy {
    PersistentH1,
    FreshH1PerOperation,
    PersistentH2,
    H1UpgradeTunnels,
    H2ExtendedConnectStreams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLedger {
    pub policy: ConnectionPolicy,
    pub planned_connections: u64,
    pub socket_creations: u64,
    pub connect_attempts: u64,
    pub connect_successes: u64,
    pub cumulative_connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub close_tokens: u64,
    pub keep_alive_tokens: u64,
    pub response_eos: u64,
    pub transport_eof: u64,
    pub active_connections: u64,
    pub max_active_connections: u64,
    pub max_requests_per_connection: u64,
    pub h2_streams: u64,
    pub reuse_attempts: u64,
    pub reconnect_attempts: u64,
    pub retry_attempts: u64,
    pub operation_connection_hash_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedProcess {
    pub role: Role,
    pub identity: ProcessIdentity,
    pub executable_sha256: String,
    pub broad_cpus: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadIdentity {
    pub pid: u32,
    pub tid: u32,
    pub start_time_ticks: u64,
    pub comm: String,
    pub assigned_cpu: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadInventory {
    pub role: Role,
    pub executable_sha256: String,
    pub threads: Vec<ThreadIdentity>,
    pub semantic_signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePoint {
    pub role: Role,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub user_ticks: u64,
    pub system_ticks: u64,
    pub vm_hwm_kib: Option<u64>,
    pub vm_rss_kib: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuAttribution {
    pub cpu: u16,
    pub capacity_ticks: u64,
    pub scheduled_ticks: u64,
    pub role_runtime_lower_ticks: u64,
    pub role_runtime_upper_ticks: u64,
    pub attribution_uncertainty_ticks: u64,
    pub external_upper_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplerReport {
    pub monotonic_ns: u64,
    pub boottime_ns: u64,
    pub frozen: bool,
    pub inventories: Vec<ThreadInventory>,
    pub resources: Vec<ResourcePoint>,
    pub attribution: Vec<CpuAttribution>,
    pub lifecycle_events: u64,
    pub post_freeze_change: Option<String>,
    pub tctl_millidegrees: Option<u64>,
    pub swap_in: u64,
    pub swap_out: u64,
    pub cpu_psi_some_us: u64,
    pub memory_psi_full_us: u64,
    pub io_psi_full_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadProof {
    pub downstream_protocol: Protocol,
    pub physical_connections: u64,
    pub h2_settings_proved: bool,
    pub extended_connect_proved: bool,
    pub warmup_operations: u64,
    pub tunnels: u64,
    pub last_operation_id: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub connection_ledger: ConnectionLedger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadResult {
    pub protocol: Protocol,
    pub operations_started: u64,
    pub operations_completed: u64,
    pub operations_completed_by_deadline: u64,
    pub window_start_ns: u64,
    pub window_deadline_ns: Option<u64>,
    pub window_end_ns: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub first_operation_id: String,
    pub last_operation_id: String,
    pub operation_hash_sha256: String,
    pub status_ok: bool,
    pub eos_ok: bool,
    pub payload_ok: bool,
    pub response_headers_sanitized: bool,
    pub retries: u64,
    pub latencies_ns: Vec<u64>,
    pub connection_ledger: ConnectionLedger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointObservation {
    pub operation_id: String,
    pub protocol: Protocol,
    pub connection_id: u64,
    pub stream_id: Option<u64>,
    pub method: String,
    pub path: String,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub status: u16,
    pub request_eos: bool,
    pub response_eos: bool,
    pub payload_ok: bool,
    pub identity_ok: bool,
    pub request_headers_sanitized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureResult {
    pub target: LoadTarget,
    pub expected_protocol: Protocol,
    pub physical_connections: u64,
    pub active_connections: u64,
    pub max_active_connections: u64,
    pub max_requests_per_connection: u64,
    pub tripwire_connections: u64,
    pub tripwire_bytes: u64,
    pub duplicate_operations: u64,
    pub unknown_requests: u64,
    pub observations: Vec<EndpointObservation>,
    pub operation_hash_sha256: String,
}

pub struct FramedControl {
    stream: TcpStream,
    context: ControlContext,
    next_send: u64,
    next_receive: u64,
}

impl FramedControl {
    pub fn new(stream: TcpStream, context: ControlContext) -> Result<Self> {
        let peer = stream.peer_addr()?;
        let local = stream.local_addr()?;
        if !peer.ip().is_loopback() || !local.ip().is_loopback() {
            return Err(Error::new("control connection is not literal loopback"));
        }
        context.cell.validate()?;
        if context.run_id.is_empty() || context.run_id.len() > 128 {
            return Err(Error::new("invalid control run ID"));
        }
        Ok(Self {
            stream,
            context,
            next_send: 0,
            next_receive: 0,
        })
    }

    pub async fn send(&mut self, body: ControlBody) -> Result<()> {
        let envelope = ControlEnvelope {
            schema: CONTROL_SCHEMA.to_owned(),
            run_id: self.context.run_id.clone(),
            cell: self.context.cell,
            arm: self.context.arm,
            block: self.context.block,
            sequence: self.next_send,
            body,
        };
        let bytes = json::canonical_bytes(&envelope)?;
        if bytes.len() > CONTROL_MAX_BYTES {
            return Err(Error::new("control frame exceeds 1 MiB"));
        }
        let length =
            u32::try_from(bytes.len()).map_err(|_| Error::new("control length overflow"))?;
        self.stream.write_all(&length.to_be_bytes()).await?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or_else(|| Error::new("control send sequence overflow"))?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<ControlBody> {
        let length = self.stream.read_u32().await? as usize;
        if length == 0 || length > CONTROL_MAX_BYTES {
            return Err(Error::new("invalid control frame length"));
        }
        let mut bytes = vec![0_u8; length];
        self.stream.read_exact(&mut bytes).await?;
        let envelope: ControlEnvelope = json::from_slice_strict(&bytes)?;
        if envelope.schema != CONTROL_SCHEMA
            || envelope.run_id != self.context.run_id
            || envelope.cell != self.context.cell
            || envelope.arm != self.context.arm
            || envelope.block != self.context.block
        {
            return Err(Error::new("stale or cross-run control envelope"));
        }
        if envelope.sequence != self.next_receive {
            return Err(Error::new(format!(
                "control sequence mismatch: expected {}, got {}",
                self.next_receive, envelope.sequence
            )));
        }
        self.next_receive = self
            .next_receive
            .checked_add(1)
            .ok_or_else(|| Error::new("control receive sequence overflow"))?;
        Ok(envelope.body)
    }
}

pub async fn bind_loopback() -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind loopback control listener")?;
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        return Err(Error::new("control listener did not bind loopback"));
    }
    Ok((listener, address))
}

pub async fn connect_loopback(
    address: SocketAddr,
    context: ControlContext,
) -> Result<FramedControl> {
    if !address.ip().is_loopback() {
        return Err(Error::new("non-loopback control target rejected"));
    }
    let stream = TcpStream::connect(address)
        .await
        .context("connect loopback control")?;
    stream.set_nodelay(true)?;
    FramedControl::new(stream, context)
}

pub fn parse_loopback_address(value: &str) -> Result<SocketAddr> {
    let address = value
        .parse::<SocketAddr>()
        .context("parse literal loopback socket address")?;
    if !address.ip().is_loopback() {
        return Err(Error::new("non-loopback socket address rejected"));
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Workload;

    fn context() -> ControlContext {
        ControlContext {
            run_id: "test-run".to_owned(),
            cell: Cell {
                workload: Workload::Get,
                concurrency: 1,
            },
            arm: Arm::C22,
            block: 7,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn framed_control_rejects_cross_run_and_sequence_aliases() {
        let (listener, address) = bind_loopback().await.expect("listener");
        let server_context = context();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut control = FramedControl::new(stream, server_context).expect("control");
            control.receive().await
        });
        let mut client = connect_loopback(address, context()).await.expect("connect");
        client
            .send(ControlBody::Ready {
                role: Role::Load,
                data_address: None,
                tripwire_address: None,
            })
            .await
            .expect("send");
        assert!(matches!(
            server.await.unwrap().unwrap(),
            ControlBody::Ready { .. }
        ));
    }

    #[test]
    fn rejects_non_loopback_control_addresses() {
        assert!(parse_loopback_address("8.8.8.8:53").is_err());
        assert!(parse_loopback_address("127.0.0.1:1234").is_ok());
    }
}
