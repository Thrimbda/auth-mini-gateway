use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::{http1, http2};
use hyper::rt::{Read as HyperRead, ReadBuf, ReadBufCursor, Write as HyperWrite};
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_rustls::{DefaultServerNameResolver, HttpsConnector, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use rand::{rngs::OsRng, RngCore as _};
use rustls::RootCertStore;
use sha1::{Digest as _, Sha1};
use tokio::net::TcpStream;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at, Instant};
use tower_service::Service;

use crate::capacity::{DownstreamLease, DownstreamStreamLease};
use crate::config::{DialHost, TrustedProxySet, UpstreamBase, UpstreamProtocol};
use crate::http::is_safe_header_value;
use crate::runtime_plan::UPSTREAM_IDLE_POOL_CAPACITY;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SENDER_READY_TIMEOUT: Duration = Duration::from_secs(1);
const H2_INITIAL_SETTINGS_MAX: usize = 16_384;
const H2_LOCAL_STREAM_CAP: usize = 100;
const H2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug)]
pub struct ProxyIdentity {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WebSocketRequest {
    downstream: DownstreamWebSocket,
    protocols: Vec<String>,
    extension_names: HashSet<String>,
}

#[derive(Clone, Debug)]
enum DownstreamWebSocket {
    Http1 { key: String },
    Http2,
}

impl WebSocketRequest {
    fn downstream_protocol(&self) -> ActualProtocol {
        match self.downstream {
            DownstreamWebSocket::Http1 { .. } => ActualProtocol::Http1,
            DownstreamWebSocket::Http2 => ActualProtocol::Http2,
        }
    }

    fn downstream_key(&self) -> Option<&str> {
        match &self.downstream {
            DownstreamWebSocket::Http1 { key } => Some(key),
            DownstreamWebSocket::Http2 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WebSocketRequestError {
    BadRequest,
    MethodNotAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebSocketBridge {
    H1ToH1,
    H1ToH2,
    H2ToH1,
    H2ToH2,
}

impl WebSocketBridge {
    fn new(downstream: ActualProtocol, upstream: ActualProtocol) -> Self {
        match (downstream, upstream) {
            (ActualProtocol::Http1, ActualProtocol::Http1) => Self::H1ToH1,
            (ActualProtocol::Http1, ActualProtocol::Http2) => Self::H1ToH2,
            (ActualProtocol::Http2, ActualProtocol::Http1) => Self::H2ToH1,
            (ActualProtocol::Http2, ActualProtocol::Http2) => Self::H2ToH2,
        }
    }

    fn downstream(self) -> ActualProtocol {
        match self {
            Self::H1ToH1 | Self::H1ToH2 => ActualProtocol::Http1,
            Self::H2ToH1 | Self::H2ToH2 => ActualProtocol::Http2,
        }
    }

    fn upstream(self) -> ActualProtocol {
        match self {
            Self::H1ToH1 | Self::H2ToH1 => ActualProtocol::Http1,
            Self::H1ToH2 | Self::H2ToH2 => ActualProtocol::Http2,
        }
    }
}

struct PreparedWebSocket {
    bridge: WebSocketBridge,
    upstream_key: Option<String>,
}

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    BadGateway,
    Internal,
    Capacity(CapacityClass),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityClass {
    ActiveUpstream,
    BlockingResolver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientIp(IpAddr);

pub(crate) fn derive_client_ip(
    direct_peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxySet,
) -> Result<ClientIp, ProxyError> {
    if !trusted_proxies.contains(direct_peer) {
        return Ok(ClientIp(direct_peer));
    }
    let values: Vec<_> = headers.get_all("x-forwarded-for").iter().collect();
    if values.is_empty() {
        return Ok(ClientIp(direct_peer));
    }
    if values.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    let value = values[0].to_str().map_err(|_| ProxyError::BadRequest)?;
    if value.is_empty()
        || value.contains(',')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ProxyError::BadRequest);
    }
    value
        .parse::<IpAddr>()
        .map(ClientIp)
        .map_err(|_| ProxyError::BadRequest)
}

type RequestBody = TrackedRequestBody<Incoming>;
type H1Sender = http1::SendRequest<RequestBody>;
type H2Sender = http2::SendRequest<RequestBody>;
type UpstreamIo = MaybeHttpsStream<TokioIo<TcpStream>>;
type ProvedH2Io = H2ProofIo<UpstreamIo>;
type H2Connection = http2::Connection<ProvedH2Io, RequestBody, hyper_util::rt::TokioExecutor>;
type OwnerPool = Arc<Mutex<Vec<PoolEntry>>>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InitialH2Settings {
    extended_connect: bool,
    max_concurrent_streams: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H2ProofStatus {
    Pending,
    Ready(InitialH2Settings),
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationState {
    Proving,
    LiveDisabled,
    LiveEnabled,
    Revoked,
    Retiring,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H2DispatchKind {
    Ordinary,
    ExtendedConnect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchGateError {
    Ineligible,
    Poisoned,
}

struct GenerationControl {
    id: u64,
    selectable: AtomicBool,
    state: Mutex<GenerationState>,
    retirement: watch::Sender<bool>,
}

impl GenerationControl {
    fn new(id: u64) -> Arc<Self> {
        let (retirement, _) = watch::channel(false);
        Arc::new(Self {
            id,
            selectable: AtomicBool::new(false),
            state: Mutex::new(GenerationState::Proving),
            retirement,
        })
    }

    fn install_initial(&self, enabled: bool) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if *state != GenerationState::Proving {
            return Err(());
        }
        *state = if enabled {
            GenerationState::LiveEnabled
        } else {
            GenerationState::LiveDisabled
        };
        self.selectable.store(true, Ordering::Release);
        Ok(())
    }

    fn revoke_if_enabled(&self) {
        let publish = match self.state.lock() {
            Ok(mut state) if *state == GenerationState::LiveEnabled => {
                *state = GenerationState::Revoked;
                self.selectable.store(false, Ordering::Release);
                true
            }
            Ok(_) => false,
            Err(_) => {
                self.selectable.store(false, Ordering::Release);
                true
            }
        };
        if publish {
            self.retirement.send_replace(true);
        }
    }

    fn is_selectable(&self) -> bool {
        self.selectable.load(Ordering::Acquire)
    }

    fn initial_state_matches(&self, extended_connect: bool) -> bool {
        self.state.lock().is_ok_and(|state| {
            matches!(
                (*state, extended_connect),
                (GenerationState::LiveEnabled, true) | (GenerationState::LiveDisabled, false)
            )
        })
    }

    fn permits_extended_connect(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| *state == GenerationState::LiveEnabled)
    }

    fn linearize_dispatch<R>(
        &self,
        kind: H2DispatchKind,
        enqueue: impl FnOnce() -> R,
    ) -> Result<R, DispatchGateError> {
        let state = self.state.lock().map_err(|_| DispatchGateError::Poisoned)?;
        let allowed = match (*state, kind) {
            (GenerationState::LiveDisabled, H2DispatchKind::Ordinary)
            | (GenerationState::LiveEnabled, _) => true,
            (GenerationState::Proving, _)
            | (GenerationState::LiveDisabled, H2DispatchKind::ExtendedConnect)
            | (GenerationState::Revoked, _)
            | (GenerationState::Retiring, _)
            | (GenerationState::Closed, _) => false,
        };
        if !allowed {
            return Err(DispatchGateError::Ineligible);
        }
        Ok(enqueue())
    }

    fn mark_retiring(&self) {
        self.selectable.store(false, Ordering::Release);
        if let Ok(mut state) = self.state.lock() {
            if *state != GenerationState::Closed {
                *state = GenerationState::Retiring;
            }
        }
    }

    fn mark_closed(&self) {
        self.selectable.store(false, Ordering::Release);
        if let Ok(mut state) = self.state.lock() {
            *state = GenerationState::Closed;
        }
    }

    fn retirement_receiver(&self) -> watch::Receiver<bool> {
        self.retirement.subscribe()
    }

    fn io_must_fail(&self) -> bool {
        self.state.lock().map_or(true, |state| {
            matches!(
                *state,
                GenerationState::Revoked | GenerationState::Retiring | GenerationState::Closed
            )
        })
    }
}

struct H2ProofState {
    parser: Mutex<H2ProofParser>,
    status: watch::Sender<H2ProofStatus>,
    transport_dropped: watch::Sender<bool>,
    control: Arc<GenerationControl>,
}

impl H2ProofState {
    fn new(control: Arc<GenerationControl>) -> Arc<Self> {
        let (status, _) = watch::channel(H2ProofStatus::Pending);
        let (transport_dropped, _) = watch::channel(false);
        Arc::new(Self {
            parser: Mutex::new(H2ProofParser::default()),
            status,
            transport_dropped,
            control,
        })
    }

    fn status_receiver(&self) -> watch::Receiver<H2ProofStatus> {
        self.status.subscribe()
    }

    fn observe_inbound(&self, bytes: &[u8]) {
        let (status, initial, revoke) = match self.parser.lock() {
            Ok(mut parser) => match parser.inbound.feed(bytes) {
                Ok(observation) => (
                    self.proof_status(&parser),
                    observation.initial,
                    observation.revoke,
                ),
                Err(()) => (H2ProofStatus::Failed, None, false),
            },
            Err(_) => (H2ProofStatus::Failed, None, true),
        };
        if let Some(initial) = initial {
            if self
                .control
                .install_initial(initial.extended_connect)
                .is_err()
            {
                self.status.send_replace(H2ProofStatus::Failed);
                return;
            }
        }
        if revoke {
            self.control.revoke_if_enabled();
        }
        self.publish_status(status);
    }

    fn observe_outbound(&self, bytes: &[u8]) {
        self.update(|parser| parser.outbound.feed(bytes));
    }

    fn observe_outbound_vectored(&self, bufs: &[IoSlice<'_>], mut accepted: usize) {
        for buf in bufs {
            if accepted == 0 {
                break;
            }
            let consumed = accepted.min(buf.len());
            self.observe_outbound(&buf[..consumed]);
            accepted -= consumed;
        }
    }

    fn io_failed(&self) {
        self.status.send_replace(H2ProofStatus::Failed);
    }

    fn update(&self, feed: impl FnOnce(&mut H2ProofParser) -> Result<(), ()>) {
        if *self.status.borrow() != H2ProofStatus::Pending {
            return;
        }
        let status = match self.parser.lock() {
            Ok(mut parser) => {
                if feed(&mut parser).is_err() {
                    H2ProofStatus::Failed
                } else {
                    self.proof_status(&parser)
                }
            }
            Err(_) => H2ProofStatus::Failed,
        };
        self.publish_status(status);
    }

    fn proof_status(&self, parser: &H2ProofParser) -> H2ProofStatus {
        if parser.outbound.ack_seen {
            parser
                .inbound
                .settings
                .map_or(H2ProofStatus::Pending, H2ProofStatus::Ready)
        } else {
            H2ProofStatus::Pending
        }
    }

    fn publish_status(&self, status: H2ProofStatus) {
        if status != H2ProofStatus::Pending && *self.status.borrow() == H2ProofStatus::Pending {
            self.status.send_replace(status);
        }
    }

    fn mark_transport_dropped(&self) {
        self.transport_dropped.send_replace(true);
        if *self.status.borrow() == H2ProofStatus::Pending {
            self.status.send_replace(H2ProofStatus::Failed);
        }
    }

    fn is_transport_dropped(&self) -> bool {
        *self.transport_dropped.borrow()
    }

    async fn wait_transport_dropped(&self) {
        let mut receiver = self.transport_dropped.subscribe();
        while !*receiver.borrow() {
            if receiver.changed().await.is_err() {
                break;
            }
        }
    }
}

#[derive(Default)]
struct H2ProofParser {
    inbound: ServerFrameScanner,
    outbound: ClientAckParser,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InboundObservation {
    initial: Option<InitialH2Settings>,
    revoke: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ScannedPayload {
    #[default]
    Skip,
    InitialSettings,
    LaterSettings,
}

#[derive(Default)]
struct ServerFrameScanner {
    header: [u8; 9],
    header_len: usize,
    payload_remaining: u32,
    payload: ScannedPayload,
    pair: [u8; 6],
    pair_len: usize,
    frame_extended_connect: Option<bool>,
    building_initial: InitialH2Settings,
    settings: Option<InitialH2Settings>,
}

impl ServerFrameScanner {
    fn feed(&mut self, mut bytes: &[u8]) -> Result<InboundObservation, ()> {
        let mut observation = InboundObservation::default();
        while !bytes.is_empty() {
            if self.payload_remaining == 0 {
                let copied = (self.header.len() - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + copied]
                    .copy_from_slice(&bytes[..copied]);
                self.header_len += copied;
                bytes = &bytes[copied..];
                if self.header_len < self.header.len() {
                    break;
                }
                self.begin_frame()?;
                if self.payload_remaining == 0 {
                    self.finish_frame(&mut observation);
                    continue;
                }
            }

            match self.payload {
                ScannedPayload::Skip => {
                    let skipped = usize::try_from(self.payload_remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    self.payload_remaining -= skipped as u32;
                    bytes = &bytes[skipped..];
                }
                ScannedPayload::InitialSettings | ScannedPayload::LaterSettings => {
                    let copied = (self.pair.len() - self.pair_len)
                        .min(usize::try_from(self.payload_remaining).unwrap_or(usize::MAX))
                        .min(bytes.len());
                    self.pair[self.pair_len..self.pair_len + copied]
                        .copy_from_slice(&bytes[..copied]);
                    self.pair_len += copied;
                    self.payload_remaining -= copied as u32;
                    bytes = &bytes[copied..];
                    if self.pair_len == self.pair.len() {
                        self.consume_pair()?;
                        self.pair_len = 0;
                    }
                }
            }

            if self.payload_remaining == 0 {
                self.finish_frame(&mut observation);
            }
        }
        Ok(observation)
    }

    fn begin_frame(&mut self) -> Result<(), ()> {
        let length = u32::from_be_bytes([0, self.header[0], self.header[1], self.header[2]]);
        let frame_type = self.header[3];
        let flags = self.header[4];
        let stream = u32::from_be_bytes([
            self.header[5],
            self.header[6],
            self.header[7],
            self.header[8],
        ]) & 0x7fff_ffff;
        self.header_len = 0;
        self.payload_remaining = length;
        self.pair_len = 0;
        self.frame_extended_connect = None;

        if self.settings.is_none() {
            if frame_type != 0x4
                || flags & 0x1 != 0
                || stream != 0
                || length as usize > H2_INITIAL_SETTINGS_MAX
                || !length.is_multiple_of(6)
            {
                return Err(());
            }
            self.building_initial = InitialH2Settings::default();
            self.payload = ScannedPayload::InitialSettings;
        } else if frame_type == 0x4 && flags & 0x1 == 0 && stream == 0 && length.is_multiple_of(6) {
            self.payload = ScannedPayload::LaterSettings;
        } else {
            self.payload = ScannedPayload::Skip;
        }
        Ok(())
    }

    fn consume_pair(&mut self) -> Result<(), ()> {
        let id = u16::from_be_bytes([self.pair[0], self.pair[1]]);
        let value = u32::from_be_bytes([self.pair[2], self.pair[3], self.pair[4], self.pair[5]]);
        match self.payload {
            ScannedPayload::InitialSettings => match id {
                0x2 => return Err(()),
                0x3 => self.building_initial.max_concurrent_streams = Some(value),
                0x4 if value > 0x7fff_ffff => return Err(()),
                0x5 if !(16_384..=16_777_215).contains(&value) => return Err(()),
                0x8 if value > 1 => return Err(()),
                0x8 => self.building_initial.extended_connect = value == 1,
                _ => {}
            },
            ScannedPayload::LaterSettings if id == 0x8 && value <= 1 => {
                self.frame_extended_connect = Some(value == 1);
            }
            ScannedPayload::LaterSettings | ScannedPayload::Skip => {}
        }
        Ok(())
    }

    fn finish_frame(&mut self, observation: &mut InboundObservation) {
        match self.payload {
            ScannedPayload::InitialSettings => {
                self.settings = Some(self.building_initial);
                observation.initial = Some(self.building_initial);
            }
            ScannedPayload::LaterSettings => {
                if self.frame_extended_connect == Some(false) {
                    observation.revoke = true;
                }
            }
            ScannedPayload::Skip => {}
        }
        self.payload = ScannedPayload::Skip;
        self.pair_len = 0;
        self.frame_extended_connect = None;
    }
}

#[derive(Default)]
struct ClientAckParser {
    preface_len: usize,
    header: [u8; 9],
    header_len: usize,
    payload_remaining: usize,
    ack_seen: bool,
}

impl ClientAckParser {
    fn feed(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        if self.ack_seen {
            return Ok(());
        }
        while !bytes.is_empty() {
            if self.preface_len < H2_CLIENT_PREFACE.len() {
                let copied = (H2_CLIENT_PREFACE.len() - self.preface_len).min(bytes.len());
                if bytes[..copied] != H2_CLIENT_PREFACE[self.preface_len..self.preface_len + copied]
                {
                    return Err(());
                }
                self.preface_len += copied;
                bytes = &bytes[copied..];
                continue;
            }

            if self.payload_remaining != 0 {
                let skipped = self.payload_remaining.min(bytes.len());
                self.payload_remaining -= skipped;
                bytes = &bytes[skipped..];
                continue;
            }

            let copied = (self.header.len() - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.header_len += copied;
            bytes = &bytes[copied..];
            if self.header_len < self.header.len() {
                continue;
            }

            let length = ((self.header[0] as usize) << 16)
                | ((self.header[1] as usize) << 8)
                | self.header[2] as usize;
            let stream = u32::from_be_bytes([
                self.header[5],
                self.header[6],
                self.header[7],
                self.header[8],
            ]) & 0x7fff_ffff;
            if self.header[3] == 0x4 && self.header[4] & 0x1 != 0 {
                if length != 0 || stream != 0 {
                    return Err(());
                }
                self.ack_seen = true;
                return Ok(());
            }
            self.payload_remaining = length;
            self.header_len = 0;
        }
        Ok(())
    }
}

struct H2ProofIo<T> {
    inner: Option<T>,
    proof: Arc<H2ProofState>,
}

impl<T> H2ProofIo<T> {
    fn new(inner: T, proof: Arc<H2ProofState>) -> Self {
        Self {
            inner: Some(inner),
            proof,
        }
    }
}

fn revoked_h2_io_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "upstream HTTP/2 generation retired",
    )
}

impl<T: HyperRead + Unpin> HyperRead for H2ProofIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut cursor: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if cursor.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.proof.control.io_must_fail() {
            return Poll::Ready(Err(revoked_h2_io_error()));
        }
        let mut observed = ReadBuf::uninit(unsafe { cursor.as_mut() });
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(revoked_h2_io_error()));
        };
        match Pin::new(inner).poll_read(context, observed.unfilled()) {
            Poll::Ready(Ok(())) => {
                let filled = observed.filled();
                if filled.is_empty() {
                    this.proof.io_failed();
                } else {
                    this.proof.observe_inbound(filled);
                }
                let count = filled.len();
                unsafe { cursor.advance(count) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.proof.io_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: HyperWrite + Unpin> HyperWrite for H2ProofIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.proof.control.io_must_fail() {
            return Poll::Ready(Err(revoked_h2_io_error()));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(revoked_h2_io_error()));
        };
        match Pin::new(inner).poll_write(context, bytes) {
            Poll::Ready(Ok(accepted)) => {
                this.proof.observe_outbound(&bytes[..accepted]);
                Poll::Ready(Ok(accepted))
            }
            Poll::Ready(Err(error)) => {
                this.proof.io_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if this.proof.control.io_must_fail() {
            return Poll::Ready(Err(revoked_h2_io_error()));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(revoked_h2_io_error()));
        };
        Pin::new(inner).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        if this.proof.control.io_must_fail() {
            return Poll::Ready(Err(revoked_h2_io_error()));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(revoked_h2_io_error()));
        };
        Pin::new(inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(HyperWrite::is_write_vectored)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.proof.control.io_must_fail() {
            return Poll::Ready(Err(revoked_h2_io_error()));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(Err(revoked_h2_io_error()));
        };
        match Pin::new(inner).poll_write_vectored(context, bufs) {
            Poll::Ready(Ok(accepted)) => {
                this.proof.observe_outbound_vectored(bufs, accepted);
                Poll::Ready(Ok(accepted))
            }
            Poll::Ready(Err(error)) => {
                this.proof.io_failed();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Drop for H2ProofIo<T> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            drop(inner);
        }
        self.proof.mark_transport_dropped();
    }
}

struct PrivateH2Gate {
    sender: Option<H2Sender>,
    connection: Option<Pin<Box<H2Connection>>>,
    proof: Arc<H2ProofState>,
    status: watch::Receiver<H2ProofStatus>,
    active_permit: Option<OwnedSemaphorePermit>,
    armed: bool,
}

impl PrivateH2Gate {
    fn new(
        sender: H2Sender,
        connection: H2Connection,
        proof: Arc<H2ProofState>,
        active_permit: OwnedSemaphorePermit,
    ) -> Self {
        let status = proof.status_receiver();
        Self {
            sender: Some(sender),
            connection: Some(Box::pin(connection)),
            proof,
            status,
            active_permit: Some(active_permit),
            armed: true,
        }
    }

    fn sender(&self) -> &H2Sender {
        self.sender.as_ref().expect("private H2 sender")
    }

    async fn prove(&mut self, deadline: Instant) -> Result<InitialH2Settings, ProxyError> {
        loop {
            let status = *self.status.borrow_and_update();
            match status {
                H2ProofStatus::Ready(settings) => {
                    let connection_completed = std::future::poll_fn(|context| {
                        Poll::Ready(
                            self.connection
                                .as_mut()
                                .expect("private H2 connection")
                                .as_mut()
                                .poll(context)
                                .is_ready(),
                        )
                    })
                    .await;
                    let hyper_extended_connect = self
                        .connection
                        .as_ref()
                        .expect("private H2 connection")
                        .as_ref()
                        .get_ref()
                        .is_extended_connect_protocol_enabled();
                    if connection_completed
                        || self.sender().is_closed()
                        || self.proof.is_transport_dropped()
                        || !self
                            .proof
                            .control
                            .initial_state_matches(settings.extended_connect)
                        || (settings.extended_connect && !hyper_extended_connect)
                    {
                        tracing::info!(
                            event = "upstream_failure",
                            stage = "settings",
                            protocol = "http2",
                            outcome = "connection_closed"
                        );
                        return Err(ProxyError::BadGateway);
                    }
                    return Ok(settings);
                }
                H2ProofStatus::Failed => {
                    tracing::info!(
                        event = "upstream_failure",
                        stage = "settings",
                        protocol = "http2",
                        outcome = "invalid"
                    );
                    return Err(ProxyError::BadGateway);
                }
                H2ProofStatus::Pending => {}
            }

            let connection = self
                .connection
                .as_mut()
                .expect("private H2 connection")
                .as_mut();
            tokio::select! {
                _ = connection => {
                    tracing::info!(
                        event = "upstream_failure",
                        stage = "settings",
                        protocol = "http2",
                        outcome = "connection_closed"
                    );
                    return Err(ProxyError::BadGateway);
                }
                changed = self.status.changed() => {
                    if changed.is_err() {
                        return Err(ProxyError::BadGateway);
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    tracing::info!(
                        event = "upstream_failure",
                        stage = "settings",
                        protocol = "http2",
                        outcome = "timeout"
                    );
                    return Err(ProxyError::BadGateway);
                }
            }
        }
    }

    fn take(
        &mut self,
    ) -> (
        H2Sender,
        Pin<Box<H2Connection>>,
        Arc<H2ProofState>,
        OwnedSemaphorePermit,
    ) {
        self.armed = false;
        (
            self.sender.take().expect("private H2 sender"),
            self.connection.take().expect("private H2 connection"),
            Arc::clone(&self.proof),
            self.active_permit.take().expect("private H2 permit"),
        )
    }
}

impl Drop for PrivateH2Gate {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.sender.take();
        self.connection.take();
        if let Some(permit) = self.active_permit.take() {
            schedule_permit_after_transport_drop(Arc::clone(&self.proof), permit);
        }
    }
}

#[derive(Clone)]
pub struct Proxy {
    upstream: UpstreamBase,
    configured_protocol: UpstreamProtocol,
    connect_uri: Uri,
    tls: rustls::ClientConfig,
    idle: OwnerPool,
    active: Arc<Semaphore>,
    active_limit: usize,
    resolvers: Arc<Semaphore>,
    resolver: Arc<dyn HostResolver>,
    resolver_accounting: Arc<ResolverAccounting>,
    connect_timeout: Duration,
    driver_accounting: Arc<DriverRetirementAccounting>,
    next_generation: Arc<AtomicU64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActualProtocol {
    Http1,
    Http2,
}

impl ActualProtocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
        }
    }
}

#[derive(Clone, Copy)]
enum TransportKind {
    Cleartext,
    Tls,
}

impl TransportKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cleartext => "cleartext",
            Self::Tls => "tls",
        }
    }
}

#[derive(Clone, Copy)]
enum ProtocolSource {
    Forced,
    Alpn,
}

#[derive(Clone, Copy)]
struct ActualSelection {
    protocol: ActualProtocol,
    transport: TransportKind,
    source: ProtocolSource,
}

fn select_actual_protocol(
    configured: UpstreamProtocol,
    scheme: &str,
    io: &UpstreamIo,
) -> Result<ActualSelection, ProxyError> {
    let transport = if scheme == "https" {
        TransportKind::Tls
    } else {
        TransportKind::Cleartext
    };
    let alpn = match (transport, io) {
        (TransportKind::Cleartext, MaybeHttpsStream::Http(_)) => None,
        (TransportKind::Tls, MaybeHttpsStream::Https(stream)) => {
            stream.inner().get_ref().1.alpn_protocol()
        }
        _ => return Err(ProxyError::BadGateway),
    };

    let (protocol, source) = match (transport, configured) {
        (TransportKind::Cleartext, UpstreamProtocol::Http1) => {
            (ActualProtocol::Http1, ProtocolSource::Forced)
        }
        (TransportKind::Cleartext, UpstreamProtocol::Http2) => {
            (ActualProtocol::Http2, ProtocolSource::Forced)
        }
        (TransportKind::Cleartext, UpstreamProtocol::Auto) => {
            return Err(ProxyError::BadGateway);
        }
        (TransportKind::Tls, UpstreamProtocol::Http1) => {
            if alpn.is_some() {
                return Err(ProxyError::BadGateway);
            }
            (ActualProtocol::Http1, ProtocolSource::Forced)
        }
        (TransportKind::Tls, UpstreamProtocol::Http2) => {
            if alpn != Some(b"h2".as_slice()) {
                return Err(ProxyError::BadGateway);
            }
            (ActualProtocol::Http2, ProtocolSource::Forced)
        }
        (TransportKind::Tls, UpstreamProtocol::Auto) => match alpn {
            Some(b"h2") => (ActualProtocol::Http2, ProtocolSource::Alpn),
            Some(b"http/1.1") | None => (ActualProtocol::Http1, ProtocolSource::Alpn),
            Some(_) => return Err(ProxyError::BadGateway),
        },
    };
    Ok(ActualSelection {
        protocol,
        transport,
        source,
    })
}

fn emit_upstream_protocol_selected(
    configured: UpstreamProtocol,
    selection: ActualSelection,
    h2: Option<(u64, bool)>,
) {
    match h2 {
        Some((generation, extended_connect)) => tracing::info!(
            event = "upstream_protocol_selected",
            configured = configured.as_str(),
            transport = selection.transport.as_str(),
            protocol = selection.protocol.as_str(),
            source = selection.source.as_str(),
            generation,
            extended_connect
        ),
        None => tracing::info!(
            event = "upstream_protocol_selected",
            configured = configured.as_str(),
            transport = selection.transport.as_str(),
            protocol = selection.protocol.as_str(),
            source = selection.source.as_str()
        ),
    }
}

impl ProtocolSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Forced => "forced",
            Self::Alpn => "alpn",
        }
    }
}

enum PoolEntry {
    H1(CompleteOwner),
    H2(Arc<H2Generation>),
    RetiringH2 { generation: u64 },
}

struct H2DriverState {
    control: Arc<GenerationControl>,
    published: AtomicBool,
    pool: Weak<Mutex<Vec<PoolEntry>>>,
    proof: Arc<H2ProofState>,
}

struct H2Generation {
    state: Arc<H2DriverState>,
    master: Mutex<Option<H2Sender>>,
    streams: Arc<Semaphore>,
}

enum H2ReserveResult {
    Reserved(H2StreamReservation),
    Saturated,
    Closed,
}

impl H2Generation {
    fn id(&self) -> u64 {
        self.state.control.id
    }

    fn try_reserve(self: &Arc<Self>) -> H2ReserveResult {
        if !self.state.control.is_selectable() {
            return H2ReserveResult::Closed;
        }
        let permit = match Arc::clone(&self.streams).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return H2ReserveResult::Saturated,
        };
        let sender = match self.master.lock() {
            Ok(master) => match master.as_ref() {
                Some(sender) if !sender.is_closed() => sender.clone(),
                _ => {
                    self.state
                        .control
                        .selectable
                        .store(false, Ordering::Release);
                    return H2ReserveResult::Closed;
                }
            },
            Err(_) => {
                self.state
                    .control
                    .selectable
                    .store(false, Ordering::Release);
                return H2ReserveResult::Closed;
            }
        };
        H2ReserveResult::Reserved(H2StreamReservation {
            generation: Arc::clone(self),
            sender: Some(sender),
            _stream_permit: permit,
        })
    }

    fn retire(&self) {
        self.state.control.mark_retiring();
        if let Ok(mut master) = self.master.lock() {
            master.take();
        }
    }
}

fn retire_h2_generation(generation: &Arc<H2Generation>) {
    generation.retire();
    if !generation.state.published.load(Ordering::Acquire) {
        return;
    }
    let Some(pool) = generation.state.pool.upgrade() else {
        return;
    };
    let Ok(mut entries) = pool.lock() else {
        return;
    };
    if let Some(index) = entries.iter().position(
        |entry| matches!(entry, PoolEntry::H2(candidate) if candidate.id() == generation.id()),
    ) {
        entries[index] = PoolEntry::RetiringH2 {
            generation: generation.id(),
        };
    }
}

fn remove_retiring_h2_slot(pool: &OwnerPool, generation_id: u64) {
    if let Ok(mut entries) = pool.lock() {
        entries.retain(|entry| {
            !matches!(entry, PoolEntry::RetiringH2 { generation } if *generation == generation_id)
        });
    }
}

fn reserve_h2_creator(
    sender: &H2Sender,
    streams: &Arc<Semaphore>,
) -> Result<(H2Sender, OwnedSemaphorePermit), ProxyError> {
    let permit = Arc::clone(streams)
        .try_acquire_owned()
        .map_err(|_| ProxyError::BadGateway)?;
    Ok((sender.clone(), permit))
}

fn publish_h2_generation_slot(pool: &OwnerPool, generation: &Arc<H2Generation>) -> bool {
    if !generation.state.control.is_selectable() {
        return false;
    }
    match pool.lock() {
        Ok(mut entries) if entries.len() < UPSTREAM_IDLE_POOL_CAPACITY => {
            entries.push(PoolEntry::H2(Arc::clone(generation)));
            generation.state.published.store(true, Ordering::Release);
            true
        }
        _ => false,
    }
}

fn spawn_h2_driver(mut connection: Pin<Box<H2Connection>>, state: Arc<H2DriverState>) {
    tokio::spawn(async move {
        let mut retirement = state.control.retirement_receiver();
        let revoked = async {
            loop {
                if *retirement.borrow_and_update() {
                    break;
                }
                if retirement.changed().await.is_err() {
                    break;
                }
            }
        };
        tokio::pin!(revoked);
        let outcome = tokio::select! {
            outcome = connection.as_mut() => Some(outcome),
            () = &mut revoked => None,
        };
        drop(connection);
        state.control.mark_retiring();

        if state.published.load(Ordering::Acquire) {
            if let Some(pool) = state.pool.upgrade() {
                let retired = if let Ok(mut entries) = pool.lock() {
                    if let Some(index) = entries.iter().position(|entry| {
                        matches!(entry, PoolEntry::H2(generation) if generation.id() == state.control.id)
                    }) {
                        let generation = match &entries[index] {
                            PoolEntry::H2(generation) => Some(Arc::clone(generation)),
                            _ => None,
                        };
                        entries[index] = PoolEntry::RetiringH2 {
                            generation: state.control.id,
                        };
                        generation
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(generation) = retired {
                    generation.retire();
                }
            }
        }

        state.proof.wait_transport_dropped().await;
        if state.published.load(Ordering::Acquire) {
            if let Some(pool) = state.pool.upgrade() {
                remove_retiring_h2_slot(&pool, state.control.id);
            }
        }
        state.control.mark_closed();
        tracing::debug!(
            event = "upstream_h2_driver",
            generation = state.control.id,
            outcome = match outcome {
                Some(Ok(())) => "closed",
                Some(Err(_)) => "error",
                None => "revoked",
            }
        );
    });
}

struct H2StreamReservation {
    generation: Arc<H2Generation>,
    sender: Option<H2Sender>,
    _stream_permit: OwnedSemaphorePermit,
}

impl H2StreamReservation {
    fn sender_mut(&mut self) -> Option<&mut H2Sender> {
        self.sender.as_mut()
    }
}

struct H2ExchangeOwner {
    reservation: H2StreamReservation,
    active_permit: Option<OwnedSemaphorePermit>,
    private_generation: bool,
}

enum ExchangeResource {
    H1 { owner: ActiveOwner, pool: OwnerPool },
    H2(H2ExchangeOwner),
}

impl ExchangeResource {
    fn protocol(&self) -> ActualProtocol {
        match self {
            Self::H1 { .. } => ActualProtocol::Http1,
            Self::H2(_) => ActualProtocol::Http2,
        }
    }

    fn h2_extended_connect_enabled(&self) -> Option<bool> {
        match self {
            Self::H1 { .. } => None,
            Self::H2(owner) => Some(
                owner
                    .reservation
                    .generation
                    .state
                    .control
                    .permits_extended_connect(),
            ),
        }
    }
}

struct SelectedExchange {
    resource: Option<ExchangeResource>,
}

impl SelectedExchange {
    fn new(resource: ExchangeResource) -> Self {
        Self {
            resource: Some(resource),
        }
    }

    fn resource(&self) -> &ExchangeResource {
        self.resource.as_ref().expect("selected exchange resource")
    }

    fn protocol(&self) -> ActualProtocol {
        self.resource().protocol()
    }

    fn h2_extended_connect_enabled(&self) -> Option<bool> {
        self.resource().h2_extended_connect_enabled()
    }

    async fn ready(&mut self) -> Result<(), ProxyError> {
        match self.resource.as_mut().expect("selected exchange resource") {
            ExchangeResource::H1 { owner, .. } => {
                let sender = owner.sender_mut().ok_or(ProxyError::Internal)?;
                if sender.ready().await.is_err() {
                    owner.set_retirement_reason(RetirementReason::ReadyFailure);
                    return Err(ProxyError::BadGateway);
                }
            }
            ExchangeResource::H2(owner) => {
                let sender = owner.reservation.sender_mut().ok_or(ProxyError::Internal)?;
                if sender.ready().await.is_err() {
                    retire_h2_generation(&owner.reservation.generation);
                    return Err(ProxyError::BadGateway);
                }
            }
        }
        Ok(())
    }

    fn into_latch(mut self) -> Arc<ExchangeLatch> {
        ExchangeLatch::new(self.resource.take().expect("selected resource"))
    }
}

impl Drop for SelectedExchange {
    fn drop(&mut self) {
        if let Some(resource) = self.resource.take() {
            finish_exchange_resource(resource, false, RetirementReason::RequestCancellation);
        }
    }
}

struct ExchangeLatch {
    inner: Mutex<ExchangeLatchInner>,
}

struct ExchangeLatchInner {
    request_done: Option<bool>,
    response_done: Option<ResponseCompletion>,
    resource: Option<ExchangeResource>,
}

#[derive(Clone, Copy)]
struct ResponseCompletion {
    reusable: bool,
    reason: RetirementReason,
}

impl ExchangeLatch {
    fn new(resource: ExchangeResource) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ExchangeLatchInner {
                request_done: None,
                response_done: None,
                resource: Some(resource),
            }),
        })
    }

    fn request_done(&self, clean: bool) {
        self.complete(|inner| {
            inner.request_done.get_or_insert(clean);
        });
    }

    fn response_done(&self, reusable: bool, reason: RetirementReason) {
        self.complete(|inner| {
            inner
                .response_done
                .get_or_insert(ResponseCompletion { reusable, reason });
        });
    }

    fn complete(&self, update: impl FnOnce(&mut ExchangeLatchInner)) {
        let completed = {
            let mut inner = self.inner.lock().expect("exchange latch");
            update(&mut inner);
            match (inner.request_done, inner.response_done) {
                (Some(request_clean), Some(response)) => inner
                    .resource
                    .take()
                    .map(|resource| (resource, request_clean, response)),
                _ => None,
            }
        };
        if let Some((resource, request_clean, response)) = completed {
            finish_exchange_resource(
                resource,
                request_clean && response.reusable,
                response.reason,
            );
        }
    }

    fn drop_h1_sender(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(ExchangeResource::H1 { owner, .. }) = inner.resource.as_mut() {
                owner.drop_sender();
            }
        }
    }

    fn take_dispatch_sender(self: &Arc<Self>) -> Result<DispatchSenderGuard, ProxyError> {
        let sender = {
            let mut inner = self.inner.lock().map_err(|_| ProxyError::Internal)?;
            match inner.resource.as_mut().ok_or(ProxyError::Internal)? {
                ExchangeResource::H1 { owner, .. } => {
                    DispatchSender::H1(owner.take_sender().ok_or(ProxyError::Internal)?)
                }
                ExchangeResource::H2(owner) => DispatchSender::H2 {
                    sender: owner
                        .reservation
                        .sender
                        .take()
                        .ok_or(ProxyError::Internal)?,
                    generation: Arc::clone(&owner.reservation.generation),
                },
            }
        };
        Ok(DispatchSenderGuard {
            exchange: Arc::clone(self),
            sender: Some(sender),
        })
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: Request<RequestBody>,
        kind: H2DispatchKind,
    ) -> Result<Response<Incoming>, ProxyError> {
        let mut sender = self.take_dispatch_sender()?;
        let result = match sender.sender_mut() {
            DispatchSender::H1(h1_sender) => {
                emit_upstream_dispatch_selected(ActualProtocol::Http1, 0);
                h1_sender.send_request(request).await
            }
            DispatchSender::H2 {
                sender: h2_sender,
                generation,
            } => {
                let generation_id = generation.id();
                let control = Arc::clone(&generation.state.control);
                let response = control.linearize_dispatch(kind, || {
                    emit_upstream_dispatch_selected(ActualProtocol::Http2, generation_id);
                    h2_sender.send_request(request)
                });
                match response {
                    Ok(response) => response.await,
                    Err(DispatchGateError::Ineligible) => return Err(ProxyError::BadGateway),
                    Err(DispatchGateError::Poisoned) => {
                        retire_h2_generation(generation);
                        return Err(ProxyError::BadGateway);
                    }
                }
            }
        };
        if result.is_err() {
            sender.invalidate_if_closed();
        }
        result.map_err(|_| ProxyError::BadGateway)
    }
}

fn emit_upstream_dispatch_selected(protocol: ActualProtocol, generation: u64) {
    tracing::info!(
        event = "upstream_dispatch_selected",
        protocol = protocol.as_str(),
        generation_present = generation != 0,
        generation
    );
}

enum DispatchSender {
    H1(H1Sender),
    H2 {
        sender: H2Sender,
        generation: Arc<H2Generation>,
    },
}

struct DispatchSenderGuard {
    exchange: Arc<ExchangeLatch>,
    sender: Option<DispatchSender>,
}

impl DispatchSenderGuard {
    fn sender_mut(&mut self) -> &mut DispatchSender {
        self.sender.as_mut().expect("dispatch sender")
    }

    fn invalidate_if_closed(&self) {
        if let Some(DispatchSender::H2 { sender, generation }) = self.sender.as_ref() {
            if sender.is_closed() || !generation.state.control.is_selectable() {
                retire_h2_generation(generation);
            }
        }
    }
}

impl Drop for DispatchSenderGuard {
    fn drop(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        if let Ok(mut inner) = self.exchange.inner.lock() {
            if let Some(resource) = inner.resource.as_mut() {
                match (resource, sender) {
                    (ExchangeResource::H1 { owner, .. }, DispatchSender::H1(sender)) => {
                        owner.put_sender(sender);
                    }
                    (ExchangeResource::H2(owner), DispatchSender::H2 { sender, .. }) => {
                        owner.reservation.sender = Some(sender);
                    }
                    _ => {}
                }
            }
        }
    }
}

struct ResponseHalfGuard {
    exchange: Option<Arc<ExchangeLatch>>,
}

impl ResponseHalfGuard {
    fn new(exchange: Arc<ExchangeLatch>) -> Self {
        Self {
            exchange: Some(exchange),
        }
    }

    fn take(&mut self) -> Arc<ExchangeLatch> {
        self.exchange.take().expect("response half exchange")
    }
}

impl Drop for ResponseHalfGuard {
    fn drop(&mut self) {
        if let Some(exchange) = self.exchange.take() {
            exchange.response_done(false, RetirementReason::RequestCancellation);
        }
    }
}

fn finish_exchange_resource(resource: ExchangeResource, reusable: bool, reason: RetirementReason) {
    match resource {
        ExchangeResource::H1 { mut owner, pool } => {
            if reusable {
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(park_or_retire(owner, pool));
                    }
                    Err(_) => owner.set_retirement_reason(reason),
                }
            } else {
                owner.set_retirement_reason(reason);
            }
        }
        ExchangeResource::H2(mut owner) => {
            if owner.private_generation {
                owner.reservation.generation.retire();
                let proof = Arc::clone(&owner.reservation.generation.state.proof);
                let active_permit = owner
                    .active_permit
                    .take()
                    .expect("private H2 active permit");
                drop(owner);
                schedule_permit_after_transport_drop(proof, active_permit);
            }
        }
    }
}

fn schedule_permit_after_transport_drop(proof: Arc<H2ProofState>, permit: OwnedSemaphorePermit) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                proof.wait_transport_dropped().await;
                drop(permit);
            });
        }
        Err(_) => std::mem::forget(permit),
    }
}

impl Proxy {
    pub fn new(
        upstream: UpstreamBase,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::new_with_protocol(
            upstream,
            UpstreamProtocol::Http1,
            max_active_upstreams,
            max_blocking_resolvers,
        )
    }

    pub fn new_with_protocol(
        upstream: UpstreamBase,
        configured_protocol: UpstreamProtocol,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::new_with_native_root_loader_protocol(
            upstream,
            configured_protocol,
            max_active_upstreams,
            max_blocking_resolvers,
            || {
                let native = rustls_native_certs::load_native_certs();
                let mut roots = RootCertStore::empty();
                let (added, _) = roots.add_parsable_certificates(native.certs);
                if added == 0 {
                    return Err("no native TLS roots available".into());
                }
                Ok(roots)
            },
        )
    }

    #[cfg(test)]
    fn new_with_native_root_loader<F>(
        upstream: UpstreamBase,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        load_native_roots: F,
    ) -> Result<Self, BoxError>
    where
        F: FnOnce() -> Result<RootCertStore, BoxError>,
    {
        Self::new_with_native_root_loader_protocol(
            upstream,
            UpstreamProtocol::Http1,
            max_active_upstreams,
            max_blocking_resolvers,
            load_native_roots,
        )
    }

    fn new_with_native_root_loader_protocol<F>(
        upstream: UpstreamBase,
        configured_protocol: UpstreamProtocol,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        load_native_roots: F,
    ) -> Result<Self, BoxError>
    where
        F: FnOnce() -> Result<RootCertStore, BoxError>,
    {
        if upstream.scheme() == "http" {
            return Self::with_root_store_and_protocol(
                upstream,
                configured_protocol,
                RootCertStore::empty(),
                max_active_upstreams,
                max_blocking_resolvers,
            );
        }
        let roots = load_native_roots()?;
        Self::with_root_store_and_protocol(
            upstream,
            configured_protocol,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
        )
    }

    pub fn with_root_store(
        upstream: UpstreamBase,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::with_root_store_and_protocol(
            upstream,
            UpstreamProtocol::Http1,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
        )
    }

    pub fn with_root_store_and_protocol(
        upstream: UpstreamBase,
        configured_protocol: UpstreamProtocol,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
    ) -> Result<Self, BoxError> {
        Self::with_root_store_and_resolver_protocol(
            upstream,
            configured_protocol,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
            Arc::new(SystemHostResolver),
            Arc::new(ResolverAccounting::default()),
        )
    }

    #[cfg(test)]
    pub(crate) fn with_root_store_and_resolver(
        upstream: UpstreamBase,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        resolver: Arc<dyn HostResolver>,
        resolver_accounting: Arc<ResolverAccounting>,
    ) -> Result<Self, BoxError> {
        Self::with_root_store_and_resolver_protocol(
            upstream,
            UpstreamProtocol::Http1,
            roots,
            max_active_upstreams,
            max_blocking_resolvers,
            resolver,
            resolver_accounting,
        )
    }

    pub(crate) fn with_root_store_and_resolver_protocol(
        upstream: UpstreamBase,
        configured_protocol: UpstreamProtocol,
        roots: RootCertStore,
        max_active_upstreams: usize,
        max_blocking_resolvers: usize,
        resolver: Arc<dyn HostResolver>,
        resolver_accounting: Arc<ResolverAccounting>,
    ) -> Result<Self, BoxError> {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connect_uri = format!("{}://{}/", upstream.scheme(), upstream.authority()).parse()?;
        Ok(Self {
            upstream,
            configured_protocol,
            connect_uri,
            tls,
            idle: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(Semaphore::new(max_active_upstreams)),
            active_limit: max_active_upstreams,
            resolvers: Arc::new(Semaphore::new(max_blocking_resolvers)),
            resolver,
            resolver_accounting,
            connect_timeout: CONNECT_TIMEOUT,
            driver_accounting: Arc::new(DriverRetirementAccounting::default()),
            next_generation: Arc::new(AtomicU64::new(1)),
        })
    }

    #[cfg(test)]
    pub(crate) fn resolver_accounting(&self) -> Arc<ResolverAccounting> {
        Arc::clone(&self.resolver_accounting)
    }

    #[cfg(test)]
    pub(crate) fn idle_owner_count(&self) -> usize {
        self.idle
            .lock()
            .expect("idle owner pool")
            .iter()
            .filter(|entry| matches!(entry, PoolEntry::H1(_)))
            .count()
    }

    #[cfg(test)]
    pub(crate) fn occupy_resolver_for_test(&self) -> ResolverOccupancy {
        let permit = Arc::clone(&self.resolvers)
            .try_acquire_owned()
            .expect("resolver fixture capacity");
        ResolverOccupancy {
            _permit: TrackedResolverPermit::new(permit, Arc::clone(&self.resolver_accounting)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward(
        &self,
        mut request: Request<Incoming>,
        path_and_query: &str,
        public_authority: HeaderValue,
        client_ip: ClientIp,
        public_proto: &str,
        identity: ProxyIdentity,
        renewal: Option<String>,
        close_downstream: bool,
        websocket: Option<WebSocketRequest>,
        downstream_lease: DownstreamLease,
        downstream_stream_lease: Option<DownstreamStreamLease>,
    ) -> Result<Response<GatewayBody>, ProxyError> {
        let active_permit = Arc::clone(&self.active)
            .try_acquire_owned()
            .map_err(|_| ProxyError::Capacity(CapacityClass::ActiveUpstream))?;
        let mut selected = self.select_exchange(active_permit).await?;
        selected.ready().await?;
        let actual_protocol = selected.protocol();
        if websocket.is_some()
            && actual_protocol == ActualProtocol::Http2
            && !selected
                .h2_extended_connect_enabled()
                .ok_or(ProxyError::Internal)?
        {
            // Candidate selection is closed: never inspect or fall through to
            // an idle H1 owner after reserving this H2 generation.
            return Err(ProxyError::BadGateway);
        }
        let prepared_websocket = websocket
            .as_ref()
            .map(|request| prepare_websocket(request, actual_protocol))
            .transpose()?;
        let downstream_upgrade = websocket.as_ref().map(|_| hyper::upgrade::on(&mut request));
        let tunnel_stream_lease = websocket
            .as_ref()
            .and_then(|_| downstream_stream_lease.clone());
        let upstream_path = compose_path(self.upstream.path_prefix(), path_and_query)?;
        match prepared_websocket.as_ref() {
            Some(prepared) => set_websocket_upstream_target(
                &mut request,
                &self.upstream,
                &upstream_path,
                prepared,
            )?,
            None => set_upstream_target(
                &mut request,
                &self.upstream,
                &upstream_path,
                actual_protocol,
            )?,
        }
        sanitize_request_headers(
            request.headers_mut(),
            public_authority,
            client_ip,
            public_proto,
            &identity,
            websocket.is_some(),
            actual_protocol,
        )?;
        if let Some(key) = prepared_websocket
            .as_ref()
            .and_then(|prepared| prepared.upstream_key.as_deref())
        {
            request.headers_mut().insert(
                "sec-websocket-key",
                HeaderValue::from_str(key).map_err(|_| ProxyError::Internal)?,
            );
        }

        let exchange = selected.into_latch();
        let mut response_half = ResponseHalfGuard::new(Arc::clone(&exchange));
        let (parts, body) = request.into_parts();
        let upload = Arc::new(UploadState::default());
        let mut upload_cancellation = UploadCancellationGuard::new(Arc::clone(&upload));
        let dispatch_kind = if websocket.is_some() && actual_protocol == ActualProtocol::Http2 {
            H2DispatchKind::ExtendedConnect
        } else {
            H2DispatchKind::Ordinary
        };
        let upstream_request = Request::from_parts(
            parts,
            TrackedRequestBody::new(
                body,
                Arc::clone(&upload),
                Arc::clone(&exchange),
                downstream_stream_lease,
            ),
        );
        let mut upstream_response = match exchange.dispatch(upstream_request, dispatch_kind).await {
            Ok(response) => response,
            Err(error) => {
                response_half
                    .take()
                    .response_done(false, RetirementReason::SendFailure);
                return Err(error);
            }
        };
        let upload_complete = upload.is_complete();
        if !upload_complete {
            upload.cancel();
        }
        upload_cancellation.disarm();

        if let (Some(metadata), Some(prepared)) = (websocket.as_ref(), prepared_websocket.as_ref())
        {
            let downstream_upgrade = downstream_upgrade.ok_or(ProxyError::Internal)?;
            match prepared.bridge.upstream() {
                ActualProtocol::Http1 => {
                    if validate_websocket_upstream_response(&upstream_response, metadata, prepared)
                        .is_err()
                    {
                        response_half
                            .take()
                            .response_done(false, RetirementReason::InvalidUpgrade);
                        return Err(ProxyError::BadGateway);
                    }
                    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
                    let response = match sanitize_websocket_response_head(
                        upstream_response,
                        renewal.as_deref(),
                        metadata,
                        prepared,
                    ) {
                        Ok(response) => response,
                        Err(error) => {
                            response_half
                                .take()
                                .response_done(false, RetirementReason::InvalidUpgrade);
                            return Err(error);
                        }
                    };
                    let exchange = response_half.take();
                    exchange.drop_h1_sender();
                    let bridge = PendingBridgeGuard::new(
                        downstream_upgrade,
                        upstream_upgrade,
                        exchange,
                        downstream_lease,
                        tunnel_stream_lease,
                    );
                    tokio::spawn(bridge_upgrades(bridge));
                    return Ok(response);
                }
                ActualProtocol::Http2 => {
                    if upstream_response.status() != StatusCode::OK {
                        response_half
                            .take()
                            .response_done(false, RetirementReason::InvalidUpgrade);
                        return Err(ProxyError::BadGateway);
                    }
                    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
                    let candidate = H2UpgradeCandidate::new(
                        upstream_upgrade,
                        response_half.take(),
                        downstream_lease,
                        tunnel_stream_lease,
                    );
                    validate_websocket_upstream_response(&upstream_response, metadata, prepared)?;
                    let response = sanitize_websocket_response_head(
                        upstream_response,
                        renewal.as_deref(),
                        metadata,
                        prepared,
                    )?;
                    let bridge = candidate.into_bridge(downstream_upgrade);
                    tokio::spawn(bridge_upgrades(bridge));
                    return Ok(response);
                }
            }
        }

        if upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
            response_half
                .take()
                .response_done(false, RetirementReason::InvalidUpgrade);
            return Err(ProxyError::BadGateway);
        }

        let reusable = actual_protocol == ActualProtocol::Http1
            && upstream_response.version() == Version::HTTP_11
            && !header_has_token(upstream_response.headers(), CONNECTION, "close")
            && upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS;
        let response = match sanitize_response_head(upstream_response, renewal.as_deref(), false) {
            Ok(response) => response,
            Err(error) => {
                response_half
                    .take()
                    .response_done(false, RetirementReason::NonReusableResponse);
                return Err(error);
            }
        };
        let (parts, body) = response.into_parts();
        let body = ExchangeResponseBody::new(body, response_half.take(), reusable)
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync();
        let mut response = Response::from_parts(parts, body);
        if close_downstream || !upload_complete {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        Ok(response)
    }

    async fn select_exchange(
        &self,
        active_permit: OwnedSemaphorePermit,
    ) -> Result<SelectedExchange, ProxyError> {
        let mut active_permit = Some(active_permit);
        let allow_h2 = matches!(
            self.configured_protocol,
            UpstreamProtocol::Auto | UpstreamProtocol::Http2
        );
        let allow_h1 = matches!(
            self.configured_protocol,
            UpstreamProtocol::Auto | UpstreamProtocol::Http1
        );

        let h2_candidates = if allow_h2 {
            self.idle
                .lock()
                .map_err(|_| ProxyError::Internal)?
                .iter()
                .filter_map(|entry| match entry {
                    PoolEntry::H2(generation) => Some(Arc::clone(generation)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for generation in h2_candidates {
            match generation.try_reserve() {
                H2ReserveResult::Reserved(reservation) => {
                    return Ok(SelectedExchange::new(ExchangeResource::H2(
                        H2ExchangeOwner {
                            reservation,
                            active_permit: active_permit.take(),
                            private_generation: false,
                        },
                    )));
                }
                H2ReserveResult::Closed => retire_h2_generation(&generation),
                H2ReserveResult::Saturated => {}
            }
        }

        if allow_h1 {
            let complete = {
                let mut pool = self.idle.lock().map_err(|_| ProxyError::Internal)?;
                pool.iter()
                    .position(|entry| matches!(entry, PoolEntry::H1(_)))
                    .map(|index| match pool.remove(index) {
                        PoolEntry::H1(complete) => complete,
                        _ => unreachable!(),
                    })
            };
            if let Some(complete) = complete {
                return Ok(SelectedExchange::new(ExchangeResource::H1 {
                    owner: ActiveOwner::new(
                        complete,
                        active_permit.take().expect("pooled H1 active permit"),
                    ),
                    pool: Arc::clone(&self.idle),
                }));
            }
        }

        self.connect(
            active_permit
                .take()
                .expect("fresh connection active permit"),
        )
        .await
    }

    async fn connect(
        &self,
        active_permit: OwnedSemaphorePermit,
    ) -> Result<SelectedExchange, ProxyError> {
        let deadline = Instant::now() + self.connect_timeout;
        let (candidates, active_permit) = match self.upstream.dial_target().host() {
            DialHost::Ip(address) => (
                vec![SocketAddr::new(
                    *address,
                    self.upstream.dial_target().port(),
                )],
                active_permit,
            ),
            DialHost::Domain(domain) => {
                let resolver_permit = match Arc::clone(&self.resolvers).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        self.resolver_accounting.trace("saturated");
                        return Err(ProxyError::Capacity(CapacityClass::BlockingResolver));
                    }
                };
                let resolver_permit = TrackedResolverPermit::new(
                    resolver_permit,
                    Arc::clone(&self.resolver_accounting),
                );
                self.resolver_accounting.trace("admitted");
                resolve_domain(
                    domain.clone(),
                    self.upstream.dial_target().port(),
                    active_permit,
                    resolver_permit,
                    deadline,
                    Arc::clone(&self.resolver),
                    Arc::clone(&self.resolver_accounting),
                )
                .await?
            }
        };
        let inner = ResolvedTcpConnector::new(candidates);
        let mut tls = self.tls.clone();
        tls.alpn_protocols = match (self.upstream.scheme(), self.configured_protocol) {
            ("https", UpstreamProtocol::Auto) => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            ("https", UpstreamProtocol::Http2) => vec![b"h2".to_vec()],
            _ => Vec::new(),
        };
        let mut connector: HttpsConnector<ResolvedTcpConnector> = HttpsConnector::new(
            inner,
            tls,
            false,
            Arc::new(DefaultServerNameResolver::default()),
        );
        let connect = timeout_at(deadline, connector.call(self.connect_uri.clone()));
        let (result, active_permit) = ActivePhase::new(connect, active_permit).await;
        let io = result
            .map_err(|_| ProxyError::BadGateway)?
            .map_err(|_| ProxyError::BadGateway)?;
        let selection =
            match select_actual_protocol(self.configured_protocol, self.upstream.scheme(), &io) {
                Ok(selection) => selection,
                Err(error) => {
                    tracing::info!(
                        event = "upstream_failure",
                        stage = "alpn",
                        outcome = "protocol_mismatch"
                    );
                    return Err(error);
                }
            };
        match selection.protocol {
            ActualProtocol::Http1 => {
                let handshake = timeout_at(deadline, http1::handshake::<_, RequestBody>(io));
                let (result, active_permit) = ActivePhase::new(handshake, active_permit).await;
                let (sender, connection) = result
                    .map_err(|_| ProxyError::BadGateway)?
                    .map_err(|_| ProxyError::BadGateway)?;
                let driver = tokio::spawn(async move {
                    if connection.with_upgrades().await.is_err() {
                        tracing::debug!(event = "upstream_connection", outcome = "closed");
                    }
                });
                emit_upstream_protocol_selected(self.configured_protocol, selection, None);
                Ok(SelectedExchange::new(ExchangeResource::H1 {
                    owner: ActiveOwner::new(
                        CompleteOwner::new(sender, driver, Arc::clone(&self.driver_accounting)),
                        active_permit,
                    ),
                    pool: Arc::clone(&self.idle),
                }))
            }
            ActualProtocol::Http2 => {
                self.connect_h2(io, active_permit, deadline, selection)
                    .await
            }
        }
    }

    async fn connect_h2(
        &self,
        io: UpstreamIo,
        active_permit: OwnedSemaphorePermit,
        deadline: Instant,
        selection: ActualSelection,
    ) -> Result<SelectedExchange, ProxyError> {
        let id = self.next_generation.fetch_add(1, Ordering::AcqRel);
        let control = GenerationControl::new(id);
        let proof = H2ProofState::new(Arc::clone(&control));
        let mut builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder.initial_max_send_streams(H2_LOCAL_STREAM_CAP);
        let handshake = timeout_at(
            deadline,
            builder.handshake::<_, RequestBody>(H2ProofIo::new(io, Arc::clone(&proof))),
        );
        let (result, active_permit) = ActivePhase::new(handshake, active_permit).await;
        let (sender, connection) = result
            .map_err(|_| ProxyError::BadGateway)?
            .map_err(|_| ProxyError::BadGateway)?;
        let mut gate = PrivateH2Gate::new(sender, connection, proof, active_permit);
        let settings = gate.prove(deadline).await?;
        let peer_limit = settings
            .max_concurrent_streams
            .map_or(usize::MAX, |limit| limit as usize);
        let limit = self.active_limit.min(H2_LOCAL_STREAM_CAP).min(peer_limit);
        if limit == 0 || gate.sender().is_closed() || !control.is_selectable() {
            tracing::info!(
                event = "upstream_failure",
                stage = "settings",
                protocol = "http2",
                outcome = "no_creator_capacity"
            );
            return Err(ProxyError::BadGateway);
        }

        let streams = Arc::new(Semaphore::new(limit));
        let (creator_sender, creator_permit) = reserve_h2_creator(gate.sender(), &streams)?;
        let (master_sender, connection, proof, active_permit) = gate.take();
        let driver_state = Arc::new(H2DriverState {
            control,
            published: AtomicBool::new(false),
            pool: Arc::downgrade(&self.idle),
            proof,
        });
        let generation = Arc::new(H2Generation {
            state: Arc::clone(&driver_state),
            master: Mutex::new(Some(master_sender)),
            streams,
        });
        let reservation = H2StreamReservation {
            generation: Arc::clone(&generation),
            sender: Some(creator_sender),
            _stream_permit: creator_permit,
        };

        let mut connection = Some(connection);
        let published = publish_h2_generation_slot(&self.idle, &generation);
        if published {
            spawn_h2_driver(
                connection.take().expect("private H2 connection"),
                Arc::clone(&driver_state),
            );
        }
        if let Some(connection) = connection {
            spawn_h2_driver(connection, Arc::clone(&driver_state));
        }
        emit_upstream_protocol_selected(
            self.configured_protocol,
            selection,
            Some((id, settings.extended_connect)),
        );
        Ok(SelectedExchange::new(ExchangeResource::H2(
            H2ExchangeOwner {
                reservation,
                active_permit: Some(active_permit),
                private_generation: !published,
            },
        )))
    }
}

struct ActivePhase<F> {
    future: Option<Pin<Box<F>>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<F> ActivePhase<F> {
    fn new(future: F, permit: OwnedSemaphorePermit) -> Self {
        Self {
            future: Some(Box::pin(future)),
            permit: Some(permit),
        }
    }
}

impl<F> Future for ActivePhase<F>
where
    F: Future,
{
    type Output = (F::Output, OwnedSemaphorePermit);

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let output = match this.future.as_mut() {
            Some(future) => match future.as_mut().poll(context) {
                Poll::Ready(output) => output,
                Poll::Pending => return Poll::Pending,
            },
            None => panic!("active phase polled after completion"),
        };
        this.future.take();
        Poll::Ready((
            output,
            this.permit.take().expect("active phase owns permit"),
        ))
    }
}

impl<F> Drop for ActivePhase<F> {
    fn drop(&mut self) {
        // Explicit field order: cancel/drop current I/O before returning U.
        self.future.take();
        self.permit.take();
    }
}

const RESOLVER_QUEUED: u8 = 0;
const RESOLVER_STARTED: u8 = 1;
const RESOLVER_FINISHED: u8 = 2;

type ResolverOutput = io::Result<Vec<SocketAddr>>;

pub(crate) trait HostResolver: Send + Sync {
    fn resolve(&self, domain: Box<str>, port: u16) -> ResolverOutput;
}

struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, domain: Box<str>, port: u16) -> ResolverOutput {
        (domain.as_ref(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
    }
}

#[derive(Default)]
pub(crate) struct ResolverAccounting {
    held_r: AtomicUsize,
    submitted_unobserved: AtomicUsize,
    request_owned: AtomicUsize,
    cleanup_owned: AtomicUsize,
    live_blocking: AtomicUsize,
    total_submitted: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResolverSnapshot {
    pub held_r: usize,
    pub submitted_unobserved: usize,
    pub request_owned: usize,
    pub cleanup_owned: usize,
    pub live_blocking: usize,
    pub total_submitted: usize,
}

impl ResolverAccounting {
    pub(crate) fn snapshot(&self) -> ResolverSnapshot {
        ResolverSnapshot {
            held_r: self.held_r.load(Ordering::Acquire),
            submitted_unobserved: self.submitted_unobserved.load(Ordering::Acquire),
            request_owned: self.request_owned.load(Ordering::Acquire),
            cleanup_owned: self.cleanup_owned.load(Ordering::Acquire),
            live_blocking: self.live_blocking.load(Ordering::Acquire),
            total_submitted: self.total_submitted.load(Ordering::Acquire),
        }
    }

    fn resolver_acquired(&self) {
        self.held_r.fetch_add(1, Ordering::AcqRel);
    }

    fn resolver_released(&self) {
        self.held_r.fetch_sub(1, Ordering::AcqRel);
    }

    fn submitted(&self) {
        self.submitted_unobserved.fetch_add(1, Ordering::AcqRel);
        self.request_owned.fetch_add(1, Ordering::AcqRel);
        self.total_submitted.fetch_add(1, Ordering::AcqRel);
    }

    fn request_to_cleanup(&self) {
        self.request_owned.fetch_sub(1, Ordering::AcqRel);
        self.cleanup_owned.fetch_add(1, Ordering::AcqRel);
    }

    fn request_joined(&self) {
        self.request_owned.fetch_sub(1, Ordering::AcqRel);
        self.submitted_unobserved.fetch_sub(1, Ordering::AcqRel);
    }

    fn cleanup_joined(&self) {
        self.cleanup_owned.fetch_sub(1, Ordering::AcqRel);
        self.submitted_unobserved.fetch_sub(1, Ordering::AcqRel);
    }

    fn blocking_started(&self) {
        self.live_blocking.fetch_add(1, Ordering::AcqRel);
    }

    fn blocking_finished(&self) {
        self.live_blocking.fetch_sub(1, Ordering::AcqRel);
    }

    fn trace(&self, outcome: &'static str) {
        let snapshot = self.snapshot();
        tracing::debug!(
            event = "resolver_accounting",
            outcome,
            held_r = snapshot.held_r,
            submitted_unobserved = snapshot.submitted_unobserved,
            request_owned = snapshot.request_owned,
            cleanup_owned = snapshot.cleanup_owned,
            live_blocking = snapshot.live_blocking,
            total_submitted = snapshot.total_submitted
        );
    }
}

struct TrackedResolverPermit {
    _permit: OwnedSemaphorePermit,
    accounting: Arc<ResolverAccounting>,
}

#[cfg(test)]
pub(crate) struct ResolverOccupancy {
    _permit: TrackedResolverPermit,
}

impl TrackedResolverPermit {
    fn new(permit: OwnedSemaphorePermit, accounting: Arc<ResolverAccounting>) -> Self {
        accounting.resolver_acquired();
        Self {
            _permit: permit,
            accounting,
        }
    }
}

impl Drop for TrackedResolverPermit {
    fn drop(&mut self) {
        self.accounting.resolver_released();
    }
}

struct LiveResolverGuard {
    accounting: Arc<ResolverAccounting>,
}

impl Drop for LiveResolverGuard {
    fn drop(&mut self) {
        self.accounting.blocking_finished();
    }
}

struct ResolutionParts {
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    handle: JoinHandle<ResolverOutput>,
    state: Arc<AtomicU8>,
    accounting: Arc<ResolverAccounting>,
}

struct ResolutionAttempt {
    parts: Option<ResolutionParts>,
}

impl ResolutionAttempt {
    fn new(parts: ResolutionParts) -> Self {
        Self { parts: Some(parts) }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<ResolverOutput> {
        &mut self.parts.as_mut().expect("resolution parts").handle
    }

    fn observed(mut self) -> OwnedSemaphorePermit {
        let parts = self.parts.take().expect("observed resolution parts");
        parts.accounting.request_joined();
        parts.accounting.trace("request_joined");
        tracing::debug!(
            event = "resolver_lifecycle",
            outcome = "joined",
            state = resolver_state(parts.state.load(Ordering::Acquire))
        );
        drop(parts.handle);
        drop(parts.resolver_permit);
        parts.active_permit
    }
}

impl Drop for ResolutionAttempt {
    fn drop(&mut self) {
        if let Some(parts) = self.parts.take() {
            schedule_resolver_cleanup(parts);
        }
    }
}

async fn resolve_domain(
    domain: Box<str>,
    port: u16,
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    deadline: Instant,
    resolver: Arc<dyn HostResolver>,
    accounting: Arc<ResolverAccounting>,
) -> Result<(Vec<SocketAddr>, OwnedSemaphorePermit), ProxyError> {
    let mut attempt = submit_resolution_tracked(
        active_permit,
        resolver_permit,
        Arc::clone(&accounting),
        move || resolver.resolve(domain, port),
    );
    let joined = match timeout_at(deadline, attempt.handle_mut()).await {
        Ok(joined) => joined,
        Err(_) => return Err(ProxyError::BadGateway),
    };
    let active_permit = attempt.observed();
    let addresses = joined
        .map_err(|_| ProxyError::BadGateway)?
        .map_err(|_| ProxyError::BadGateway)?;
    if addresses.is_empty() {
        return Err(ProxyError::BadGateway);
    }
    Ok((addresses, active_permit))
}

#[cfg(test)]
fn submit_resolution<F>(
    active_permit: OwnedSemaphorePermit,
    resolver_permit: OwnedSemaphorePermit,
    operation: F,
) -> ResolutionAttempt
where
    F: FnOnce() -> ResolverOutput + Send + 'static,
{
    let accounting = Arc::new(ResolverAccounting::default());
    let resolver_permit = TrackedResolverPermit::new(resolver_permit, Arc::clone(&accounting));
    submit_resolution_tracked(active_permit, resolver_permit, accounting, operation)
}

fn submit_resolution_tracked<F>(
    active_permit: OwnedSemaphorePermit,
    resolver_permit: TrackedResolverPermit,
    accounting: Arc<ResolverAccounting>,
    operation: F,
) -> ResolutionAttempt
where
    F: FnOnce() -> ResolverOutput + Send + 'static,
{
    let state = Arc::new(AtomicU8::new(RESOLVER_QUEUED));
    let task_state = Arc::clone(&state);
    accounting.submitted();
    accounting.trace("submitted");
    let task_accounting = Arc::clone(&accounting);
    let handle = tokio::task::spawn_blocking(move || {
        task_state.store(RESOLVER_STARTED, Ordering::Release);
        task_accounting.blocking_started();
        let _live = LiveResolverGuard {
            accounting: Arc::clone(&task_accounting),
        };
        let result = operation();
        task_state.store(RESOLVER_FINISHED, Ordering::Release);
        result
    });
    tracing::debug!(event = "resolver_lifecycle", outcome = "submitted");
    ResolutionAttempt::new(ResolutionParts {
        active_permit,
        resolver_permit,
        handle,
        state,
        accounting,
    })
}

fn resolver_state(state: u8) -> &'static str {
    match state {
        RESOLVER_QUEUED => "queued",
        RESOLVER_STARTED => "started",
        RESOLVER_FINISHED => "finished",
        _ => "unknown",
    }
}

fn schedule_resolver_cleanup(parts: ResolutionParts) {
    parts.accounting.request_to_cleanup();
    parts.accounting.trace("cleanup_owned");
    parts.handle.abort();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // The returned JoinHandle is intentionally private and detached.
            // No request or bridge can cancel this bounded cleanup task; the
            // only remaining cancellation boundary is runtime/process exit.
            handle.spawn(async move {
                let mut parts = parts;
                let _ = (&mut parts.handle).await;
                parts.accounting.cleanup_joined();
                parts.accounting.trace("cleanup_joined");
                tracing::debug!(
                    event = "resolver_lifecycle",
                    outcome = "cleanup_joined",
                    state = resolver_state(parts.state.load(Ordering::Acquire))
                );
                // Field order is explicit: handle observation precedes R/U.
                drop(parts.handle);
                drop(parts.resolver_permit);
                drop(parts.active_permit);
            });
        }
        Err(_) => {
            // Runtime teardown is fail-closed: never release U/R without join
            // observation. Process exit will reclaim the bounded resources.
            std::mem::forget(parts);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum RetirementReason {
    RequestCancellation,
    ReadyFailure,
    SendFailure,
    InvalidUpgrade,
    ResponseBodyError,
    ResponseBodyDrop,
    NonReusableResponse,
    PoolReadyTimeout,
    PoolReadyFailure,
    PoolFull,
    PoolPoisoned,
    UpgradeFailure,
    WebSocketClosed,
    WebSocketError,
    WebSocketCancellation,
    IdleOwnerDrop,
}

const RETIREMENT_REASON_COUNT: usize = RetirementReason::IdleOwnerDrop as usize + 1;

impl RetirementReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestCancellation => "request_cancellation",
            Self::ReadyFailure => "ready_failure",
            Self::SendFailure => "send_failure",
            Self::InvalidUpgrade => "invalid_upgrade",
            Self::ResponseBodyError => "response_body_error",
            Self::ResponseBodyDrop => "response_body_drop",
            Self::NonReusableResponse => "non_reusable_response",
            Self::PoolReadyTimeout => "pool_ready_timeout",
            Self::PoolReadyFailure => "pool_ready_failure",
            Self::PoolFull => "pool_full",
            Self::PoolPoisoned => "pool_poisoned",
            Self::UpgradeFailure => "upgrade_failure",
            Self::WebSocketClosed => "websocket_closed",
            Self::WebSocketError => "websocket_error",
            Self::WebSocketCancellation => "websocket_cancellation",
            Self::IdleOwnerDrop => "idle_owner_drop",
        }
    }
}

struct DriverRetirementAccounting {
    started: [AtomicUsize; RETIREMENT_REASON_COUNT],
    joined: [AtomicUsize; RETIREMENT_REASON_COUNT],
    active_cleanups: AtomicUsize,
}

impl Default for DriverRetirementAccounting {
    fn default() -> Self {
        Self {
            started: std::array::from_fn(|_| AtomicUsize::new(0)),
            joined: std::array::from_fn(|_| AtomicUsize::new(0)),
            active_cleanups: AtomicUsize::new(0),
        }
    }
}

impl DriverRetirementAccounting {
    fn started(&self, reason: RetirementReason) {
        self.started[reason as usize].fetch_add(1, Ordering::AcqRel);
        self.active_cleanups.fetch_add(1, Ordering::AcqRel);
        tracing::debug!(
            event = "driver_retirement",
            reason = reason.as_str(),
            outcome = "started",
            active_cleanups = self.active_cleanups.load(Ordering::Acquire)
        );
    }

    fn joined(&self, reason: RetirementReason) {
        self.joined[reason as usize].fetch_add(1, Ordering::AcqRel);
        self.active_cleanups.fetch_sub(1, Ordering::AcqRel);
        tracing::debug!(
            event = "driver_retirement",
            reason = reason.as_str(),
            outcome = "joined",
            active_cleanups = self.active_cleanups.load(Ordering::Acquire)
        );
    }

    #[cfg(test)]
    fn counts(&self, reason: RetirementReason) -> (usize, usize) {
        (
            self.started[reason as usize].load(Ordering::Acquire),
            self.joined[reason as usize].load(Ordering::Acquire),
        )
    }
}

struct CompleteOwner {
    sender: Option<H1Sender>,
    driver: Option<JoinHandle<()>>,
    accounting: Arc<DriverRetirementAccounting>,
}

impl CompleteOwner {
    fn new(
        sender: H1Sender,
        driver: JoinHandle<()>,
        accounting: Arc<DriverRetirementAccounting>,
    ) -> Self {
        Self {
            sender: Some(sender),
            driver: Some(driver),
            accounting,
        }
    }

    fn retirement_parts(
        mut self,
        permit: Option<OwnedSemaphorePermit>,
        reason: RetirementReason,
    ) -> RetirementParts {
        RetirementParts {
            sender: self.sender.take(),
            driver: self.driver.take().expect("complete owner driver"),
            _permit: permit,
            reason,
            accounting: Arc::clone(&self.accounting),
            started: false,
        }
    }
}

impl Drop for CompleteOwner {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            schedule_retirement(RetirementParts {
                sender: self.sender.take(),
                driver,
                _permit: None,
                reason: RetirementReason::IdleOwnerDrop,
                accounting: Arc::clone(&self.accounting),
                started: false,
            });
        }
    }
}

struct ActiveOwner {
    complete: Option<CompleteOwner>,
    permit: Option<OwnedSemaphorePermit>,
    retirement_reason: RetirementReason,
}

impl ActiveOwner {
    fn new(complete: CompleteOwner, permit: OwnedSemaphorePermit) -> Self {
        Self {
            complete: Some(complete),
            permit: Some(permit),
            retirement_reason: RetirementReason::RequestCancellation,
        }
    }

    fn sender_mut(&mut self) -> Option<&mut H1Sender> {
        self.complete.as_mut()?.sender.as_mut()
    }

    fn take_sender(&mut self) -> Option<H1Sender> {
        self.complete.as_mut()?.sender.take()
    }

    fn put_sender(&mut self, sender: H1Sender) {
        if let Some(complete) = self.complete.as_mut() {
            complete.sender = Some(sender);
        }
    }

    fn drop_sender(&mut self) {
        if let Some(complete) = self.complete.as_mut() {
            complete.sender.take();
        }
    }

    fn set_retirement_reason(&mut self, reason: RetirementReason) {
        self.retirement_reason = reason;
    }

    fn retirement_parts(mut self, reason: RetirementReason) -> RetirementParts {
        let permit = self.permit.take().expect("active owner permit");
        self.complete
            .take()
            .expect("active complete owner")
            .retirement_parts(Some(permit), reason)
    }

    fn idle_parts(mut self) -> (CompleteOwner, OwnedSemaphorePermit) {
        (
            self.complete.take().expect("active complete owner"),
            self.permit.take().expect("active owner permit"),
        )
    }
}

impl Drop for ActiveOwner {
    fn drop(&mut self) {
        if let (Some(complete), Some(permit)) = (self.complete.take(), self.permit.take()) {
            schedule_retirement(complete.retirement_parts(Some(permit), self.retirement_reason));
        }
    }
}

struct RetirementParts {
    sender: Option<H1Sender>,
    driver: JoinHandle<()>,
    _permit: Option<OwnedSemaphorePermit>,
    reason: RetirementReason,
    accounting: Arc<DriverRetirementAccounting>,
    started: bool,
}

impl RetirementParts {
    fn mark_started(&mut self) {
        if !self.started {
            self.accounting.started(self.reason);
            self.started = true;
        }
    }

    fn mark_joined(&self) {
        self.accounting.joined(self.reason);
    }
}

struct RetirementGuard {
    parts: Option<RetirementParts>,
}

impl RetirementGuard {
    fn new(parts: RetirementParts) -> Self {
        Self { parts: Some(parts) }
    }

    fn finish(mut self) {
        self.parts.take();
    }
}

impl Drop for RetirementGuard {
    fn drop(&mut self) {
        if let Some(parts) = self.parts.take() {
            schedule_retirement(parts);
        }
    }
}

fn schedule_retirement(mut parts: RetirementParts) {
    parts.mark_started();
    parts.sender.take();
    parts.driver.abort();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // This cleanup handle is never exposed, so request/bridge
            // cancellation cannot abort it. Runtime exit is the fail-stop
            // boundary and reclaims the process transport.
            handle.spawn(async move {
                let _ = (&mut parts.driver).await;
                parts.mark_joined();
                drop(parts.driver);
                drop(parts._permit);
            });
        }
        Err(_) => {
            // Preserve fail-closed capacity during runtime teardown rather than
            // releasing a permit before driver observation.
            std::mem::forget(parts);
        }
    }
}

fn retire_parts(parts: RetirementParts) -> impl Future<Output = ()> + Send {
    // As with resolver cleanup, make cancellation safe even before first poll.
    let mut parts = parts;
    parts.mark_started();
    let mut guard = RetirementGuard::new(parts);
    async move {
        let parts = guard.parts.as_mut().expect("retirement parts");
        parts.sender.take();
        parts.driver.abort();
        let _ = (&mut parts.driver).await;
        parts.mark_joined();
        guard.finish();
    }
}

async fn retire_active_owner(owner: ActiveOwner, reason: RetirementReason) {
    retire_parts(owner.retirement_parts(reason)).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolReadinessOutcome {
    Ready,
    Timeout,
    Failure,
}

impl PoolReadinessOutcome {
    const fn retirement_reason(self) -> Option<RetirementReason> {
        match self {
            Self::Ready => None,
            Self::Timeout => Some(RetirementReason::PoolReadyTimeout),
            Self::Failure => Some(RetirementReason::PoolReadyFailure),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoolPlacementOutcome {
    Parked,
    Full,
    Poisoned,
}

impl PoolPlacementOutcome {
    const fn retirement_reason(self) -> Option<RetirementReason> {
        match self {
            Self::Parked => None,
            Self::Full => Some(RetirementReason::PoolFull),
            Self::Poisoned => Some(RetirementReason::PoolPoisoned),
        }
    }
}

async fn park_or_retire(mut owner: ActiveOwner, pool: OwnerPool) {
    let readiness = match owner.sender_mut() {
        Some(sender) => match timeout(SENDER_READY_TIMEOUT, sender.ready()).await {
            Ok(Ok(())) => PoolReadinessOutcome::Ready,
            Ok(Err(_)) => PoolReadinessOutcome::Failure,
            Err(_) => PoolReadinessOutcome::Timeout,
        },
        None => PoolReadinessOutcome::Failure,
    };
    if let Some(reason) = readiness.retirement_reason() {
        retire_active_owner(owner, reason).await;
        return;
    }

    let (complete, permit) = owner.idle_parts();
    let mut complete = Some(complete);
    let placement = {
        match pool.lock() {
            Ok(mut idle) if idle.len() < UPSTREAM_IDLE_POOL_CAPACITY => {
                idle.push(PoolEntry::H1(
                    complete.take().expect("complete owner available"),
                ));
                PoolPlacementOutcome::Parked
            }
            Ok(_) => PoolPlacementOutcome::Full,
            Err(_) => PoolPlacementOutcome::Poisoned,
        }
    };
    if placement == PoolPlacementOutcome::Parked {
        // Atomic park: the complete owner is visible in the pool before U is
        // returned, and no await occurs while the pool is locked.
        drop(permit);
    } else {
        let reason = placement
            .retirement_reason()
            .expect("unparked retirement reason");
        retire_parts(
            complete
                .take()
                .expect("unparked complete owner")
                .retirement_parts(Some(permit), reason),
        )
        .await;
    }
}

pub fn full_body(bytes: impl Into<Bytes>) -> GatewayBody {
    Full::new(bytes.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn empty_body() -> GatewayBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn parse_connection_tokens(headers: &HeaderMap) -> Result<HashSet<HeaderName>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all(CONNECTION) {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(ProxyError::BadRequest);
            }
            names.insert(
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| ProxyError::BadRequest)?,
            );
        }
    }
    Ok(names)
}

pub(crate) fn parse_websocket_request(
    request: &Request<Incoming>,
) -> Result<Option<WebSocketRequest>, WebSocketRequestError> {
    let extended_protocol = request.extensions().get::<hyper::ext::Protocol>();
    if request.method() == Method::CONNECT {
        if request.version() != Version::HTTP_2 {
            return Err(WebSocketRequestError::MethodNotAllowed);
        }
        let Some(protocol) = extended_protocol else {
            return Err(WebSocketRequestError::MethodNotAllowed);
        };
        if protocol.as_ref() != b"websocket" {
            return Err(WebSocketRequestError::MethodNotAllowed);
        }
        validate_h2_websocket_request(request).map_err(|_| WebSocketRequestError::BadRequest)?;
        return Ok(Some(WebSocketRequest {
            downstream: DownstreamWebSocket::Http2,
            protocols: parse_protocols(request.headers())
                .map_err(|_| WebSocketRequestError::BadRequest)?,
            extension_names: parse_extensions(request.headers())
                .map_err(|_| WebSocketRequestError::BadRequest)?,
        }));
    }
    if extended_protocol.is_some() {
        return Err(WebSocketRequestError::MethodNotAllowed);
    }

    let upgrade_values: Vec<_> = request.headers().get_all(UPGRADE).iter().collect();
    let connection_tokens = parse_connection_tokens(request.headers())
        .map_err(|_| WebSocketRequestError::BadRequest)?;
    let has_upgrade_token = connection_tokens.contains(&UPGRADE);
    if !has_upgrade_token && upgrade_values.is_empty() {
        if websocket_handshake_headers_present(request.headers()) {
            return Err(WebSocketRequestError::BadRequest);
        }
        return Ok(None);
    }
    if !has_upgrade_token || upgrade_values.len() != 1 {
        return Err(WebSocketRequestError::BadRequest);
    }
    for handshake in [
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-version"),
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
        HeaderName::from_static("origin"),
    ] {
        if request.headers().contains_key(&handshake) && connection_tokens.contains(&handshake) {
            return Err(WebSocketRequestError::BadRequest);
        }
    }
    if request.headers().contains_key("sec-websocket-accept") {
        return Err(WebSocketRequestError::BadRequest);
    }
    if !upgrade_values[0]
        .to_str()
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(WebSocketRequestError::BadRequest);
    }
    if request.method() != Method::GET
        || request.version() != Version::HTTP_11
        || !request.body().is_end_stream()
    {
        return Err(WebSocketRequestError::BadRequest);
    }
    let version = exactly_one(request.headers(), "sec-websocket-version")
        .map_err(|_| WebSocketRequestError::BadRequest)?;
    if version.as_bytes() != b"13" {
        return Err(WebSocketRequestError::BadRequest);
    }
    let key = exactly_one(request.headers(), "sec-websocket-key")
        .map_err(|_| WebSocketRequestError::BadRequest)?
        .to_str()
        .map_err(|_| WebSocketRequestError::BadRequest)?;
    if key != key.trim() {
        return Err(WebSocketRequestError::BadRequest);
    }
    let decoded = STANDARD
        .decode(key.as_bytes())
        .map_err(|_| WebSocketRequestError::BadRequest)?;
    if decoded.len() != 16 || STANDARD.encode(decoded) != key {
        return Err(WebSocketRequestError::BadRequest);
    }
    validate_websocket_origin(request.headers()).map_err(|_| WebSocketRequestError::BadRequest)?;
    let protocols =
        parse_protocols(request.headers()).map_err(|_| WebSocketRequestError::BadRequest)?;
    let extension_names =
        parse_extensions(request.headers()).map_err(|_| WebSocketRequestError::BadRequest)?;
    Ok(Some(WebSocketRequest {
        downstream: DownstreamWebSocket::Http1 {
            key: key.to_string(),
        },
        protocols,
        extension_names,
    }))
}

fn websocket_handshake_headers_present(headers: &HeaderMap) -> bool {
    [
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
        "sec-websocket-accept",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

fn validate_h2_websocket_request(request: &Request<Incoming>) -> Result<(), ProxyError> {
    if !matches!(request.uri().scheme_str(), Some("http" | "https"))
        || request.uri().authority().is_none()
        || !request
            .uri()
            .path_and_query()
            .is_some_and(|value| value.as_str().starts_with('/'))
        || !request.body().is_end_stream()
    {
        return Err(ProxyError::BadRequest);
    }
    validate_h2_websocket_content_length(request.headers())?;
    for forbidden in [
        HOST,
        CONNECTION,
        UPGRADE,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        TRANSFER_ENCODING,
        TE,
        TRAILER,
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-accept"),
    ] {
        if request.headers().contains_key(forbidden) {
            return Err(ProxyError::BadRequest);
        }
    }
    let version = exactly_one(request.headers(), "sec-websocket-version")?;
    if version.as_bytes() != b"13" {
        return Err(ProxyError::BadRequest);
    }
    validate_websocket_origin(request.headers())?;
    parse_protocols(request.headers())?;
    parse_extensions(request.headers())?;
    Ok(())
}

fn validate_h2_websocket_content_length(headers: &HeaderMap) -> Result<(), ProxyError> {
    let mut parsed = None;
    for line in headers.get_all(CONTENT_LENGTH) {
        let line = line.to_str().map_err(|_| ProxyError::BadRequest)?;
        for value in line.split(',') {
            let value = value.trim().as_bytes();
            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(ProxyError::BadRequest);
            }
            let value = value.iter().try_fold(0_u64, |number, digit| {
                number
                    .checked_mul(10)?
                    .checked_add(u64::from(*digit - b'0'))
            });
            let value = value.ok_or(ProxyError::BadRequest)?;
            match parsed {
                None => parsed = Some(value),
                Some(existing) if existing == value => {}
                Some(_) => return Err(ProxyError::BadRequest),
            }
        }
    }
    if parsed.is_none_or(|value| value == 0) {
        Ok(())
    } else {
        // Pinned Hyper intercepts this branch before service. Keep this check
        // fail-closed for any synthetic/service-delivered request.
        Err(ProxyError::BadRequest)
    }
}

fn validate_websocket_origin(headers: &HeaderMap) -> Result<(), ProxyError> {
    let values: Vec<_> = headers.get_all("origin").iter().collect();
    let Some(value) = values.first() else {
        return Ok(());
    };
    if values.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
    if value == "null" {
        return Ok(());
    }
    let uri = value.parse::<Uri>().map_err(|_| ProxyError::BadRequest)?;
    let authority = uri.authority().ok_or(ProxyError::BadRequest)?;
    if uri.scheme().is_none()
        || authority.as_str().contains('@')
        || uri
            .path_and_query()
            .is_some_and(|path| !matches!(path.as_str(), "" | "/"))
    {
        return Err(ProxyError::BadRequest);
    }
    Ok(())
}

fn compose_path(prefix: &str, path_and_query: &str) -> Result<String, ProxyError> {
    if !path_and_query.starts_with('/') {
        return Err(ProxyError::BadRequest);
    }
    Ok(format!("{prefix}{path_and_query}"))
}

fn set_upstream_target(
    request: &mut Request<Incoming>,
    upstream: &UpstreamBase,
    path_and_query: &str,
    protocol: ActualProtocol,
) -> Result<(), ProxyError> {
    match protocol {
        ActualProtocol::Http1 => {
            *request.uri_mut() = path_and_query
                .parse::<Uri>()
                .map_err(|_| ProxyError::Internal)?;
            *request.version_mut() = Version::HTTP_11;
        }
        ActualProtocol::Http2 => {
            *request.uri_mut() = format!(
                "{}://{}{}",
                upstream.scheme(),
                upstream.authority(),
                path_and_query
            )
            .parse::<Uri>()
            .map_err(|_| ProxyError::Internal)?;
            *request.version_mut() = Version::HTTP_2;
        }
    }
    Ok(())
}

fn prepare_websocket(
    request: &WebSocketRequest,
    upstream: ActualProtocol,
) -> Result<PreparedWebSocket, ProxyError> {
    let bridge = WebSocketBridge::new(request.downstream_protocol(), upstream);
    let upstream_key = match bridge {
        WebSocketBridge::H1ToH1 => Some(
            request
                .downstream_key()
                .ok_or(ProxyError::Internal)?
                .to_string(),
        ),
        WebSocketBridge::H2ToH1 => Some(generate_websocket_key()?),
        WebSocketBridge::H1ToH2 | WebSocketBridge::H2ToH2 => None,
    };
    Ok(PreparedWebSocket {
        bridge,
        upstream_key,
    })
}

fn generate_websocket_key() -> Result<String, ProxyError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ProxyError::Internal)?;
    Ok(STANDARD.encode(bytes))
}

fn set_websocket_upstream_target(
    request: &mut Request<Incoming>,
    upstream: &UpstreamBase,
    path_and_query: &str,
    prepared: &PreparedWebSocket,
) -> Result<(), ProxyError> {
    set_upstream_target(
        request,
        upstream,
        path_and_query,
        prepared.bridge.upstream(),
    )?;
    request.extensions_mut().remove::<hyper::ext::Protocol>();
    match prepared.bridge.upstream() {
        ActualProtocol::Http1 => {
            *request.method_mut() = Method::GET;
        }
        ActualProtocol::Http2 => {
            *request.method_mut() = Method::CONNECT;
            request
                .extensions_mut()
                .insert(hyper::ext::Protocol::from_static("websocket"));
        }
    }
    Ok(())
}

fn sanitize_request_headers(
    headers: &mut HeaderMap,
    public_authority: HeaderValue,
    client_ip: ClientIp,
    public_proto: &str,
    identity: &ProxyIdentity,
    websocket: bool,
    protocol: ActualProtocol,
) -> Result<(), ProxyError> {
    let nominated = parse_connection_tokens(headers)?;
    for name in nominated {
        headers.remove(name);
    }
    remove_fixed_hop_headers(headers);
    headers.remove(CONTENT_LENGTH);
    headers.remove(COOKIE);
    headers.remove(AUTHORIZATION);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    headers.remove("expect");
    remove_prefixed(headers, "x-auth-mini-");
    remove_prefixed(headers, "x-forwarded-");

    if protocol == ActualProtocol::Http1 {
        headers.insert(HOST, public_authority.clone());
    } else {
        headers.remove(HOST);
    }
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&client_ip.0.to_string()).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_str(public_proto).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert("x-forwarded-host", public_authority);
    headers.insert(
        "x-auth-mini-user-id",
        identity_header_value(&identity.user_id)?,
    );
    if let Some(email) = identity.email.as_deref() {
        headers.insert("x-auth-mini-email", identity_header_value(email)?);
    }
    if websocket && protocol == ActualProtocol::Http1 {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    } else if websocket {
        headers.remove("sec-websocket-key");
        headers.remove("sec-websocket-accept");
    }
    Ok(())
}

fn identity_header_value(value: &str) -> Result<HeaderValue, ProxyError> {
    if !is_safe_header_value(value) {
        return Err(ProxyError::Internal);
    }
    HeaderValue::from_bytes(value.as_bytes()).map_err(|_| ProxyError::Internal)
}

fn sanitize_response_head(
    response: Response<Incoming>,
    renewal: Option<&str>,
    websocket: bool,
) -> Result<Response<Incoming>, ProxyError> {
    let (mut parts, body) = response.into_parts();
    let nominated = parse_response_connection_tokens(&parts.headers)?;
    for name in nominated {
        parts.headers.remove(name);
    }
    remove_fixed_hop_headers(&mut parts.headers);
    parts.headers.remove(CONTENT_LENGTH);
    remove_prefixed(&mut parts.headers, "x-auth-mini-");
    filter_application_cookies(&mut parts.headers);
    if websocket {
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    if let Some(cookie) = renewal {
        parts.headers.append(
            SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(|_| ProxyError::Internal)?,
        );
    }
    Ok(Response::from_parts(parts, body))
}

fn parse_response_connection_tokens(
    headers: &HeaderMap,
) -> Result<HashSet<HeaderName>, ProxyError> {
    parse_connection_tokens(headers).map_err(|_| ProxyError::BadGateway)
}

fn remove_fixed_hop_headers(headers: &mut HeaderMap) {
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn remove_prefixed(headers: &mut HeaderMap, prefix: &str) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(prefix))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn filter_application_cookies(headers: &mut HeaderMap) {
    let values: Vec<_> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.remove(SET_COOKIE);
    for value in values {
        if is_allowed_application_cookie(&value) {
            headers.append(SET_COOKIE, value);
        }
    }
}

fn is_allowed_application_cookie(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    let bytes = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|start| &bytes[start..])
        .unwrap_or_default();
    let pair = bytes.split(|byte| *byte == b';').next().unwrap_or_default();
    let Some(equal) = pair.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let name = &pair[..equal];
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return false;
    }
    name != b"amg_session" && name != b"amg_login_state"
}

fn validate_websocket_upstream_response(
    response: &Response<Incoming>,
    request: &WebSocketRequest,
    prepared: &PreparedWebSocket,
) -> Result<(), ProxyError> {
    match prepared.bridge.upstream() {
        ActualProtocol::Http1 => validate_h1_websocket_response(
            response,
            request,
            prepared
                .upstream_key
                .as_deref()
                .ok_or(ProxyError::Internal)?,
        ),
        ActualProtocol::Http2 => validate_h2_websocket_response(response, request),
    }
}

fn validate_h1_websocket_response(
    response: &Response<Incoming>,
    request: &WebSocketRequest,
    upstream_key: &str,
) -> Result<(), ProxyError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || response.version() != Version::HTTP_11
        || !response.body().is_end_stream()
        || response.headers().contains_key("sec-websocket-key")
        || response.headers().contains_key("sec-websocket-version")
        || response.headers().contains_key("origin")
    {
        return Err(ProxyError::BadGateway);
    }
    let connection = parse_response_connection_tokens(response.headers())?;
    if !connection.contains(&UPGRADE) {
        return Err(ProxyError::BadGateway);
    }
    if connection.contains(&HeaderName::from_static("sec-websocket-accept")) {
        return Err(ProxyError::BadGateway);
    }
    for selected in [
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
    ] {
        if response.headers().contains_key(&selected) && connection.contains(&selected) {
            return Err(ProxyError::BadGateway);
        }
    }
    let upgrades: Vec<_> = response.headers().get_all(UPGRADE).iter().collect();
    if upgrades.len() != 1
        || !upgrades[0]
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ProxyError::BadGateway);
    }
    let accept = exactly_one(response.headers(), "sec-websocket-accept")
        .map_err(|_| ProxyError::BadGateway)?;
    if accept.as_bytes() != websocket_accept(upstream_key).as_bytes() {
        return Err(ProxyError::BadGateway);
    }
    validate_websocket_response_selections(response.headers(), request)
}

fn validate_h2_websocket_response(
    response: &Response<Incoming>,
    request: &WebSocketRequest,
) -> Result<(), ProxyError> {
    if response.status() != StatusCode::OK
        || response.version() != Version::HTTP_2
        || !response.body().is_end_stream()
    {
        return Err(ProxyError::BadGateway);
    }
    for forbidden in [
        CONNECTION,
        UPGRADE,
        CONTENT_LENGTH,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        TRANSFER_ENCODING,
        TE,
        TRAILER,
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-accept"),
        HeaderName::from_static("sec-websocket-version"),
        HeaderName::from_static("origin"),
        HOST,
    ] {
        if response.headers().contains_key(forbidden) {
            return Err(ProxyError::BadGateway);
        }
    }
    validate_websocket_response_selections(response.headers(), request)
}

fn validate_websocket_response_selections(
    headers: &HeaderMap,
    request: &WebSocketRequest,
) -> Result<(), ProxyError> {
    let selected: Vec<_> = headers.get_all("sec-websocket-protocol").iter().collect();
    if selected.len() > 1 {
        return Err(ProxyError::BadGateway);
    }
    if let Some(selected) = selected.first() {
        let selected = selected.to_str().map_err(|_| ProxyError::BadGateway)?;
        if selected.is_empty()
            || !selected.bytes().all(is_token_byte)
            || !request.protocols.iter().any(|offered| offered == selected)
        {
            return Err(ProxyError::BadGateway);
        }
    }
    let selected_extensions = parse_extensions(headers).map_err(|_| ProxyError::BadGateway)?;
    if !selected_extensions.is_subset(&request.extension_names) {
        return Err(ProxyError::BadGateway);
    }
    Ok(())
}

fn sanitize_websocket_response_head(
    response: Response<Incoming>,
    renewal: Option<&str>,
    request: &WebSocketRequest,
    prepared: &PreparedWebSocket,
) -> Result<Response<GatewayBody>, ProxyError> {
    let response = sanitize_response_head(response, renewal, false)?;
    let (mut parts, _) = response.into_parts();
    parts.headers.remove("sec-websocket-key");
    parts.headers.remove("sec-websocket-accept");
    parts.headers.remove("sec-websocket-version");
    parts.headers.remove("origin");
    parts.headers.remove(HOST);
    match prepared.bridge.downstream() {
        ActualProtocol::Http1 => {
            parts.status = StatusCode::SWITCHING_PROTOCOLS;
            parts.version = Version::HTTP_11;
            parts
                .headers
                .insert(CONNECTION, HeaderValue::from_static("upgrade"));
            parts
                .headers
                .insert(UPGRADE, HeaderValue::from_static("websocket"));
            let key = request.downstream_key().ok_or(ProxyError::Internal)?;
            parts.headers.insert(
                "sec-websocket-accept",
                HeaderValue::from_str(&websocket_accept(key)).map_err(|_| ProxyError::Internal)?,
            );
        }
        ActualProtocol::Http2 => {
            parts.status = StatusCode::OK;
            parts.version = Version::HTTP_2;
            remove_fixed_hop_headers(&mut parts.headers);
        }
    }
    Ok(Response::from_parts(parts, empty_body()))
}

fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finalize())
}

fn parse_protocols(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut protocols = Vec::new();
    let mut seen = HashSet::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for protocol in value.split(',') {
            let protocol = protocol.trim();
            if protocol.is_empty()
                || !protocol.bytes().all(is_token_byte)
                || !seen.insert(protocol.to_string())
            {
                return Err(ProxyError::BadRequest);
            }
            protocols.push(protocol.to_string());
        }
    }
    Ok(protocols)
}

fn parse_extensions(headers: &HeaderMap) -> Result<HashSet<String>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all("sec-websocket-extensions") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for extension in split_websocket_header(value, b',')? {
            let pieces = split_websocket_header(extension, b';')?;
            let name = pieces.first().copied().unwrap_or_default().trim();
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                return Err(ProxyError::BadRequest);
            }
            if !names.insert(name.to_ascii_lowercase()) {
                return Err(ProxyError::BadRequest);
            }
            let mut parameters = HashSet::new();
            for parameter in pieces.into_iter().skip(1) {
                let parameter = parameter.trim();
                if parameter.is_empty() {
                    return Err(ProxyError::BadRequest);
                }
                let (param_name, param_value) = parameter
                    .split_once('=')
                    .map_or((parameter, None), |(name, value)| {
                        (name.trim(), Some(value.trim()))
                    });
                if param_name.is_empty() || !param_name.bytes().all(is_token_byte) {
                    return Err(ProxyError::BadRequest);
                }
                if !parameters.insert(param_name.to_ascii_lowercase()) {
                    return Err(ProxyError::BadRequest);
                }
                if let Some(value) = param_value {
                    if value.is_empty()
                        || !(value.bytes().all(is_token_byte)
                            || valid_websocket_quoted_string(value))
                    {
                        return Err(ProxyError::BadRequest);
                    }
                }
            }
        }
    }
    Ok(names)
}

fn split_websocket_header(value: &str, delimiter: u8) -> Result<Vec<&str>, ProxyError> {
    let bytes = value.as_bytes();
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if quoted {
            if escaped {
                if byte != b'\t' && !(0x20..=0x7e).contains(&byte) {
                    return Err(ProxyError::BadRequest);
                }
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            } else if byte != b'\t'
                && !((0x20..=0x21).contains(&byte)
                    || (0x23..=0x5b).contains(&byte)
                    || (0x5d..=0x7e).contains(&byte))
            {
                return Err(ProxyError::BadRequest);
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == delimiter {
            pieces.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(ProxyError::BadRequest);
    }
    pieces.push(&value[start..]);
    Ok(pieces)
}

fn valid_websocket_quoted_string(value: &str) -> bool {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return false;
    }
    let mut escaped = false;
    for byte in value.as_bytes()[1..value.len() - 1].iter().copied() {
        if escaped {
            if byte != b'\t' && !(0x20..=0x7e).contains(&byte) {
                return false;
            }
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"'
            || (byte != b'\t'
                && !((0x20..=0x21).contains(&byte)
                    || (0x23..=0x5b).contains(&byte)
                    || (0x5d..=0x7e).contains(&byte)))
        {
            return false;
        }
    }
    !escaped
}

fn exactly_one<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a HeaderValue, ProxyError> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.len() == 1 {
        Ok(values[0])
    } else {
        Err(ProxyError::BadRequest)
    }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

struct H2UpgradeCandidate {
    upstream: Option<OnUpgrade>,
    exchange: Option<Arc<ExchangeLatch>>,
    downstream_lease: Option<DownstreamLease>,
    downstream_stream_lease: Option<DownstreamStreamLease>,
}

impl H2UpgradeCandidate {
    fn new(
        upstream: OnUpgrade,
        exchange: Arc<ExchangeLatch>,
        downstream_lease: DownstreamLease,
        downstream_stream_lease: Option<DownstreamStreamLease>,
    ) -> Self {
        Self {
            upstream: Some(upstream),
            exchange: Some(exchange),
            downstream_lease: Some(downstream_lease),
            downstream_stream_lease,
        }
    }

    fn into_bridge(mut self, downstream: OnUpgrade) -> PendingBridgeGuard {
        PendingBridgeGuard::new(
            downstream,
            self.upstream.take().expect("H2 candidate upstream upgrade"),
            self.exchange.take().expect("H2 candidate exchange"),
            self.downstream_lease
                .take()
                .expect("H2 candidate downstream lease"),
            self.downstream_stream_lease.take(),
        )
    }
}

impl Drop for H2UpgradeCandidate {
    fn drop(&mut self) {
        let Some(upstream) = self.upstream.take() else {
            return;
        };
        let cleanup = RejectedH2UpgradeCleanup::new(
            upstream,
            self.exchange.take(),
            self.downstream_lease.take(),
            self.downstream_stream_lease.take(),
        );
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(cleanup.run());
            }
            Err(_) => std::mem::forget(cleanup),
        }
    }
}

struct RejectedH2UpgradeCleanup {
    upstream: Option<OnUpgrade>,
    exchange: Option<Arc<ExchangeLatch>>,
    downstream_stream_lease: Option<DownstreamStreamLease>,
    downstream_lease: Option<DownstreamLease>,
    #[cfg(test)]
    before_upgraded_drop: Option<watch::Receiver<bool>>,
    #[cfg(test)]
    held_permits: Vec<OwnedSemaphorePermit>,
}

impl RejectedH2UpgradeCleanup {
    fn new(
        upstream: OnUpgrade,
        exchange: Option<Arc<ExchangeLatch>>,
        downstream_lease: Option<DownstreamLease>,
        downstream_stream_lease: Option<DownstreamStreamLease>,
    ) -> Self {
        Self {
            upstream: Some(upstream),
            exchange,
            downstream_stream_lease,
            downstream_lease,
            #[cfg(test)]
            before_upgraded_drop: None,
            #[cfg(test)]
            held_permits: Vec::new(),
        }
    }

    async fn run(mut self) {
        let upgraded = match self.upstream.take() {
            Some(upstream) => upstream.await.ok(),
            None => None,
        };
        #[cfg(test)]
        if let Some(mut gate) = self.before_upgraded_drop.take() {
            while !*gate.borrow() {
                if gate.changed().await.is_err() {
                    break;
                }
            }
        }
        // Reset/drop the rejected H2 stream before releasing U or either
        // stream/connection lease. This never retires the shared generation.
        drop(upgraded);
        self.finish();
    }

    fn finish(&mut self) {
        if let Some(exchange) = self.exchange.take() {
            exchange.response_done(false, RetirementReason::InvalidUpgrade);
        }
        self.downstream_stream_lease.take();
        self.downstream_lease.take();
        #[cfg(test)]
        self.held_permits.clear();
    }
}

impl Drop for RejectedH2UpgradeCleanup {
    fn drop(&mut self) {
        // If the detached cleanup is canceled, dropping OnUpgrade first
        // discards any already-fulfilled Upgraded value before permit release.
        self.upstream.take();
        self.finish();
    }
}

struct PendingBridgeGuard {
    downstream: Option<OnUpgrade>,
    upstream: Option<OnUpgrade>,
    exchange: Option<Arc<ExchangeLatch>>,
    downstream_stream_lease: Option<DownstreamStreamLease>,
    downstream_lease: Option<DownstreamLease>,
}

impl PendingBridgeGuard {
    fn new(
        downstream: OnUpgrade,
        upstream: OnUpgrade,
        exchange: Arc<ExchangeLatch>,
        downstream_lease: DownstreamLease,
        downstream_stream_lease: Option<DownstreamStreamLease>,
    ) -> Self {
        Self {
            downstream: Some(downstream),
            upstream: Some(upstream),
            exchange: Some(exchange),
            downstream_stream_lease,
            downstream_lease: Some(downstream_lease),
        }
    }

    async fn wait_for_upgrades(&mut self) -> Result<(Upgraded, Upgraded), hyper::Error> {
        let (downstream, upstream) = (&mut self.downstream, &mut self.upstream);
        tokio::try_join!(
            downstream.as_mut().expect("downstream upgrade"),
            upstream.as_mut().expect("upstream upgrade")
        )
    }

    fn mark_upgrade_failure(&mut self) {
        if let Some(exchange) = self.exchange.take() {
            exchange.response_done(false, RetirementReason::UpgradeFailure);
        }
    }

    fn into_active(mut self, downstream: Upgraded, upstream: Upgraded) -> ActiveBridgeGuard {
        self.downstream.take();
        self.upstream.take();
        ActiveBridgeGuard {
            downstream: Some(TokioIo::new(downstream)),
            upstream: Some(TokioIo::new(upstream)),
            exchange: self.exchange.take(),
            downstream_stream_lease: self.downstream_stream_lease.take(),
            downstream_lease: self.downstream_lease.take(),
        }
    }
}

impl Drop for PendingBridgeGuard {
    fn drop(&mut self) {
        // On cancellation, discard both upgrade futures before transport
        // retirement and release the downstream lease last.
        self.downstream.take();
        self.upstream.take();
        if let Some(exchange) = self.exchange.take() {
            exchange.response_done(false, RetirementReason::WebSocketCancellation);
        }
        self.downstream_stream_lease.take();
        self.downstream_lease.take();
    }
}

struct ActiveBridgeGuard {
    downstream: Option<TokioIo<Upgraded>>,
    upstream: Option<TokioIo<Upgraded>>,
    exchange: Option<Arc<ExchangeLatch>>,
    downstream_stream_lease: Option<DownstreamStreamLease>,
    downstream_lease: Option<DownstreamLease>,
}

impl ActiveBridgeGuard {
    fn streams(&mut self) -> (&mut TokioIo<Upgraded>, &mut TokioIo<Upgraded>) {
        (
            self.downstream.as_mut().expect("downstream bridge I/O"),
            self.upstream.as_mut().expect("upstream bridge I/O"),
        )
    }

    fn drop_streams(&mut self) {
        self.downstream.take();
        self.upstream.take();
    }

    fn finish_exchange(&mut self, reason: RetirementReason) {
        if let Some(exchange) = self.exchange.take() {
            exchange.response_done(false, reason);
        }
    }
}

impl Drop for ActiveBridgeGuard {
    fn drop(&mut self) {
        // This ordering also applies when copy_bidirectional or its parent task
        // is canceled: upgraded I/O closes before U retirement and D release.
        self.drop_streams();
        self.finish_exchange(RetirementReason::WebSocketCancellation);
        self.downstream_stream_lease.take();
        self.downstream_lease.take();
    }
}

async fn bridge_upgrades(mut pending: PendingBridgeGuard) {
    let upgraded = pending.wait_for_upgrades().await;
    let Ok((downstream, upstream)) = upgraded else {
        pending.mark_upgrade_failure();
        tracing::info!(event = "websocket_tunnel", outcome = "upgrade_failed");
        return;
    };
    let mut bridge = pending.into_active(downstream, upstream);
    let outcome = {
        let (downstream, upstream) = bridge.streams();
        tokio::io::copy_bidirectional(downstream, upstream).await
    };
    bridge.drop_streams();
    let reason = if outcome.is_ok() {
        RetirementReason::WebSocketClosed
    } else {
        RetirementReason::WebSocketError
    };
    bridge.finish_exchange(reason);
    tracing::info!(
        event = "websocket_tunnel",
        outcome = if outcome.is_ok() {
            "closed"
        } else {
            "io_error"
        }
    );
    drop(bridge);
}

#[derive(Default)]
struct UploadState {
    complete: AtomicBool,
    cancelled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl UploadState {
    fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            slot.take();
        }
    }

    fn cancel(&self) {
        if self.is_complete() {
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn register(&self, waker: &Waker) {
        if let Ok(mut slot) = self.waker.lock() {
            if slot
                .as_ref()
                .is_none_or(|registered| !registered.will_wake(waker))
            {
                *slot = Some(waker.clone());
            }
        }
    }
}

struct UploadCancellationGuard {
    upload: Arc<UploadState>,
    armed: bool,
}

impl UploadCancellationGuard {
    fn new(upload: Arc<UploadState>) -> Self {
        Self {
            upload,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UploadCancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.upload.cancel();
        }
    }
}

struct TrackedRequestBody<B> {
    inner: Option<B>,
    upload: Arc<UploadState>,
    exchange: Option<Arc<ExchangeLatch>>,
    stream_lease: Option<DownstreamStreamLease>,
    terminal: Option<bool>,
}

impl<B> TrackedRequestBody<B> {
    fn new(
        inner: B,
        upload: Arc<UploadState>,
        exchange: Arc<ExchangeLatch>,
        stream_lease: Option<DownstreamStreamLease>,
    ) -> Self
    where
        B: Body,
    {
        let complete = inner.is_end_stream();
        let mut body = Self {
            inner: Some(inner),
            upload,
            exchange: Some(exchange),
            stream_lease,
            terminal: None,
        };
        if complete {
            body.observe_terminal(true);
        }
        body
    }

    fn observe_terminal(&mut self, clean: bool) {
        if self.terminal.is_some() {
            return;
        }
        self.terminal = Some(clean);
        if clean {
            self.upload.mark_complete();
        } else {
            self.upload.cancel();
        }
        self.inner.take();
    }

    fn finish_on_drop(&mut self) {
        if self.terminal.is_none() {
            self.observe_terminal(false);
        }
        let Some(exchange) = self.exchange.take() else {
            return;
        };
        self.stream_lease.take();
        exchange.request_done(self.terminal.unwrap_or(false));
    }
}

impl<B> Drop for TrackedRequestBody<B> {
    fn drop(&mut self) {
        // Hyper can retain a frame returned from `poll_frame` in its H2
        // `PipeToSendStream` while waiting for flow-control capacity. The
        // wrapper drop is the first witness that Hyper has sent or discarded
        // that buffered frame, so request-half ownership is released only here.
        self.finish_on_drop();
    }
}

impl<B> Body for TrackedRequestBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.upload.is_cancelled() {
            self.observe_terminal(false);
            return Poll::Ready(None);
        }
        self.upload.register(context.waker());
        if self.upload.is_cancelled() {
            self.observe_terminal(false);
            return Poll::Ready(None);
        }
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                self.observe_terminal(true);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                if self.inner.as_ref().is_some_and(Body::is_end_stream) {
                    self.observe_terminal(true);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.observe_terminal(true);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.observe_terminal(false);
                Poll::Ready(Some(Err(error)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.upload.is_cancelled() || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

struct ExchangeResponseBody {
    inner: Option<Incoming>,
    exchange: Option<Arc<ExchangeLatch>>,
    reusable: bool,
}

impl ExchangeResponseBody {
    fn new(inner: Incoming, exchange: Arc<ExchangeLatch>, reusable: bool) -> Self {
        let complete = inner.is_end_stream();
        let mut body = Self {
            inner: Some(inner),
            exchange: Some(exchange),
            reusable,
        };
        if complete {
            body.complete();
        }
        body
    }

    fn complete(&mut self) {
        let Some(exchange) = self.exchange.take() else {
            return;
        };
        self.inner.take();
        exchange.response_done(self.reusable, RetirementReason::NonReusableResponse);
    }

    fn fail(&mut self, reason: RetirementReason) {
        let Some(exchange) = self.exchange.take() else {
            return;
        };
        self.inner.take();
        exchange.response_done(false, reason);
    }
}

impl Drop for ExchangeResponseBody {
    fn drop(&mut self) {
        self.fail(RetirementReason::ResponseBodyDrop);
    }
}

impl Body for ExchangeResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                self.complete();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                if self.inner.as_ref().is_some_and(Body::is_end_stream) {
                    self.complete();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.complete();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.fail(RetirementReason::ResponseBodyError);
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

struct ResolvedTcpConnector {
    candidates: Option<Vec<SocketAddr>>,
}

impl ResolvedTcpConnector {
    fn new(candidates: Vec<SocketAddr>) -> Self {
        Self {
            candidates: Some(candidates),
        }
    }
}

impl Service<Uri> for ResolvedTcpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let candidates = self.candidates.take();
        Box::pin(async move {
            let candidates = candidates.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "connector already used")
            })?;
            let mut last_kind = io::ErrorKind::NotConnected;
            for address in candidates {
                match TcpStream::connect(address).await {
                    Ok(stream) => {
                        // A TCP success ends address fallback. NODELAY, TLS,
                        // handshake, and HTTP failures never choose another IP.
                        stream.set_nodelay(true)?;
                        return Ok(TokioIo::new(stream));
                    }
                    Err(error) => last_kind = error.kind(),
                }
            }
            Err(io::Error::new(last_kind, "no resolved address connected"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::pending;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::sync::{Barrier, Condvar};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    struct FragmentingProofIo {
        reads: VecDeque<Vec<u8>>,
        writes: Arc<Mutex<Vec<u8>>>,
        write_limit: usize,
        vectored_calls: Arc<AtomicUsize>,
    }

    impl HyperRead for FragmentingProofIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            mut cursor: ReadBufCursor<'_>,
        ) -> Poll<Result<(), io::Error>> {
            let Some(mut bytes) = self.reads.pop_front() else {
                return Poll::Pending;
            };
            let copied = cursor.remaining().min(bytes.len());
            cursor.put_slice(&bytes[..copied]);
            if copied != bytes.len() {
                bytes.drain(..copied);
                self.reads.push_front(bytes);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl HyperWrite for FragmentingProofIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let accepted = self.write_limit.min(bytes.len());
            self.writes
                .lock()
                .expect("fragmenting writes")
                .extend_from_slice(&bytes[..accepted]);
            Poll::Ready(Ok(accepted))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            self.vectored_calls.fetch_add(1, Ordering::SeqCst);
            let mut remaining = self.write_limit;
            let mut accepted = 0;
            let mut writes = self.writes.lock().expect("fragmenting vectored writes");
            for buf in bufs {
                let copied = remaining.min(buf.len());
                writes.extend_from_slice(&buf[..copied]);
                accepted += copied;
                remaining -= copied;
                if remaining == 0 || copied != buf.len() {
                    break;
                }
            }
            Poll::Ready(Ok(accepted))
        }
    }

    fn h2_proof_for_test() -> Arc<H2ProofState> {
        H2ProofState::new(GenerationControl::new(1))
    }

    async fn in_memory_h2_sender() -> (H2Sender, JoinHandle<()>, JoinHandle<()>) {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let service = hyper::service::service_fn(|_request: Request<Incoming>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
            });
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        let (sender, connection) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake::<_, RequestBody>(TokioIo::new(client))
            .await
            .expect("in-memory H2 sender");
        let client_task = tokio::spawn(async move {
            let _ = connection.await;
        });
        (sender, client_task, server_task)
    }

    fn test_h2_generation(
        id: u64,
        sender: H2Sender,
        pool: &OwnerPool,
        stream_limit: usize,
    ) -> Arc<H2Generation> {
        let control = GenerationControl::new(id);
        control.install_initial(true).expect("test generation live");
        let proof = H2ProofState::new(Arc::clone(&control));
        Arc::new(H2Generation {
            state: Arc::new(H2DriverState {
                control,
                published: AtomicBool::new(false),
                pool: Arc::downgrade(pool),
                proof,
            }),
            master: Mutex::new(Some(sender)),
            streams: Arc::new(Semaphore::new(stream_limit)),
        })
    }

    fn assert_resolver_accounting(snapshot: ResolverSnapshot, limit: usize) {
        assert_eq!(
            snapshot.submitted_unobserved,
            snapshot.request_owned + snapshot.cleanup_owned
        );
        assert!(snapshot.submitted_unobserved <= snapshot.held_r);
        assert!(snapshot.held_r <= limit);
        assert!(snapshot.live_blocking <= snapshot.submitted_unobserved);
        assert!(snapshot.live_blocking <= limit);
    }

    type ResolverOperation = Box<dyn FnOnce() -> ResolverOutput + Send>;

    struct OneShotResolver {
        operation: Mutex<Option<ResolverOperation>>,
    }

    impl OneShotResolver {
        fn new(operation: impl FnOnce() -> ResolverOutput + Send + 'static) -> Self {
            Self {
                operation: Mutex::new(Some(Box::new(operation))),
            }
        }
    }

    impl HostResolver for OneShotResolver {
        fn resolve(&self, _domain: Box<str>, _port: u16) -> ResolverOutput {
            self.operation
                .lock()
                .expect("resolver operation")
                .take()
                .expect("one resolver call")()
        }
    }

    #[test]
    fn set_cookie_filter_is_exact_and_fail_closed() {
        for value in [
            "amg_session=x; Path=/",
            "amg_login_state=x",
            "amg_session =x",
            "no-equals",
        ] {
            assert!(!is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
        for value in ["amg_session2=x", "AMG_SESSION=x", "app=x; Path=/"] {
            assert!(is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn h2_websocket_content_length_accepts_absent_or_consistent_zero_only() {
        let mut headers = HeaderMap::new();
        assert!(validate_h2_websocket_content_length(&headers).is_ok());
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("0, 0"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("000"));
        assert!(validate_h2_websocket_content_length(&headers).is_ok());

        for values in [vec!["1"], vec!["0", "1"], vec!["0, bad"], vec!["+"]] {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(
                    CONTENT_LENGTH,
                    HeaderValue::from_str(value).expect("Content-Length fixture"),
                );
            }
            assert!(matches!(
                validate_h2_websocket_content_length(&headers),
                Err(ProxyError::BadRequest)
            ));
        }
    }

    fn settings_frame(payload: &[u8], flags: u8) -> Vec<u8> {
        let length = payload.len();
        let mut frame = vec![
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            0x4,
            flags,
            0,
            0,
            0,
            0,
        ];
        frame.extend_from_slice(payload);
        frame
    }

    fn arbitrary_h2_frame(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut frame = vec![
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            frame_type,
            flags,
        ];
        frame.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn same_connection_settings_proof_handles_fragmented_reads_and_accepted_vectored_writes() {
        let proof = h2_proof_for_test();
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, 3, 0, 0, 0, 7]);
        payload.extend_from_slice(&[0, 8, 0, 0, 0, 1]);
        payload.extend_from_slice(&[0, 3, 0, 0, 0, 2]);
        let inbound = settings_frame(&payload, 0);
        for byte in inbound.chunks(1) {
            proof.observe_inbound(byte);
        }
        assert_eq!(*proof.status.borrow(), H2ProofStatus::Pending);

        let mut outbound = H2_CLIENT_PREFACE.to_vec();
        outbound.extend_from_slice(&settings_frame(&[0, 4, 0, 0, 255, 255], 0));
        outbound.extend_from_slice(&settings_frame(&[], 1));
        let split = 11;
        let buffers = [
            IoSlice::new(&outbound[..split]),
            IoSlice::new(&outbound[split..]),
        ];
        proof.observe_outbound_vectored(&buffers, outbound.len() - 1);
        assert_eq!(*proof.status.borrow(), H2ProofStatus::Pending);
        proof.observe_outbound(&outbound[outbound.len() - 1..]);
        assert_eq!(
            *proof.status.borrow(),
            H2ProofStatus::Ready(InitialH2Settings {
                extended_connect: true,
                max_concurrent_streams: Some(2),
            })
        );
    }

    #[test]
    fn real_h2_proof_io_is_byte_transparent_for_fragmented_reads_and_partial_vectored_writes() {
        let control = GenerationControl::new(50);
        let proof = H2ProofState::new(Arc::clone(&control));
        let inbound = settings_frame(&[0, 3, 0, 0, 0, 4, 0, 8, 0, 0, 0, 1], 0);
        let writes = Arc::new(Mutex::new(Vec::new()));
        let vectored_calls = Arc::new(AtomicUsize::new(0));
        let inner = FragmentingProofIo {
            reads: inbound.iter().map(|byte| vec![*byte]).collect(),
            writes: Arc::clone(&writes),
            write_limit: 5,
            vectored_calls: Arc::clone(&vectored_calls),
        };
        let mut io = H2ProofIo::new(inner, Arc::clone(&proof));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut delivered = Vec::new();
        for _ in 0..inbound.len() {
            let mut storage = [0_u8; 3];
            let mut read = ReadBuf::new(&mut storage);
            assert!(matches!(
                Pin::new(&mut io).poll_read(&mut context, read.unfilled()),
                Poll::Ready(Ok(()))
            ));
            delivered.extend_from_slice(read.filled());
        }
        assert_eq!(delivered, inbound);
        assert!(control.permits_extended_connect());

        let mut outbound = H2_CLIENT_PREFACE.to_vec();
        outbound.extend_from_slice(&settings_frame(&[], 0));
        outbound.extend_from_slice(&settings_frame(&[], 1));
        let first = [
            IoSlice::new(&outbound[..2]),
            IoSlice::new(&outbound[2..11]),
            IoSlice::new(&outbound[11..]),
        ];
        let accepted = match Pin::new(&mut io).poll_write_vectored(&mut context, &first) {
            Poll::Ready(Ok(accepted)) => accepted,
            other => panic!("unexpected vectored write result: {other:?}"),
        };
        assert_eq!(accepted, 5);
        let mut offset = accepted;
        while offset < outbound.len() {
            let accepted = match Pin::new(&mut io).poll_write(&mut context, &outbound[offset..]) {
                Poll::Ready(Ok(accepted)) => accepted,
                other => panic!("unexpected scalar write result: {other:?}"),
            };
            assert_ne!(accepted, 0);
            offset += accepted;
        }
        assert_eq!(vectored_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*writes.lock().expect("observed proof writes"), outbound);
        assert!(outbound[H2_CLIENT_PREFACE.len()..]
            .chunks(9)
            .all(|chunk| chunk.get(3).is_none_or(|kind| !matches!(*kind, 0x0 | 0x1))));
        assert_eq!(
            *proof.status.borrow(),
            H2ProofStatus::Ready(InitialH2Settings {
                extended_connect: true,
                max_concurrent_streams: Some(4),
            })
        );
    }

    #[tokio::test]
    async fn h2_proof_io_connection_completion_before_proof_is_fail_closed() {
        let control = GenerationControl::new(51);
        let proof = H2ProofState::new(Arc::clone(&control));
        let (client, mut peer) = tokio::io::duplex(1024);
        let builder = http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        let (_sender, connection) = builder
            .handshake::<_, Empty<Bytes>>(H2ProofIo::new(TokioIo::new(client), Arc::clone(&proof)))
            .await
            .expect("in-memory H2 handshake");
        let driver = tokio::spawn(connection);
        let mut preface = vec![0_u8; H2_CLIENT_PREFACE.len()];
        peer.read_exact(&mut preface)
            .await
            .expect("client H2 preface");
        assert_eq!(preface, H2_CLIENT_PREFACE);
        let mut header = [0_u8; 9];
        peer.read_exact(&mut header)
            .await
            .expect("client SETTINGS header");
        let length =
            ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
        assert_eq!(header[3], 0x4);
        let mut payload = vec![0_u8; length];
        peer.read_exact(&mut payload)
            .await
            .expect("client SETTINGS payload");
        loop {
            let mut preproof_header = [0_u8; 9];
            if timeout(
                Duration::from_millis(5),
                peer.read_exact(&mut preproof_header),
            )
            .await
            .is_err()
            {
                break;
            }
            assert!(
                !matches!(preproof_header[3], 0x0 | 0x1),
                "application HEADERS/DATA appeared before SETTINGS proof"
            );
            let length = ((preproof_header[0] as usize) << 16)
                | ((preproof_header[1] as usize) << 8)
                | preproof_header[2] as usize;
            let mut payload = vec![0_u8; length];
            peer.read_exact(&mut payload)
                .await
                .expect("pre-proof control frame payload");
        }
        peer.write_all(&settings_frame(&[0, 8, 0, 0, 0, 1], 0)[..8])
            .await
            .expect("partial server SETTINGS");
        drop(peer);
        assert!(driver.await.expect("H2 driver join").is_err());
        proof.wait_transport_dropped().await;
        assert!(proof.is_transport_dropped());
        assert_eq!(*proof.status.borrow(), H2ProofStatus::Failed);
        assert!(!control.is_selectable());
    }

    #[test]
    fn same_connection_settings_proof_rejects_wrong_first_frame_and_invalid_known_values() {
        let wrong_frame = h2_proof_for_test();
        wrong_frame.observe_inbound(&[0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(*wrong_frame.status.borrow(), H2ProofStatus::Failed);

        let invalid_setting = h2_proof_for_test();
        invalid_setting.observe_inbound(&settings_frame(&[0, 8, 0, 0, 0, 2], 0));
        assert_eq!(*invalid_setting.status.borrow(), H2ProofStatus::Failed);

        let oversized = h2_proof_for_test();
        oversized.observe_inbound(&[0, 0x40, 1, 4, 0, 0, 0, 0, 0]);
        assert_eq!(*oversized.status.borrow(), H2ProofStatus::Failed);
    }

    #[test]
    fn ongoing_settings_scanner_is_fragmented_bounded_and_last_value_wins() {
        assert!(std::mem::size_of::<ServerFrameScanner>() <= 80);
        let initial = settings_frame(&[0, 8, 0, 0, 0, 1], 0);
        let revoke = settings_frame(&[0, 8, 0, 0, 0, 0], 0);
        for split in 0..=revoke.len() {
            let control = GenerationControl::new(split as u64 + 1);
            let proof = H2ProofState::new(Arc::clone(&control));
            proof.observe_inbound(&initial);
            assert!(control.permits_extended_connect());
            proof.observe_inbound(&revoke[..split]);
            proof.observe_inbound(&revoke[split..]);
            assert!(!control.is_selectable(), "split {split}");
        }

        let control = GenerationControl::new(100);
        let proof = H2ProofState::new(Arc::clone(&control));
        proof.observe_inbound(&initial);
        let large = arbitrary_h2_frame(0x0, 0, 1, &vec![0x5a; 16_384]);
        for chunk in large.chunks(257) {
            proof.observe_inbound(chunk);
        }
        assert!(control.permits_extended_connect());
        proof.observe_inbound(&settings_frame(&[0, 8, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1], 0));
        assert!(control.permits_extended_connect());
        proof.observe_inbound(&settings_frame(&[0, 8, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0], 0));
        assert!(!control.is_selectable());

        let disabled = GenerationControl::new(101);
        let disabled_proof = H2ProofState::new(Arc::clone(&disabled));
        disabled_proof.observe_inbound(&settings_frame(&[], 0));
        disabled_proof.observe_inbound(&settings_frame(&[0, 8, 0, 0, 0, 1], 0));
        assert!(!disabled.permits_extended_connect());
        assert_eq!(
            disabled.linearize_dispatch(H2DispatchKind::Ordinary, || 7),
            Ok(7)
        );
        assert_eq!(
            disabled.linearize_dispatch(H2DispatchKind::ExtendedConnect, || 9),
            Err(DispatchGateError::Ineligible)
        );

        let coalesced = GenerationControl::new(102);
        let coalesced_proof = H2ProofState::new(Arc::clone(&coalesced));
        let mut bytes = initial;
        bytes.extend_from_slice(&arbitrary_h2_frame(0x6, 0, 0, b"12345678"));
        bytes.extend_from_slice(&revoke);
        coalesced_proof.observe_inbound(&bytes);
        assert!(!coalesced.is_selectable());
    }

    #[test]
    fn generation_gate_linearizes_update_before_and_candidate_before_update() {
        let update_first = GenerationControl::new(200);
        update_first.install_initial(true).expect("initial enabled");
        update_first.revoke_if_enabled();
        let sends = AtomicUsize::new(0);
        let h1_fallbacks = AtomicUsize::new(0);
        assert_eq!(
            update_first.linearize_dispatch(H2DispatchKind::ExtendedConnect, || {
                sends.fetch_add(1, Ordering::SeqCst);
            }),
            Err(DispatchGateError::Ineligible)
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0);
        assert_eq!(h1_fallbacks.load(Ordering::SeqCst), 0);
        assert!(!update_first.is_selectable());

        let candidate_first = GenerationControl::new(201);
        candidate_first
            .install_initial(true)
            .expect("initial enabled");
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let sends = Arc::new(AtomicUsize::new(0));
        let candidate = {
            let control = Arc::clone(&candidate_first);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let sends = Arc::clone(&sends);
            std::thread::spawn(move || {
                control.linearize_dispatch(H2DispatchKind::ExtendedConnect, || {
                    sends.fetch_add(1, Ordering::SeqCst);
                    entered.wait();
                    release.wait();
                })
            })
        };
        entered.wait();
        assert!(candidate_first.state.try_lock().is_err());
        let update = {
            let control = Arc::clone(&candidate_first);
            std::thread::spawn(move || control.revoke_if_enabled())
        };
        release.wait();
        assert_eq!(candidate.join().expect("candidate thread"), Ok(()));
        update.join().expect("update thread");
        assert_eq!(sends.load(Ordering::SeqCst), 1);
        assert!(!candidate_first.is_selectable());
        assert_eq!(h1_fallbacks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn creator_reservation_precedes_barrier_controlled_publication() {
        let (sender, client_task, server_task) = in_memory_h2_sender().await;
        let pool: OwnerPool = Arc::new(Mutex::new(Vec::new()));
        let generation = test_h2_generation(300, sender, &pool, 1);
        let reserved = Arc::new(Barrier::new(2));
        let publish = Arc::new(Barrier::new(2));
        let creator_slot = Arc::new(Mutex::new(None));
        let producer = {
            let generation = Arc::clone(&generation);
            let pool = Arc::clone(&pool);
            let reserved = Arc::clone(&reserved);
            let publish = Arc::clone(&publish);
            let creator_slot = Arc::clone(&creator_slot);
            std::thread::spawn(move || {
                let (sender, permit) = {
                    let master = generation.master.lock().expect("creator master sender");
                    reserve_h2_creator(
                        master.as_ref().expect("creator sender"),
                        &generation.streams,
                    )
                    .expect("creator owns only sender and stream permit")
                };
                *creator_slot.lock().expect("creator reservation slot") =
                    Some(H2StreamReservation {
                        generation: Arc::clone(&generation),
                        sender: Some(sender),
                        _stream_permit: permit,
                    });
                reserved.wait();
                publish.wait();
                assert!(publish_h2_generation_slot(&pool, &generation));
            })
        };
        reserved.wait();
        assert_eq!(generation.streams.available_permits(), 0);
        assert!(pool.lock().expect("pre-publication pool").is_empty());
        publish.wait();
        producer.join().expect("creator publication thread");
        assert_eq!(pool.lock().expect("published pool").len(), 1);
        assert!(matches!(
            generation.try_reserve(),
            H2ReserveResult::Saturated
        ));
        assert!(creator_slot
            .lock()
            .expect("creator reservation")
            .as_ref()
            .is_some_and(|reservation| reservation.sender.is_some()));
        assert_eq!(generation.id(), 300);
        assert_eq!(
            pool.lock()
                .expect("no H1 fallback pool")
                .iter()
                .filter(|entry| matches!(entry, PoolEntry::H1(_)))
                .count(),
            0
        );
        drop(creator_slot);
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn retiring_slot_and_stale_generation_cleanup_are_exact_id_scoped() {
        let (sender, client_task, server_task) = in_memory_h2_sender().await;
        let pool: OwnerPool = Arc::new(Mutex::new(Vec::new()));
        let generation_1 = test_h2_generation(400, sender.clone(), &pool, 2);
        let generation_2 = test_h2_generation(401, sender, &pool, 2);
        {
            let mut entries = pool.lock().expect("generation pool");
            entries.push(PoolEntry::H2(Arc::clone(&generation_1)));
            entries.push(PoolEntry::H2(Arc::clone(&generation_2)));
            generation_1.state.published.store(true, Ordering::Release);
            generation_2.state.published.store(true, Ordering::Release);
        }
        retire_h2_generation(&generation_1);
        {
            let entries = pool.lock().expect("retiring generation pool");
            assert!(matches!(
                entries.first(),
                Some(PoolEntry::RetiringH2 { generation: 400 })
            ));
            assert!(matches!(
                entries.get(1),
                Some(PoolEntry::H2(generation)) if generation.id() == 401
            ));
        }
        remove_retiring_h2_slot(&pool, 400);
        retire_h2_generation(&generation_1);
        {
            let entries = pool.lock().expect("stale completion pool");
            assert_eq!(entries.len(), 1);
            assert!(matches!(
                entries.first(),
                Some(PoolEntry::H2(generation)) if generation.id() == 401
            ));
        }
        client_task.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn tracked_request_body_defers_h2_eos_and_cancellation_until_wrapper_drop() {
        let (sender, client_task, server_task) = in_memory_h2_sender().await;
        let pool: OwnerPool = Arc::new(Mutex::new(Vec::new()));
        let generation = test_h2_generation(500, sender, &pool, 1);
        let local_streams = Arc::clone(&generation.streams);
        let local_permit = Arc::clone(&local_streams)
            .try_acquire_owned()
            .expect("local H2 stream permit");
        let sender = generation
            .master
            .lock()
            .expect("request body master sender")
            .as_ref()
            .expect("request body sender")
            .clone();
        let active = Arc::new(Semaphore::new(1));
        let active_permit = Arc::clone(&active)
            .try_acquire_owned()
            .expect("request body U");
        let downstream = Arc::new(Semaphore::new(1));
        let downstream_lease = DownstreamStreamLease::new(
            Arc::clone(&downstream)
                .try_acquire_owned()
                .expect("downstream stream permit"),
        );
        let exchange = ExchangeLatch::new(ExchangeResource::H2(H2ExchangeOwner {
            reservation: H2StreamReservation {
                generation: Arc::clone(&generation),
                sender: Some(sender),
                _stream_permit: local_permit,
            },
            active_permit: Some(active_permit),
            private_generation: false,
        }));
        let upload = Arc::new(UploadState::default());
        let mut body = TrackedRequestBody::new(
            Full::new(Bytes::from_static(b"flow-controlled-final-data")),
            upload,
            Arc::clone(&exchange),
            Some(downstream_lease),
        );
        exchange.response_done(false, RetirementReason::NonReusableResponse);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let buffered_frame = match Pin::new(&mut body).poll_frame(&mut context) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => panic!("final body frame was not produced: {other:?}"),
        };
        assert!(buffered_frame.is_data());
        assert!(body.is_end_stream());
        assert_eq!(active.available_permits(), 0);
        assert_eq!(local_streams.available_permits(), 0);
        assert_eq!(body.stream_lease.as_ref().map(|_| 1), Some(1));
        assert_eq!(downstream.available_permits(), 0);
        assert_eq!(body.exchange.as_ref().map(|_| 1), Some(1));
        assert_eq!(body.terminal, Some(true));
        assert_eq!(
            body.exchange
                .as_ref()
                .expect("request exchange")
                .inner
                .lock()
                .expect("request latch")
                .request_done,
            None
        );
        drop(buffered_frame);
        assert_eq!(active.available_permits(), 0);
        drop(body);
        assert_eq!(active.available_permits(), 1);
        assert_eq!(local_streams.available_permits(), 1);
        assert_eq!(downstream.available_permits(), 1);

        let cancelled_local_permit = Arc::clone(&local_streams)
            .try_acquire_owned()
            .expect("cancelled local H2 stream permit");
        let cancelled_sender = generation
            .master
            .lock()
            .expect("cancelled master sender")
            .as_ref()
            .expect("cancelled sender")
            .clone();
        let cancelled_active = Arc::new(Semaphore::new(1));
        let cancelled_downstream = Arc::new(Semaphore::new(1));
        let cancelled_exchange = ExchangeLatch::new(ExchangeResource::H2(H2ExchangeOwner {
            reservation: H2StreamReservation {
                generation,
                sender: Some(cancelled_sender),
                _stream_permit: cancelled_local_permit,
            },
            active_permit: Some(
                Arc::clone(&cancelled_active)
                    .try_acquire_owned()
                    .expect("cancelled U"),
            ),
            private_generation: false,
        }));
        let cancelled_upload = Arc::new(UploadState::default());
        let mut cancelled_body = TrackedRequestBody::new(
            Full::new(Bytes::from_static(b"cancelled-data")),
            Arc::clone(&cancelled_upload),
            Arc::clone(&cancelled_exchange),
            Some(DownstreamStreamLease::new(
                Arc::clone(&cancelled_downstream)
                    .try_acquire_owned()
                    .expect("cancelled downstream permit"),
            )),
        );
        cancelled_exchange.response_done(false, RetirementReason::RequestCancellation);
        cancelled_upload.cancel();
        assert!(matches!(
            Pin::new(&mut cancelled_body).poll_frame(&mut context),
            Poll::Ready(None)
        ));
        assert_eq!(cancelled_body.terminal, Some(false));
        assert_eq!(cancelled_active.available_permits(), 0);
        assert_eq!(local_streams.available_permits(), 0);
        assert_eq!(cancelled_downstream.available_permits(), 0);
        drop(cancelled_body);
        assert_eq!(cancelled_active.available_permits(), 1);
        assert_eq!(local_streams.available_permits(), 1);
        assert_eq!(cancelled_downstream.available_permits(), 1);
        client_task.abort();
        server_task.abort();
    }

    struct BlockingDropTransport {
        entered: mpsc::Sender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for BlockingDropTransport {
        fn drop(&mut self) {
            self.entered.send(()).expect("drop observer");
            let (lock, condition) = &*self.release;
            let mut released = lock.lock().expect("drop release lock");
            while !*released {
                released = condition.wait(released).expect("drop release wait");
            }
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h2_proof_io_signals_transport_only_after_inner_drop_completes() {
        let active = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&active)
            .acquire_owned()
            .await
            .expect("private H2 U");
        let proof = h2_proof_for_test();
        let (entered_sender, entered_receiver) = mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let dropped = Arc::new(AtomicBool::new(false));
        let wrapped = H2ProofIo::new(
            BlockingDropTransport {
                entered: entered_sender,
                release: Arc::clone(&release),
                dropped: Arc::clone(&dropped),
            },
            Arc::clone(&proof),
        );
        schedule_permit_after_transport_drop(Arc::clone(&proof), permit);
        let drop_thread = std::thread::spawn(move || drop(wrapped));
        entered_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("inner transport drop entered");
        tokio::task::yield_now().await;
        assert!(!dropped.load(Ordering::Acquire));
        assert!(!proof.is_transport_dropped());
        assert_eq!(active.available_permits(), 0);
        assert!(Arc::clone(&active).try_acquire_owned().is_err());

        {
            let (lock, condition) = &*release;
            *lock.lock().expect("release inner drop") = true;
            condition.notify_all();
        }
        drop_thread.join().expect("inner transport drop thread");
        assert!(dropped.load(Ordering::Acquire));
        timeout(Duration::from_secs(2), async {
            while active.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("transport witness released U");
        assert_eq!(active.available_permits(), 1);
    }

    #[tokio::test]
    async fn rejected_h2_upgrade_gate_holds_all_permits_until_upgraded_drop_point() {
        let permits = [
            Arc::new(Semaphore::new(1)),
            Arc::new(Semaphore::new(1)),
            Arc::new(Semaphore::new(1)),
        ];
        let held_permits = permits
            .iter()
            .map(|semaphore| {
                Arc::clone(semaphore)
                    .try_acquire_owned()
                    .expect("rejected upgrade permit")
            })
            .collect();
        let (release, gate) = watch::channel(false);
        let cleanup = RejectedH2UpgradeCleanup {
            upstream: None,
            exchange: None,
            downstream_stream_lease: None,
            downstream_lease: None,
            before_upgraded_drop: Some(gate),
            held_permits,
        };
        let task = tokio::spawn(cleanup.run());
        tokio::task::yield_now().await;
        for permit in &permits {
            assert_eq!(permit.available_permits(), 0);
            assert!(Arc::clone(permit).try_acquire_owned().is_err());
        }

        release.send_replace(true);
        task.await.expect("rejected upgrade cleanup");
        for permit in &permits {
            assert_eq!(permit.available_permits(), 1);
        }
    }

    #[test]
    fn websocket_extension_grammar_is_quote_aware_and_rejects_duplicates() {
        let mut valid = HeaderMap::new();
        valid.insert(
            "sec-websocket-extensions",
            HeaderValue::from_static(
                "permessage-deflate; mode=\"a,b;c\"; client_max_window_bits, x-test",
            ),
        );
        assert_eq!(
            parse_extensions(&valid).expect("valid extensions"),
            HashSet::from(["permessage-deflate".to_string(), "x-test".to_string()])
        );

        for malformed in [
            "permessage-deflate, PERMESSAGE-DEFLATE",
            "permessage-deflate; mode=one; MODE=two",
            "permessage-deflate; mode=\"unterminated",
            "permessage-deflate; mode=\"bad\"quote\"",
            "permessage-deflate; =value",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "sec-websocket-extensions",
                HeaderValue::from_str(malformed).expect("legal malformed header bytes"),
            );
            assert!(parse_extensions(&headers).is_err(), "{malformed}");
        }
    }

    #[test]
    fn http_upstream_initialization_does_not_load_native_tls_roots() {
        let upstream = crate::config::parse_upstream_url(Some("http://127.0.0.1:4096"))
            .expect("valid")
            .expect("configured");
        let proxy = Proxy::new_with_native_root_loader(upstream, 128, 8, || {
            panic!("HTTP initialization must not load TLS roots")
        });
        assert!(proxy.is_ok());
    }

    #[test]
    fn https_upstream_initialization_requires_native_tls_roots() {
        let upstream = crate::config::parse_upstream_url(Some("https://app.example"))
            .expect("valid")
            .expect("configured");
        let proxy = Proxy::new_with_native_root_loader(upstream, 128, 8, || {
            Err("test native roots unavailable".into())
        });
        assert!(proxy.is_err());
    }

    #[test]
    fn trusted_forwarding_accepts_only_one_strict_bare_ip() {
        let trusted =
            crate::config::parse_trusted_proxy_cidrs(Some("127.0.0.1/32")).expect("trusted peer");
        let peer = "127.0.0.1".parse::<IpAddr>().expect("peer");

        assert_eq!(
            derive_client_ip(peer, &HeaderMap::new(), &trusted).expect("missing fallback"),
            ClientIp(peer)
        );
        let mut valid = HeaderMap::new();
        valid.insert("x-forwarded-for", HeaderValue::from_static("2001:db8::7"));
        assert_eq!(
            derive_client_ip(peer, &valid, &trusted).expect("valid IPv6"),
            ClientIp("2001:db8::7".parse().expect("IPv6"))
        );

        for malformed in [
            "192.0.2.1, 192.0.2.2",
            "192.0.2.1:443",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.0.2.1 ",
            "opaque",
            "",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-forwarded-for",
                HeaderValue::from_str(malformed).expect("legal header bytes"),
            );
            assert!(matches!(
                derive_client_ip(peer, &headers, &trusted),
                Err(ProxyError::BadRequest)
            ));
        }
        let mut repeated = HeaderMap::new();
        repeated.append("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        repeated.append("x-forwarded-for", HeaderValue::from_static("192.0.2.2"));
        assert!(matches!(
            derive_client_ip(peer, &repeated, &trusted),
            Err(ProxyError::BadRequest)
        ));
        let mut opaque = HeaderMap::new();
        opaque.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
        );
        assert!(matches!(
            derive_client_ip(peer, &opaque, &trusted),
            Err(ProxyError::BadRequest)
        ));
    }

    #[test]
    fn untrusted_forwarding_is_never_parsed_and_mapped_families_are_distinct() {
        let trusted_v4 =
            crate::config::parse_trusted_proxy_cidrs(Some("127.0.0.1/32")).expect("trusted v4");
        let mapped = "::ffff:127.0.0.1".parse::<IpAddr>().expect("mapped peer");
        let mut opaque = HeaderMap::new();
        opaque.append(
            "x-forwarded-for",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header"),
        );
        opaque.append(
            "x-forwarded-for",
            HeaderValue::from_static("attacker, invalid"),
        );
        assert_eq!(
            derive_client_ip(mapped, &opaque, &trusted_v4).expect("ignored XFF"),
            ClientIp(mapped)
        );

        let trusted_mapped = crate::config::parse_trusted_proxy_cidrs(Some("::ffff:127.0.0.1/128"))
            .expect("trusted mapped peer");
        let mut canonical = HeaderMap::new();
        canonical.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.9"));
        assert_eq!(
            derive_client_ip(mapped, &canonical, &trusted_mapped).expect("mapped trust"),
            ClientIp("192.0.2.9".parse().expect("client"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn started_resolver_cleanup_retains_both_permits_until_join() {
        let active = Arc::new(Semaphore::new(1));
        let resolvers = Arc::new(Semaphore::new(1));
        let active_permit = Arc::clone(&active)
            .acquire_owned()
            .await
            .expect("active permit");
        let resolver_permit = Arc::clone(&resolvers)
            .acquire_owned()
            .await
            .expect("resolver permit");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let operation_gate = Arc::clone(&gate);
        let operation_started = Arc::clone(&started);
        let attempt = submit_resolution(active_permit, resolver_permit, move || {
            operation_started.store(true, Ordering::Release);
            let (lock, condition) = &*operation_gate;
            let mut released = lock.lock().expect("resolver gate");
            while !*released {
                released = condition.wait(released).expect("resolver wait");
            }
            Ok(vec!["127.0.0.1:80".parse().expect("address")])
        });
        let accounting = Arc::clone(
            &attempt
                .parts
                .as_ref()
                .expect("started accounting")
                .accounting,
        );
        let waiter = tokio::spawn(async move {
            let mut attempt = attempt;
            let _ = attempt.handle_mut().await;
            attempt.observed()
        });
        timeout(Duration::from_secs(5), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver started");
        assert_resolver_accounting(accounting.snapshot(), 1);
        assert_eq!(accounting.snapshot().request_owned, 1);
        waiter.abort();
        assert!(waiter.await.expect_err("request canceled").is_cancelled());
        assert_eq!(active.available_permits(), 0);
        assert_eq!(resolvers.available_permits(), 0);
        assert!(Arc::clone(&resolvers).try_acquire_owned().is_err());
        assert_resolver_accounting(accounting.snapshot(), 1);
        assert_eq!(accounting.snapshot().cleanup_owned, 1);

        {
            let (lock, condition) = &*gate;
            *lock.lock().expect("resolver release") = true;
            condition.notify_all();
        }
        timeout(Duration::from_secs(5), async {
            while active.available_permits() != 1 || resolvers.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("resolver cleanup joined before permit release");
        assert_eq!(
            accounting.snapshot(),
            ResolverSnapshot {
                total_submitted: 1,
                ..ResolverSnapshot::default()
            }
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resolver_saturation_is_immediate_and_ip_literals_bypass_r() {
        let domain = crate::config::parse_upstream_url(Some("http://localhost:9"))
            .expect("domain URL")
            .expect("domain upstream");
        let domain_proxy =
            Proxy::with_root_store(domain, RootCertStore::empty(), 1, 1).expect("domain proxy");
        let resolver_lease = Arc::clone(&domain_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy R");
        let active = Arc::clone(&domain_proxy.active)
            .try_acquire_owned()
            .expect("U available");
        assert!(matches!(
            domain_proxy.connect(active).await,
            Err(ProxyError::Capacity(CapacityClass::BlockingResolver))
        ));
        assert_eq!(domain_proxy.active.available_permits(), 1);
        assert_eq!(domain_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unused IP address");
        let address = listener.local_addr().expect("unused address");
        drop(listener);
        let ip = crate::config::parse_upstream_url(Some(&format!("http://{address}")))
            .expect("IP URL")
            .expect("IP upstream");
        let ip_proxy = Proxy::with_root_store(ip, RootCertStore::empty(), 1, 1).expect("IP proxy");
        let resolver_lease = Arc::clone(&ip_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy IP proxy R");
        let active = Arc::clone(&ip_proxy.active)
            .try_acquire_owned()
            .expect("IP proxy U");
        let result = timeout(Duration::from_secs(2), ip_proxy.connect(active))
            .await
            .expect("direct IP connect did not wait for R");
        assert!(matches!(result, Err(ProxyError::BadGateway)));
        assert_eq!(ip_proxy.active.available_permits(), 1);
        assert_eq!(ip_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);

        let ipv6 = crate::config::parse_upstream_url(Some("http://[2001:db8::1]:9"))
            .expect("IPv6 URL")
            .expect("IPv6 upstream");
        assert_eq!(
            ipv6.dial_target().host(),
            &DialHost::Ip("2001:db8::1".parse().expect("IPv6 literal"))
        );
        assert_eq!(
            SocketAddr::new(
                match ipv6.dial_target().host() {
                    DialHost::Ip(ip) => *ip,
                    DialHost::Domain(_) => panic!("typed IPv6 became domain"),
                },
                ipv6.dial_target().port(),
            ),
            "[2001:db8::1]:9".parse().expect("exact IPv6 SocketAddr")
        );
        let mut ipv6_proxy =
            Proxy::with_root_store(ipv6, RootCertStore::empty(), 1, 1).expect("IPv6 proxy");
        ipv6_proxy.connect_timeout = Duration::from_millis(100);
        let resolver_lease = Arc::clone(&ipv6_proxy.resolvers)
            .acquire_owned()
            .await
            .expect("occupy IPv6 proxy R");
        let active = Arc::clone(&ipv6_proxy.active)
            .try_acquire_owned()
            .expect("IPv6 proxy U");
        let result = timeout(Duration::from_secs(2), ipv6_proxy.connect(active))
            .await
            .expect("IPv6 literal did not wait for resolver");
        assert!(matches!(result, Err(ProxyError::BadGateway)));
        assert_eq!(
            ipv6_proxy.resolver_accounting().snapshot().total_submitted,
            0
        );
        assert_eq!(ipv6_proxy.resolvers.available_permits(), 0);
        drop(resolver_lease);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolver_success_failure_empty_and_join_error_all_drain_accounting() {
        crate::exit::install_sanitized_panic_hook();
        let unused = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unused address");
        let unused_address = unused.local_addr().expect("unused address value");
        drop(unused);
        let operations: Vec<ResolverOperation> = vec![
            Box::new(move || Ok(vec![unused_address])),
            Box::new(|| Err(io::Error::new(io::ErrorKind::NotFound, "resolver fixture"))),
            Box::new(|| Ok(Vec::new())),
            Box::new(|| std::panic::panic_any("resolver-join-payload-marker")),
        ];
        for operation in operations {
            let upstream = crate::config::parse_upstream_url(Some("http://resolver.example:80"))
                .expect("resolver URL")
                .expect("resolver upstream");
            let accounting = Arc::new(ResolverAccounting::default());
            let resolver = Arc::new(OneShotResolver {
                operation: Mutex::new(Some(operation)),
            });
            let proxy = Proxy::with_root_store_and_resolver(
                upstream,
                RootCertStore::empty(),
                1,
                1,
                resolver,
                Arc::clone(&accounting),
            )
            .expect("resolver proxy");
            let active = Arc::clone(&proxy.active)
                .acquire_owned()
                .await
                .expect("active permit");
            assert!(matches!(
                proxy.connect(active).await,
                Err(ProxyError::BadGateway)
            ));
            assert_eq!(proxy.active.available_permits(), 1);
            assert_eq!(proxy.resolvers.available_permits(), 1);
            assert_eq!(
                accounting.snapshot(),
                ResolverSnapshot {
                    total_submitted: 1,
                    ..ResolverSnapshot::default()
                }
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolver_timeout_returns_502_phase_but_keeps_u_r_through_cleanup_join() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let resolver_gate = Arc::clone(&gate);
        let resolver_started = Arc::clone(&started);
        let resolver = Arc::new(OneShotResolver::new(move || {
            resolver_started.store(true, Ordering::Release);
            let (lock, condition) = &*resolver_gate;
            let mut released = lock.lock().expect("timeout gate");
            while !*released {
                released = condition.wait(released).expect("timeout wait");
            }
            Ok(vec!["127.0.0.1:9".parse().expect("timeout address")])
        }));
        let accounting = Arc::new(ResolverAccounting::default());
        let upstream = crate::config::parse_upstream_url(Some("http://resolver.example:80"))
            .expect("timeout URL")
            .expect("timeout upstream");
        let mut proxy = Proxy::with_root_store_and_resolver(
            upstream,
            RootCertStore::empty(),
            1,
            1,
            resolver,
            Arc::clone(&accounting),
        )
        .expect("timeout proxy");
        proxy.connect_timeout = Duration::from_millis(100);
        let active = Arc::clone(&proxy.active)
            .acquire_owned()
            .await
            .expect("timeout active");
        let proxy_for_task = proxy.clone();
        let request = tokio::spawn(async move { proxy_for_task.connect(active).await });
        timeout(Duration::from_secs(5), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout resolver started");
        assert!(matches!(
            timeout(Duration::from_secs(2), request)
                .await
                .expect("request timeout response")
                .expect("request task"),
            Err(ProxyError::BadGateway)
        ));
        assert_eq!(proxy.active.available_permits(), 0);
        assert_eq!(proxy.resolvers.available_permits(), 0);
        let snapshot = accounting.snapshot();
        assert_resolver_accounting(snapshot, 1);
        assert_eq!(snapshot.cleanup_owned, 1);
        assert_eq!(snapshot.live_blocking, 1);
        {
            let (lock, condition) = &*gate;
            *lock.lock().expect("timeout release") = true;
            condition.notify_all();
        }
        timeout(Duration::from_secs(5), async {
            while proxy.active.available_permits() != 1 || proxy.resolvers.available_permits() != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout cleanup joined");
        assert_eq!(
            accounting.snapshot(),
            ResolverSnapshot {
                total_submitted: 1,
                ..ResolverSnapshot::default()
            }
        );
    }

    #[tokio::test]
    async fn resolved_connector_uses_ordered_socketaddr_tcp_fallback_only() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unavailable candidate");
        let unavailable_address = unavailable.local_addr().expect("unavailable address");
        drop(unavailable);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fallback listener");
        let available_address = listener.local_addr().expect("available address");
        let accepted =
            tokio::spawn(async move { listener.accept().await.expect("fallback accept") });
        let mut connector = ResolvedTcpConnector::new(vec![unavailable_address, available_address]);
        let io = connector
            .call(
                "http://fixed-authority.example/"
                    .parse()
                    .expect("connector URI"),
            )
            .await
            .expect("second SocketAddr connected");
        let (_, peer) = accepted.await.expect("accept task");
        assert_eq!(peer.ip(), available_address.ip());
        drop(io);
        assert!(connector
            .call(
                "http://fixed-authority.example/"
                    .parse()
                    .expect("second URI")
            )
            .await
            .is_err());
    }

    #[test]
    fn queued_resolver_cancellation_aborts_without_running_or_leaking_permits() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("queued resolver runtime");
        runtime.block_on(async {
            let blocker_gate = Arc::new((Mutex::new(false), Condvar::new()));
            let blocker_started = Arc::new(AtomicBool::new(false));
            let task_gate = Arc::clone(&blocker_gate);
            let task_started = Arc::clone(&blocker_started);
            let blocker = tokio::task::spawn_blocking(move || {
                task_started.store(true, Ordering::Release);
                let (lock, condition) = &*task_gate;
                let mut released = lock.lock().expect("blocker gate");
                while !*released {
                    released = condition.wait(released).expect("blocker wait");
                }
            });
            timeout(Duration::from_secs(5), async {
                while !blocker_started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("blocking lane occupied");

            let active = Arc::new(Semaphore::new(1));
            let resolvers = Arc::new(Semaphore::new(1));
            let ran = Arc::new(AtomicUsize::new(0));
            let ran_job = Arc::clone(&ran);
            let attempt = submit_resolution(
                Arc::clone(&active).acquire_owned().await.expect("active"),
                Arc::clone(&resolvers)
                    .acquire_owned()
                    .await
                    .expect("resolver"),
                move || {
                    ran_job.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            );
            let accounting = Arc::clone(
                &attempt
                    .parts
                    .as_ref()
                    .expect("queued accounting")
                    .accounting,
            );
            assert_eq!(
                attempt
                    .parts
                    .as_ref()
                    .expect("queued attempt")
                    .state
                    .load(Ordering::Acquire),
                RESOLVER_QUEUED
            );
            let waiter = tokio::spawn(async move {
                let mut attempt = attempt;
                let _ = attempt.handle_mut().await;
                attempt.observed()
            });
            tokio::task::yield_now().await;
            waiter.abort();
            assert!(waiter
                .await
                .expect_err("queued request canceled")
                .is_cancelled());
            assert_eq!(active.available_permits(), 0);
            assert_eq!(resolvers.available_permits(), 0);
            assert!(Arc::clone(&resolvers).try_acquire_owned().is_err());
            assert_resolver_accounting(accounting.snapshot(), 1);
            assert_eq!(accounting.snapshot().cleanup_owned, 1);

            {
                let (lock, condition) = &*blocker_gate;
                *lock.lock().expect("blocker release") = true;
                condition.notify_all();
            }
            blocker.await.expect("blocker completion");
            timeout(Duration::from_secs(5), async {
                while active.available_permits() != 1 || resolvers.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("queued handle observed");
            assert_eq!(ran.load(Ordering::SeqCst), 0);
            assert_eq!(
                accounting.snapshot(),
                ResolverSnapshot {
                    total_submitted: 1,
                    ..ResolverSnapshot::default()
                }
            );
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_terminal_reason_observes_driver_before_returning_active_permit() {
        struct BlockingDrop {
            entered: Arc<AtomicBool>,
            gate: Arc<(Mutex<bool>, Condvar)>,
        }

        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                self.entered.store(true, Ordering::Release);
                let (lock, condition) = &*self.gate;
                let mut released = lock.lock().expect("driver drop gate");
                while !*released {
                    released = condition.wait(released).expect("driver drop wait");
                }
            }
        }

        for reason in [
            RetirementReason::RequestCancellation,
            RetirementReason::ReadyFailure,
            RetirementReason::SendFailure,
            RetirementReason::InvalidUpgrade,
            RetirementReason::ResponseBodyError,
            RetirementReason::ResponseBodyDrop,
            RetirementReason::NonReusableResponse,
            RetirementReason::PoolReadyTimeout,
            RetirementReason::PoolReadyFailure,
            RetirementReason::PoolFull,
            RetirementReason::PoolPoisoned,
            RetirementReason::UpgradeFailure,
            RetirementReason::WebSocketClosed,
            RetirementReason::WebSocketError,
            RetirementReason::WebSocketCancellation,
            RetirementReason::IdleOwnerDrop,
        ] {
            let (client, server) = tokio::io::duplex(1024);
            let (sender, connection) = http1::handshake::<_, RequestBody>(TokioIo::new(client))
                .await
                .expect("test sender");
            drop(connection);
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .acquire_owned()
                .await
                .expect("active permit");
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let created = Arc::new(AtomicBool::new(false));
            let drop_entered = Arc::new(AtomicBool::new(false));
            let driver_gate = Arc::clone(&gate);
            let driver_created = Arc::clone(&created);
            let driver_drop = Arc::clone(&drop_entered);
            let driver = tokio::spawn(async move {
                let _guard = BlockingDrop {
                    entered: driver_drop,
                    gate: driver_gate,
                };
                driver_created.store(true, Ordering::Release);
                pending::<()>().await;
            });
            timeout(Duration::from_secs(5), async {
                while !created.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver task started");

            let accounting = Arc::new(DriverRetirementAccounting::default());
            let owner = ActiveOwner::new(
                CompleteOwner::new(sender, driver, Arc::clone(&accounting)),
                permit,
            );
            schedule_retirement(owner.retirement_parts(reason));
            timeout(Duration::from_secs(5), async {
                while !drop_entered.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver abort began");
            assert_eq!(active.available_permits(), 0, "reason={reason:?}");
            assert!(Arc::clone(&active).try_acquire_owned().is_err());
            assert_eq!(accounting.counts(reason), (1, 0));
            assert_eq!(accounting.active_cleanups.load(Ordering::Acquire), 1);
            {
                let (lock, condition) = &*gate;
                *lock.lock().expect("driver release") = true;
                condition.notify_all();
            }
            timeout(Duration::from_secs(5), async {
                while active.available_permits() != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("driver joined before active release");
            assert_eq!(accounting.counts(reason), (1, 1));
            assert_eq!(accounting.active_cleanups.load(Ordering::Acquire), 0);
            drop(server);
        }
    }

    #[test]
    fn connect_and_handshake_cancellation_drop_io_before_u() {
        struct PendingIo {
            dropped: Arc<AtomicBool>,
            active: Arc<Semaphore>,
        }

        impl Future for PendingIo {
            type Output = io::Result<()>;

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Pending
            }
        }

        impl Drop for PendingIo {
            fn drop(&mut self) {
                assert_eq!(self.active.available_permits(), 0);
                self.dropped.store(true, Ordering::Release);
            }
        }

        for phase in ["connect", "handshake"] {
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .try_acquire_owned()
                .expect("phase permit");
            let dropped = Arc::new(AtomicBool::new(false));
            let future = PendingIo {
                dropped: Arc::clone(&dropped),
                active: Arc::clone(&active),
            };
            let phase_guard = ActivePhase::new(future, permit);
            drop(phase_guard);
            assert!(dropped.load(Ordering::Acquire), "phase={phase}");
            assert_eq!(active.available_permits(), 1, "phase={phase}");
        }
    }

    #[tokio::test]
    async fn connect_and_handshake_error_drop_io_before_returning_u() {
        struct ErrorIoDrop {
            dropped: Arc<AtomicBool>,
            active: Arc<Semaphore>,
        }

        impl Drop for ErrorIoDrop {
            fn drop(&mut self) {
                assert_eq!(self.active.available_permits(), 0);
                self.dropped.store(true, Ordering::Release);
            }
        }

        for phase in ["connect", "handshake"] {
            let active = Arc::new(Semaphore::new(1));
            let permit = Arc::clone(&active)
                .acquire_owned()
                .await
                .expect("error phase permit");
            let dropped = Arc::new(AtomicBool::new(false));
            let probe = ErrorIoDrop {
                dropped: Arc::clone(&dropped),
                active: Arc::clone(&active),
            };
            let operation = async move {
                drop(probe);
                Err::<(), io::Error>(io::Error::other("allowlisted fixture failure"))
            };
            let (result, permit) = ActivePhase::new(operation, permit).await;
            assert!(result.is_err(), "phase={phase}");
            assert!(dropped.load(Ordering::Acquire), "phase={phase}");
            assert_eq!(active.available_permits(), 0, "phase={phase}");
            drop(permit);
            assert_eq!(active.available_permits(), 1, "phase={phase}");
        }
    }

    #[test]
    fn pool_timeout_failure_full_and_poison_map_to_central_retirement_reasons() {
        assert_eq!(PoolReadinessOutcome::Ready.retirement_reason(), None);
        assert_eq!(
            PoolReadinessOutcome::Timeout.retirement_reason(),
            Some(RetirementReason::PoolReadyTimeout)
        );
        assert_eq!(
            PoolReadinessOutcome::Failure.retirement_reason(),
            Some(RetirementReason::PoolReadyFailure)
        );
        assert_eq!(PoolPlacementOutcome::Parked.retirement_reason(), None);
        assert_eq!(
            PoolPlacementOutcome::Full.retirement_reason(),
            Some(RetirementReason::PoolFull)
        );
        assert_eq!(
            PoolPlacementOutcome::Poisoned.retirement_reason(),
            Some(RetirementReason::PoolPoisoned)
        );
    }
}
