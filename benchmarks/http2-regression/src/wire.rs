//! Fixed-memory cleartext HTTP/2 frame observation.
//!
//! This module deliberately observes bytes at the transport boundary.  It is
//! not a replacement HTTP/2 implementation: Hyper/h2 still owns protocol
//! processing.  The observer only retains the small, decision-bearing frame
//! facts required by the benchmark and never derives them from requested
//! configuration.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify};

const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_BYTES: usize = 9;
const SETTINGS: u8 = 0x4;
const HEADERS: u8 = 0x1;
const ACK: u8 = 0x1;
const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
const MAX_SETTINGS_PAYLOAD: usize = 256;
const MAX_UNCLAIMED_STREAMS: usize = 256;
const MAX_OBSERVED_STREAMS: usize = 1_026;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointSide {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct H2WireEvidence {
    pub connection_id: u64,
    pub client_preface_seen: bool,
    pub local_initial_settings_seen: bool,
    pub peer_initial_settings_seen: bool,
    pub local_settings_ack_seen: bool,
    pub peer_settings_ack_seen: bool,
    pub local_settings_frames: u64,
    pub peer_settings_frames: u64,
    pub local_settings_ack_frames: u64,
    pub peer_settings_ack_frames: u64,
    pub enable_connect_protocol_seen: bool,
    pub request_headers: u64,
    pub claimed_request_streams: u64,
    pub request_stream_ids: Vec<u32>,
    pub request_stream_ids_complete: bool,
    pub first_request_stream_id: Option<u32>,
    pub last_request_stream_id: Option<u32>,
    pub request_stream_sequence_sha256: String,
    pub extended_connect_headers: u64,
    pub early_extended_connect_headers: u64,
    pub parse_error: Option<String>,
}

impl H2WireEvidence {
    pub fn validate(&self, require_extended_connect: bool) -> Result<()> {
        if self.connection_id == 0
            || !self.client_preface_seen
            || !self.local_initial_settings_seen
            || !self.peer_initial_settings_seen
            || !self.local_settings_ack_seen
            || !self.peer_settings_ack_seen
            || self.local_settings_frames == 0
            || self.peer_settings_frames == 0
            || self.local_settings_ack_frames == 0
            || self.peer_settings_ack_frames == 0
            || self.parse_error.is_some()
            || self.early_extended_connect_headers != 0
            || (require_extended_connect
                && (!self.enable_connect_protocol_seen || self.extended_connect_headers == 0))
        {
            return Err(Error::new(
                "wire-observed H2 preface/SETTINGS/ACK/CONNECT proof is incomplete",
            ));
        }
        let expected_last = self
            .request_headers
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| Error::new("wire-observed H2 stream sequence exceeds u32"))?;
        if self.request_headers == 0
            || self.claimed_request_streams != self.request_headers
            || (self.request_stream_ids_complete
                && self.request_stream_ids.len() as u64 != self.request_headers)
            || self.first_request_stream_id != Some(1)
            || self.last_request_stream_id != Some(expected_last)
            || self.request_stream_sequence_sha256
                != request_stream_sequence_sha256(self.request_headers)?
        {
            return Err(Error::new("wire-observed H2 request stream proof is empty"));
        }
        crate::schema::validate_sha256(
            "wire request stream sequence",
            &self.request_stream_sequence_sha256,
        )
    }
}

#[derive(Debug)]
struct FrameParser {
    expect_preface: bool,
    preface_offset: usize,
    header: [u8; FRAME_HEADER_BYTES],
    header_len: usize,
    payload_remaining: usize,
    frame_type: u8,
    frame_flags: u8,
    frame_stream_id: u32,
    settings: [u8; MAX_SETTINGS_PAYLOAD],
    settings_len: usize,
}

impl FrameParser {
    fn new(expect_preface: bool) -> Self {
        Self {
            expect_preface,
            preface_offset: 0,
            header: [0; FRAME_HEADER_BYTES],
            header_len: 0,
            payload_remaining: 0,
            frame_type: 0,
            frame_flags: 0,
            frame_stream_id: 0,
            settings: [0; MAX_SETTINGS_PAYLOAD],
            settings_len: 0,
        }
    }

    fn feed(
        &mut self,
        mut bytes: &[u8],
        direction: Direction,
        state: &mut WireState,
    ) -> Result<()> {
        if self.expect_preface && self.preface_offset < CLIENT_PREFACE.len() {
            let remaining = CLIENT_PREFACE.len() - self.preface_offset;
            let take = remaining.min(bytes.len());
            if bytes[..take] != CLIENT_PREFACE[self.preface_offset..self.preface_offset + take] {
                return Err(Error::new(
                    "cleartext H2 client preface/version bytes are wrong",
                ));
            }
            self.preface_offset += take;
            bytes = &bytes[take..];
            if self.preface_offset == CLIENT_PREFACE.len() {
                state.client_preface_seen = true;
            }
        }

        while !bytes.is_empty() {
            if self.header_len < FRAME_HEADER_BYTES {
                let take = (FRAME_HEADER_BYTES - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_len += take;
                bytes = &bytes[take..];
                if self.header_len != FRAME_HEADER_BYTES {
                    continue;
                }
                self.begin_frame(direction, state)?;
                if self.payload_remaining == 0 {
                    self.finish_frame(direction, state)?;
                    self.header_len = 0;
                    continue;
                }
            }

            let take = self.payload_remaining.min(bytes.len());
            if self.frame_type == SETTINGS {
                let end = self
                    .settings_len
                    .checked_add(take)
                    .ok_or_else(|| Error::new("SETTINGS payload length overflow"))?;
                if end > self.settings.len() {
                    return Err(Error::new(
                        "SETTINGS payload exceeds fixed observer capacity",
                    ));
                }
                self.settings[self.settings_len..end].copy_from_slice(&bytes[..take]);
                self.settings_len = end;
            }
            self.payload_remaining -= take;
            bytes = &bytes[take..];
            if self.payload_remaining == 0 {
                self.finish_frame(direction, state)?;
                self.header_len = 0;
            }
        }
        Ok(())
    }

    fn begin_frame(&mut self, direction: Direction, state: &mut WireState) -> Result<()> {
        self.payload_remaining = (usize::from(self.header[0]) << 16)
            | (usize::from(self.header[1]) << 8)
            | usize::from(self.header[2]);
        self.frame_type = self.header[3];
        self.frame_flags = self.header[4];
        if self.header[5] & 0x80 != 0 {
            return Err(Error::new("HTTP/2 frame stream reserved bit is set"));
        }
        self.frame_stream_id = u32::from_be_bytes([
            self.header[5],
            self.header[6],
            self.header[7],
            self.header[8],
        ]);
        self.settings_len = 0;
        if self.frame_type == SETTINGS
            && (self.frame_stream_id != 0
                || (self.frame_flags & ACK != 0 && self.payload_remaining != 0)
                || (self.frame_flags & ACK == 0 && !self.payload_remaining.is_multiple_of(6))
                || self.payload_remaining > MAX_SETTINGS_PAYLOAD)
        {
            return Err(Error::new("malformed HTTP/2 SETTINGS frame"));
        }
        if self.frame_type == HEADERS && state.request_direction(direction) {
            state.observe_request_headers(self.frame_stream_id)?;
        }
        Ok(())
    }

    fn finish_frame(&mut self, direction: Direction, state: &mut WireState) -> Result<()> {
        if self.frame_type != SETTINGS {
            return Ok(());
        }
        if self.frame_flags & ACK != 0 {
            return state.observe_settings_ack(direction);
        }
        let mut enable_connect = false;
        for setting in self.settings[..self.settings_len].chunks_exact(6) {
            let id = u16::from_be_bytes([setting[0], setting[1]]);
            let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
            if id == ENABLE_CONNECT_PROTOCOL {
                if value != 1 {
                    return Err(Error::new(
                        "SETTINGS_ENABLE_CONNECT_PROTOCOL has a non-one value",
                    ));
                }
                enable_connect = true;
            }
        }
        state.observe_initial_settings(direction, enable_connect)
    }
}

#[derive(Debug)]
struct WireState {
    side: EndpointSide,
    connection_id: u64,
    client_preface_seen: bool,
    local_initial_settings_seen: bool,
    peer_initial_settings_seen: bool,
    local_settings_ack_seen: bool,
    peer_settings_ack_seen: bool,
    local_settings_frames: u64,
    peer_settings_frames: u64,
    local_settings_ack_frames: u64,
    peer_settings_ack_frames: u64,
    enable_connect_protocol_seen: bool,
    request_headers: u64,
    claimed_request_streams: u64,
    first_request_stream_id: Option<u32>,
    last_request_stream_id: Option<u32>,
    request_stream_hasher: Sha256,
    unclaimed_streams: VecDeque<u32>,
    observed_streams: Vec<u32>,
    observed_streams_complete: bool,
    connect_header_pending: bool,
    extended_connect_headers: u64,
    early_extended_connect_headers: u64,
    extended_connect_streams: Vec<u32>,
    parse_error: Option<String>,
}

impl WireState {
    fn new(side: EndpointSide, connection_id: u64) -> Result<Self> {
        if connection_id == 0 {
            return Err(Error::new("wire connection ID must be nonzero"));
        }
        let mut request_stream_hasher = Sha256::new();
        request_stream_hasher.update(b"amg-http2-perf/h2-observed-streams/v1\0");
        Ok(Self {
            side,
            connection_id,
            client_preface_seen: false,
            local_initial_settings_seen: false,
            peer_initial_settings_seen: false,
            local_settings_ack_seen: false,
            peer_settings_ack_seen: false,
            local_settings_frames: 0,
            peer_settings_frames: 0,
            local_settings_ack_frames: 0,
            peer_settings_ack_frames: 0,
            enable_connect_protocol_seen: false,
            request_headers: 0,
            claimed_request_streams: 0,
            first_request_stream_id: None,
            last_request_stream_id: None,
            request_stream_hasher,
            unclaimed_streams: VecDeque::with_capacity(MAX_UNCLAIMED_STREAMS),
            observed_streams: Vec::with_capacity(MAX_OBSERVED_STREAMS),
            observed_streams_complete: true,
            connect_header_pending: false,
            extended_connect_headers: 0,
            early_extended_connect_headers: 0,
            extended_connect_streams: Vec::with_capacity(64),
            parse_error: None,
        })
    }

    fn request_direction(&self, direction: Direction) -> bool {
        matches!(
            (self.side, direction),
            (EndpointSide::Client, Direction::Write) | (EndpointSide::Server, Direction::Read)
        )
    }

    fn is_local_direction(&self, direction: Direction) -> bool {
        matches!(
            (self.side, direction),
            (EndpointSide::Client, Direction::Write) | (EndpointSide::Server, Direction::Write)
        )
    }

    fn observe_initial_settings(
        &mut self,
        direction: Direction,
        enable_connect: bool,
    ) -> Result<()> {
        let (field, count) = if self.is_local_direction(direction) {
            (
                &mut self.local_initial_settings_seen,
                &mut self.local_settings_frames,
            )
        } else {
            (
                &mut self.peer_initial_settings_seen,
                &mut self.peer_settings_frames,
            )
        };
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::new("SETTINGS frame count overflow"))?;
        if *field {
            // Later non-ACK SETTINGS are legal, but only the first frame is the
            // initial exchange used as topology proof.
            return Ok(());
        }
        *field = true;
        let capability_from_server = matches!(
            (self.side, direction),
            (EndpointSide::Client, Direction::Read) | (EndpointSide::Server, Direction::Write)
        );
        if capability_from_server && enable_connect {
            self.enable_connect_protocol_seen = true;
        }
        Ok(())
    }

    fn observe_settings_ack(&mut self, direction: Direction) -> Result<()> {
        if self.is_local_direction(direction) {
            if !self.peer_initial_settings_seen {
                return Err(Error::new(
                    "local SETTINGS ACK preceded the peer initial SETTINGS",
                ));
            }
            self.local_settings_ack_seen = true;
            self.local_settings_ack_frames = self
                .local_settings_ack_frames
                .checked_add(1)
                .ok_or_else(|| Error::new("local SETTINGS ACK count overflow"))?;
        } else {
            if !self.local_initial_settings_seen {
                return Err(Error::new(
                    "peer SETTINGS ACK preceded the local initial SETTINGS",
                ));
            }
            self.peer_settings_ack_seen = true;
            self.peer_settings_ack_frames = self
                .peer_settings_ack_frames
                .checked_add(1)
                .ok_or_else(|| Error::new("peer SETTINGS ACK count overflow"))?;
        }
        Ok(())
    }

    fn observe_request_headers(&mut self, stream_id: u32) -> Result<()> {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            return Err(Error::new(
                "client request HEADERS used a zero/even HTTP/2 stream ID",
            ));
        }
        if self
            .last_request_stream_id
            .is_some_and(|previous| stream_id <= previous)
        {
            return Err(Error::new(
                "client request HEADERS stream IDs are duplicate or non-monotonic",
            ));
        }
        if self.unclaimed_streams.len() >= MAX_UNCLAIMED_STREAMS {
            return Err(Error::new(
                "unclaimed HTTP/2 stream queue exceeds fixed observer capacity",
            ));
        }
        self.request_headers = self
            .request_headers
            .checked_add(1)
            .ok_or_else(|| Error::new("request HEADERS count overflow"))?;
        self.first_request_stream_id.get_or_insert(stream_id);
        self.last_request_stream_id = Some(stream_id);
        self.request_stream_hasher.update(stream_id.to_be_bytes());
        self.unclaimed_streams.push_back(stream_id);
        if self.observed_streams.len() < MAX_OBSERVED_STREAMS {
            self.observed_streams.push(stream_id);
        } else {
            self.observed_streams_complete = false;
        }
        if self.connect_header_pending {
            self.observe_extended_connect(stream_id)?;
            self.connect_header_pending = false;
        }
        Ok(())
    }

    fn observe_extended_connect(&mut self, stream_id: u32) -> Result<()> {
        if !self.observed_streams.contains(&stream_id)
            || self.extended_connect_streams.contains(&stream_id)
            || self.extended_connect_streams.len() >= 64
        {
            return Err(Error::new(
                "Extended CONNECT does not bind one observed unique HEADERS stream",
            ));
        }
        self.extended_connect_streams.push(stream_id);
        self.extended_connect_headers = self
            .extended_connect_headers
            .checked_add(1)
            .ok_or_else(|| Error::new("Extended CONNECT count overflow"))?;
        if !self.enable_connect_protocol_seen {
            self.early_extended_connect_headers = self
                .early_extended_connect_headers
                .checked_add(1)
                .ok_or_else(|| Error::new("early Extended CONNECT count overflow"))?;
        }
        Ok(())
    }

    fn snapshot(&self) -> H2WireEvidence {
        H2WireEvidence {
            connection_id: self.connection_id,
            client_preface_seen: self.client_preface_seen,
            local_initial_settings_seen: self.local_initial_settings_seen,
            peer_initial_settings_seen: self.peer_initial_settings_seen,
            local_settings_ack_seen: self.local_settings_ack_seen,
            peer_settings_ack_seen: self.peer_settings_ack_seen,
            local_settings_frames: self.local_settings_frames,
            peer_settings_frames: self.peer_settings_frames,
            local_settings_ack_frames: self.local_settings_ack_frames,
            peer_settings_ack_frames: self.peer_settings_ack_frames,
            enable_connect_protocol_seen: self.enable_connect_protocol_seen,
            request_headers: self.request_headers,
            claimed_request_streams: self.claimed_request_streams,
            request_stream_ids: self.observed_streams.clone(),
            request_stream_ids_complete: self.observed_streams_complete,
            first_request_stream_id: self.first_request_stream_id,
            last_request_stream_id: self.last_request_stream_id,
            request_stream_sequence_sha256: format!(
                "{:x}",
                self.request_stream_hasher.clone().finalize()
            ),
            extended_connect_headers: self.extended_connect_headers,
            early_extended_connect_headers: self.early_extended_connect_headers,
            parse_error: self.parse_error.clone(),
        }
    }
}

#[derive(Debug)]
struct Shared {
    state: Mutex<WireState>,
    notify: Notify,
    request_lock: Arc<AsyncMutex<()>>,
}

#[derive(Debug, Clone)]
pub struct H2FrameObserver {
    shared: Arc<Shared>,
}

impl H2FrameObserver {
    pub fn client(connection_id: u64) -> Result<Self> {
        Self::new(EndpointSide::Client, connection_id)
    }

    pub fn server(connection_id: u64) -> Result<Self> {
        Self::new(EndpointSide::Server, connection_id)
    }

    fn new(side: EndpointSide, connection_id: u64) -> Result<Self> {
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(WireState::new(side, connection_id)?),
                notify: Notify::new(),
                request_lock: Arc::new(AsyncMutex::new(())),
            }),
        })
    }

    #[must_use]
    pub fn request_lock(&self) -> Arc<AsyncMutex<()>> {
        Arc::clone(&self.shared.request_lock)
    }

    pub fn mark_next_headers_as_extended_connect(&self) -> Result<()> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| Error::new("H2 wire observer state poisoned"))?;
        if state.connect_header_pending {
            return Err(Error::new("duplicate pending Extended CONNECT marker"));
        }
        state.connect_header_pending = true;
        Ok(())
    }

    pub fn claim_stream_now(&self) -> Result<u32> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| Error::new("H2 wire observer state poisoned"))?;
        let stream = state
            .unclaimed_streams
            .pop_front()
            .ok_or_else(|| Error::new("request reached HTTP service without observed HEADERS"))?;
        state.claimed_request_streams = state
            .claimed_request_streams
            .checked_add(1)
            .ok_or_else(|| Error::new("claimed H2 request stream count overflow"))?;
        Ok(stream)
    }

    pub fn mark_observed_stream_as_extended_connect(&self, stream_id: u32) -> Result<()> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| Error::new("H2 wire observer state poisoned"))?;
        state.observe_extended_connect(stream_id)?;
        drop(state);
        self.shared.notify.notify_waiters();
        Ok(())
    }

    pub async fn claim_stream(&self, cap: Duration) -> Result<u32> {
        self.wait_for(cap, |state| !state.unclaimed_streams.is_empty())
            .await?;
        self.claim_stream_now()
    }

    pub async fn wait_initial_exchange(
        &self,
        require_enable_connect: bool,
        cap: Duration,
    ) -> Result<H2WireEvidence> {
        self.wait_for(cap, |state| {
            state.client_preface_seen
                && state.local_initial_settings_seen
                && state.peer_initial_settings_seen
                && state.local_settings_ack_seen
                && state.peer_settings_ack_seen
                && (!require_enable_connect || state.enable_connect_protocol_seen)
        })
        .await?;
        let evidence = self.snapshot()?;
        if evidence.parse_error.is_some() {
            return Err(Error::new("HTTP/2 frame observer recorded a parse error"));
        }
        Ok(evidence)
    }

    async fn wait_for(&self, cap: Duration, predicate: impl Fn(&WireState) -> bool) -> Result<()> {
        let future = async {
            loop {
                let notified = self.shared.notify.notified();
                {
                    let state = self
                        .shared
                        .state
                        .lock()
                        .map_err(|_| Error::new("H2 wire observer state poisoned"))?;
                    if let Some(error) = &state.parse_error {
                        return Err(Error::new(format!(
                            "HTTP/2 frame observation failed: {error}"
                        )));
                    }
                    if predicate(&state) {
                        return Ok(());
                    }
                }
                notified.await;
            }
        };
        tokio::time::timeout(cap, future)
            .await
            .map_err(|_| Error::new("wire-observed HTTP/2 proof exceeded its bounded wait"))?
    }

    pub fn snapshot(&self) -> Result<H2WireEvidence> {
        Ok(self
            .shared
            .state
            .lock()
            .map_err(|_| Error::new("H2 wire observer state poisoned"))?
            .snapshot())
    }

    fn feed(&self, parser: &mut FrameParser, direction: Direction, bytes: &[u8]) -> io::Result<()> {
        let result = self
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("H2 wire observer state poisoned"))
            .and_then(|mut state| {
                parser.feed(bytes, direction, &mut state).map_err(|error| {
                    state.parse_error.get_or_insert_with(|| error.to_string());
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })
            });
        self.shared.notify.notify_waiters();
        result
    }
}

pub fn request_stream_sequence_sha256(count: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"amg-http2-perf/h2-observed-streams/v1\0");
    for index in 0..count {
        let stream_id = index
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| Error::new("H2 request stream sequence exceeds u32"))?;
        hasher.update(stream_id.to_be_bytes());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub struct ObservedH2Io {
    inner: TcpStream,
    observer: H2FrameObserver,
    read_parser: FrameParser,
    write_parser: FrameParser,
}

impl ObservedH2Io {
    pub fn client(inner: TcpStream, observer: H2FrameObserver) -> Self {
        Self {
            inner,
            observer,
            read_parser: FrameParser::new(false),
            write_parser: FrameParser::new(true),
        }
    }

    pub fn server(inner: TcpStream, observer: H2FrameObserver) -> Self {
        Self {
            inner,
            observer,
            read_parser: FrameParser::new(true),
            write_parser: FrameParser::new(false),
        }
    }
}

impl AsyncRead for ObservedH2Io {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                this.observer.feed(
                    &mut this.read_parser,
                    Direction::Read,
                    &buffer.filled()[before..],
                )?;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for ObservedH2Io {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, bytes) {
            Poll::Ready(Ok(written)) => {
                this.observer
                    .feed(&mut this.write_parser, Direction::Write, &bytes[..written])?;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(frame_type: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len();
        let mut bytes = vec![
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
            frame_type,
            flags,
        ];
        bytes.extend_from_slice(&stream.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn observer_rejects_wrong_preface_settings_and_early_connect() {
        let observer = H2FrameObserver::client(1).expect("observer");
        let mut parser = FrameParser::new(true);
        let mut wrong = CLIENT_PREFACE.to_vec();
        wrong[9] = b'1';
        assert!(observer
            .feed(&mut parser, Direction::Write, &wrong)
            .is_err());

        let observer = H2FrameObserver::client(1).expect("observer");
        let mut parser = FrameParser::new(false);
        let malformed = frame(SETTINGS, ACK, 0, &[0; 6]);
        assert!(observer
            .feed(&mut parser, Direction::Read, &malformed)
            .is_err());

        let observer = H2FrameObserver::client(1).expect("observer");
        observer
            .mark_next_headers_as_extended_connect()
            .expect("mark CONNECT");
        let mut parser = FrameParser::new(true);
        let mut bytes = CLIENT_PREFACE.to_vec();
        bytes.extend_from_slice(&frame(HEADERS, 0x4, 1, &[]));
        observer
            .feed(&mut parser, Direction::Write, &bytes)
            .expect("parse early CONNECT");
        assert_eq!(
            observer.snapshot().unwrap().early_extended_connect_headers,
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_settings_proof_has_a_bounded_failure() {
        let observer = H2FrameObserver::client(1).expect("observer");
        assert!(observer
            .wait_initial_exchange(false, Duration::from_millis(1))
            .await
            .is_err());
    }

    #[test]
    fn settings_capability_and_actual_stream_are_observed() {
        let observer = H2FrameObserver::client(7).expect("observer");
        let mut write = FrameParser::new(true);
        let mut outbound = CLIENT_PREFACE.to_vec();
        outbound.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        observer
            .feed(&mut write, Direction::Write, &outbound)
            .expect("outbound frames");
        let mut read = FrameParser::new(false);
        let capability = [0, 8, 0, 0, 0, 1];
        observer
            .feed(
                &mut read,
                Direction::Read,
                &frame(SETTINGS, 0, 0, &capability),
            )
            .expect("peer SETTINGS");
        let mut outbound = frame(SETTINGS, ACK, 0, &[]);
        outbound.extend_from_slice(&frame(HEADERS, 0x4, 1, &[]));
        observer
            .feed(&mut write, Direction::Write, &outbound)
            .expect("local ACK and request HEADERS");
        observer
            .feed(&mut read, Direction::Read, &frame(SETTINGS, ACK, 0, &[]))
            .expect("peer ACK");
        assert_eq!(observer.claim_stream_now().unwrap(), 1);
        let evidence = observer.snapshot().expect("snapshot");
        assert!(evidence.client_preface_seen);
        assert!(evidence.enable_connect_protocol_seen);
        assert_eq!(evidence.first_request_stream_id, Some(1));
        assert_eq!(evidence.claimed_request_streams, 1);
        evidence.validate(false).expect("complete wire proof");
    }
}
