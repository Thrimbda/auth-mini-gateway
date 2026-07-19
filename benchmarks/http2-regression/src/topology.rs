//! Frozen treatment topology and deterministic workload corpus primitives.

use crate::schema::{Arm, Workload};
use crate::{Error, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CORPUS_SCHEMA: &str = "amg-http2-perf/corpus/v1";
pub const CORPUS_BYTES: usize = 1_048_576;
pub const CHUNK_BYTES: usize = 16_384;
pub const CHUNK_COUNT: usize = 64;
pub const SSE_EVENTS: usize = 16;
pub const SSE_DATA_BYTES: usize = 128;
pub const FIXED_CORPUS_SEED: [u8; 32] = [
    0x51, 0x8e, 0x24, 0xb1, 0xc5, 0xa3, 0x91, 0x7d, 0xf4, 0x33, 0x09, 0x6e, 0x88, 0x10, 0x62, 0xbd,
    0x47, 0xb9, 0x2c, 0xda, 0x13, 0xa0, 0xe7, 0x5f, 0x69, 0x34, 0x01, 0xce, 0xab, 0x72, 0x9d, 0x04,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    H1,
    H2,
}

impl Protocol {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::H1 => "h1",
            Self::H2 => "h2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayObject {
    Baseline,
    Candidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmTopology {
    pub arm: Arm,
    pub gateway: GatewayObject,
    pub downstream: Protocol,
    pub upstream: Protocol,
}

impl ArmTopology {
    #[must_use]
    pub const fn for_arm(arm: Arm) -> Self {
        match arm {
            Arm::B11 => Self {
                arm,
                gateway: GatewayObject::Baseline,
                downstream: Protocol::H1,
                upstream: Protocol::H1,
            },
            Arm::C11 => Self {
                arm,
                gateway: GatewayObject::Candidate,
                downstream: Protocol::H1,
                upstream: Protocol::H1,
            },
            Arm::C21 => Self {
                arm,
                gateway: GatewayObject::Candidate,
                downstream: Protocol::H2,
                upstream: Protocol::H1,
            },
            Arm::C12 => Self {
                arm,
                gateway: GatewayObject::Candidate,
                downstream: Protocol::H1,
                upstream: Protocol::H2,
            },
            Arm::C22 => Self {
                arm,
                gateway: GatewayObject::Candidate,
                downstream: Protocol::H2,
                upstream: Protocol::H2,
            },
        }
    }

    #[must_use]
    pub fn direct_protocols(self) -> Vec<Protocol> {
        let mut protocols = BTreeSet::new();
        protocols.insert(self.downstream);
        protocols.insert(self.upstream);
        protocols.into_iter().collect()
    }
}

#[derive(Clone)]
pub struct Corpus {
    bytes: Vec<u8>,
    seed: [u8; 32],
}

impl Corpus {
    #[must_use]
    pub fn fixed() -> Self {
        Self::new(FIXED_CORPUS_SEED)
    }

    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        let mut bytes = Vec::with_capacity(CORPUS_BYTES);
        let blocks = CORPUS_BYTES.div_ceil(32);
        for block in 0..blocks {
            let mut digest = Sha256::new();
            digest.update(b"amg-http2-perf/v1/payload");
            digest.update(seed);
            digest.update((block as u64).to_be_bytes());
            bytes.extend_from_slice(&digest.finalize());
        }
        bytes.truncate(CORPUS_BYTES);
        Self { bytes, seed }
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn get_body(&self) -> &[u8] {
        &self.bytes[..64]
    }

    pub fn chunks(&self) -> impl Iterator<Item = &[u8]> {
        self.bytes.chunks_exact(CHUNK_BYTES)
    }

    #[must_use]
    pub fn sse_data(&self, event: usize) -> [u8; SSE_DATA_BYTES] {
        let start = event * SSE_DATA_BYTES;
        let mut output = [0_u8; SSE_DATA_BYTES];
        for (destination, source) in output
            .iter_mut()
            .zip(self.bytes[start..start + SSE_DATA_BYTES].iter())
        {
            *destination = b'a' + (*source % 26);
        }
        output
    }

    #[must_use]
    pub fn sse_stream(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(SSE_EVENTS * (SSE_DATA_BYTES + 16));
        for event in 0..SSE_EVENTS {
            output.extend_from_slice(format!("id: {event}\n").as_bytes());
            output.extend_from_slice(b"data: ");
            output.extend_from_slice(&self.sse_data(event));
            output.extend_from_slice(b"\n\n");
        }
        output
    }

    #[must_use]
    pub fn websocket_mask(&self, operation_id: u128) -> [u8; 4] {
        let mut digest = Sha256::new();
        digest.update(b"amg-http2-perf/v1/ws-mask");
        digest.update(self.seed);
        digest.update(operation_id.to_be_bytes());
        digest.finalize()[..4]
            .try_into()
            .expect("four digest bytes")
    }

    #[must_use]
    pub fn sha256(&self) -> String {
        crate::seal::sha256_hex(&self.bytes)
    }
}

#[must_use]
pub const fn operation_id(phase: u16, lane: u16, sequence: u64) -> u128 {
    ((phase as u128) << 112) | ((lane as u128) << 96) | sequence as u128
}

#[must_use]
pub fn operation_id_text(value: u128) -> String {
    format!("{value:032x}")
}

/// Derives a connection identity independently from the operation identity.
/// This is called before an operation's timed boundary.
#[must_use]
pub fn planned_connection_id(phase: u16, lane: u16, sequence: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(b"amg-http2-perf/v1/connection");
    digest.update(phase.to_be_bytes());
    digest.update(lane.to_be_bytes());
    digest.update(sequence.to_be_bytes());
    format!("{:x}", digest.finalize())
}

pub fn parse_operation_id(value: &str) -> Result<u128> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new(
            "operation ID must be exactly 32 hexadecimal digits",
        ));
    }
    u128::from_str_radix(value, 16).map_err(|_| Error::new("operation ID is invalid"))
}

#[must_use]
pub fn masked_ping(corpus: &Corpus, operation_id: u128, lane: u16, sequence: u64) -> Vec<u8> {
    let mut payload = [0_u8; 8];
    payload[..2].copy_from_slice(&lane.to_be_bytes());
    payload[2..].copy_from_slice(&sequence.to_be_bytes()[2..]);
    let mask = corpus.websocket_mask(operation_id);
    let mut frame = Vec::with_capacity(14);
    frame.extend_from_slice(&[0x89, 0x88]);
    frame.extend_from_slice(&mask);
    for (index, byte) in payload.into_iter().enumerate() {
        frame.push(byte ^ mask[index % 4]);
    }
    frame
}

pub fn parse_masked_ping(frame: &[u8]) -> Result<[u8; 8]> {
    if frame.len() != 14 || frame[0] != 0x89 || frame[1] != 0x88 {
        return Err(Error::new(
            "expected one final masked RFC6455 Ping with 8-byte payload",
        ));
    }
    let mask: [u8; 4] = frame[2..6]
        .try_into()
        .map_err(|_| Error::new("Ping mask width"))?;
    let mut payload = [0_u8; 8];
    for index in 0..8 {
        payload[index] = frame[6 + index] ^ mask[index % 4];
    }
    Ok(payload)
}

#[must_use]
pub fn unmasked_pong(payload: [u8; 8]) -> Vec<u8> {
    let mut frame = vec![0x8a, 0x08];
    frame.extend_from_slice(&payload);
    frame
}

pub fn parse_unmasked_pong(frame: &[u8]) -> Result<[u8; 8]> {
    if frame.len() != 10 || frame[0] != 0x8a || frame[1] != 0x08 {
        return Err(Error::new(
            "expected one final unmasked RFC6455 Pong with 8-byte payload",
        ));
    }
    frame[2..]
        .try_into()
        .map_err(|_| Error::new("Pong payload width"))
}

#[must_use]
pub fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finalize())
}

#[must_use]
pub fn workload_path(workload: Workload) -> &'static str {
    match workload {
        Workload::Get => "/bench/get",
        Workload::Upload1Mib => "/bench/upload",
        Workload::Download1Mib => "/bench/download",
        Workload::Sse => "/bench/sse",
        Workload::WebSocket => "/bench/websocket",
    }
}

pub fn parse_workload(value: &str) -> Result<Workload> {
    Workload::ALL
        .into_iter()
        .find(|workload| workload.code() == value)
        .ok_or_else(|| Error::new(format!("unknown workload `{value}`")))
}

pub fn parse_arm(value: &str) -> Result<Arm> {
    Arm::ALL
        .into_iter()
        .find(|arm| arm.code() == value)
        .ok_or_else(|| Error::new(format!("unknown arm `{value}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_topologies_and_direct_mappings_are_exact() {
        let expected = [
            (Arm::B11, Protocol::H1, Protocol::H1, vec![Protocol::H1]),
            (Arm::C11, Protocol::H1, Protocol::H1, vec![Protocol::H1]),
            (
                Arm::C21,
                Protocol::H2,
                Protocol::H1,
                vec![Protocol::H1, Protocol::H2],
            ),
            (
                Arm::C12,
                Protocol::H1,
                Protocol::H2,
                vec![Protocol::H1, Protocol::H2],
            ),
            (Arm::C22, Protocol::H2, Protocol::H2, vec![Protocol::H2]),
        ];
        for (arm, downstream, upstream, direct) in expected {
            let topology = ArmTopology::for_arm(arm);
            assert_eq!(topology.downstream, downstream);
            assert_eq!(topology.upstream, upstream);
            assert_eq!(topology.direct_protocols(), direct);
        }
    }

    #[test]
    fn corpus_has_exact_chunks_get_and_sse_shape() {
        let corpus = Corpus::fixed();
        assert_eq!(corpus.bytes().len(), CORPUS_BYTES);
        assert_eq!(corpus.get_body().len(), 64);
        assert_eq!(corpus.chunks().count(), CHUNK_COUNT);
        assert!(corpus.chunks().all(|chunk| chunk.len() == CHUNK_BYTES));
        let sse = corpus.sse_stream();
        assert_eq!(
            sse.windows(4).filter(|window| *window == b"data").count(),
            SSE_EVENTS
        );
        assert!(sse.ends_with(b"\n\n"));
    }

    #[test]
    fn websocket_ping_and_pong_are_real_control_frames() {
        let corpus = Corpus::fixed();
        let id = operation_id(3, 7, 9);
        let ping = masked_ping(&corpus, id, 7, 9);
        let payload = parse_masked_ping(&ping).expect("Ping");
        assert_eq!(&payload[..2], &7_u16.to_be_bytes());
        assert_eq!(
            parse_unmasked_pong(&unmasked_pong(payload)).unwrap(),
            payload
        );
        assert!(parse_masked_ping(&unmasked_pong(payload)).is_err());
    }

    #[test]
    fn operation_identity_is_fixed_width_and_rejects_aliases() {
        let value = operation_id(1, 16, 42);
        let text = operation_id_text(value);
        assert_eq!(text.len(), 32);
        assert_eq!(parse_operation_id(&text).unwrap(), value);
        assert!(parse_operation_id("2a").is_err());
    }

    #[test]
    fn planned_connection_identity_is_distinct_and_deterministic() {
        let first = planned_connection_id(1, 2, 3);
        assert_eq!(first.len(), 64);
        assert_eq!(first, planned_connection_id(1, 2, 3));
        assert_ne!(first, planned_connection_id(1, 2, 4));
        assert_ne!(first, operation_id_text(operation_id(1, 2, 3)));
    }
}
