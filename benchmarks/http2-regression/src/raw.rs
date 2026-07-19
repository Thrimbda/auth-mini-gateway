use crate::json;
use crate::schema::{EvidenceClass, RawArmMetadata, JSON_MAX_BYTES};
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const LATENCY_MAGIC: &[u8; 8] = b"AMGLAT01";
const LATENCY_SCHEMA: u16 = 1;
const LATENCY_ENDIAN_LE: u8 = 1;
const LATENCY_RECORD_WIDTH: u32 = 8;
const LATENCY_HEADER_BYTES: usize = 32;

pub const COMMON_ARM_MEMBERS: [&str; 8] = [
    "metadata.json",
    "quiet.json",
    "thread-map.json",
    "thread-lifecycle.bin",
    "session-clock.bin",
    "resources.bin",
    "endpoints.bin",
    "operation-summary.bin",
];

pub fn encode_latencies(class: EvidenceClass, latencies_ns: &[u64]) -> Result<Vec<u8>> {
    if !class.has_latencies() {
        return Err(Error::new("S/D evidence forbids a latency payload"));
    }
    if latencies_ns.is_empty() || latencies_ns.contains(&0) {
        return Err(Error::new(
            "C/A latency payload must be nonempty and nonzero",
        ));
    }
    let count = u64::try_from(latencies_ns.len())
        .map_err(|_| Error::new("latency count does not fit u64"))?;
    let payload_len = latencies_ns
        .len()
        .checked_mul(8)
        .ok_or_else(|| Error::new("latency payload length overflow"))?;
    let payload_len_u32 =
        u32::try_from(payload_len).map_err(|_| Error::new("latency payload exceeds u32"))?;
    let total_len = LATENCY_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or_else(|| Error::new("latency file length overflow"))?;
    let mut output = Vec::with_capacity(total_len);
    output.extend_from_slice(LATENCY_MAGIC);
    output.extend_from_slice(&LATENCY_SCHEMA.to_le_bytes());
    output.push(class.byte());
    output.push(LATENCY_ENDIAN_LE);
    output.extend_from_slice(&LATENCY_RECORD_WIDTH.to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    output.extend_from_slice(&payload_len_u32.to_le_bytes());
    output.extend_from_slice(&[0_u8; 4]);
    for latency in latencies_ns {
        output.extend_from_slice(&latency.to_le_bytes());
    }
    let crc = crc32(&output[LATENCY_HEADER_BYTES..]);
    output[28..32].copy_from_slice(&crc.to_le_bytes());
    Ok(output)
}

pub fn decode_latencies(
    bytes: &[u8],
    expected_class: EvidenceClass,
    expected_count: u64,
    ceiling: u64,
) -> Result<Vec<u64>> {
    if !expected_class.has_latencies() {
        return Err(Error::new("S/D evidence may not decode a latency member"));
    }
    if bytes.len() < LATENCY_HEADER_BYTES || &bytes[..8] != LATENCY_MAGIC {
        return Err(Error::new(
            "latency header is truncated or has the wrong magic",
        ));
    }
    let schema = u16::from_le_bytes(
        bytes[8..10]
            .try_into()
            .map_err(|_| Error::new("latency schema field is truncated"))?,
    );
    let class = EvidenceClass::from_byte(bytes[10])?;
    let endian = bytes[11];
    let width = u32::from_le_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| Error::new("latency width field is truncated"))?,
    );
    let count = u64::from_le_bytes(
        bytes[16..24]
            .try_into()
            .map_err(|_| Error::new("latency count field is truncated"))?,
    );
    let payload_len = u32::from_le_bytes(
        bytes[24..28]
            .try_into()
            .map_err(|_| Error::new("latency length field is truncated"))?,
    );
    let expected_crc = u32::from_le_bytes(
        bytes[28..32]
            .try_into()
            .map_err(|_| Error::new("latency CRC field is truncated"))?,
    );
    if schema != LATENCY_SCHEMA
        || class != expected_class
        || endian != LATENCY_ENDIAN_LE
        || width != LATENCY_RECORD_WIDTH
    {
        return Err(Error::new("latency schema/class/endian/width mismatch"));
    }
    if count != expected_count || count == 0 || count > ceiling {
        return Err(Error::new(
            "latency record count mismatch or ceiling overflow",
        ));
    }
    let expected_payload = count
        .checked_mul(u64::from(LATENCY_RECORD_WIDTH))
        .ok_or_else(|| Error::new("latency payload calculation overflow"))?;
    if u64::from(payload_len) != expected_payload
        || bytes.len()
            != LATENCY_HEADER_BYTES
                .checked_add(
                    usize::try_from(payload_len)
                        .map_err(|_| Error::new("latency payload length does not fit usize"))?,
                )
                .ok_or_else(|| Error::new("latency total length overflow"))?
    {
        return Err(Error::new("latency payload length/count mismatch"));
    }
    if crc32(&bytes[LATENCY_HEADER_BYTES..]) != expected_crc {
        return Err(Error::new("latency payload CRC mismatch"));
    }
    let mut latencies = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for record in bytes[LATENCY_HEADER_BYTES..].chunks_exact(8) {
        let latency = u64::from_le_bytes(
            record
                .try_into()
                .map_err(|_| Error::new("truncated latency record"))?,
        );
        if latency == 0 {
            return Err(Error::new("zero latency record is invalid"));
        }
        latencies.push(latency);
    }
    Ok(latencies)
}

pub fn write_latencies_new(path: &Path, class: EvidenceClass, latencies_ns: &[u64]) -> Result<()> {
    let bytes = encode_latencies(class, latencies_ns)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| Error::new(format!("cannot create {}: {error}", path.display())))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn validate_evidence_tree(root: &Path) -> Result<Vec<PathBuf>> {
    let mut metadata_paths = Vec::new();
    collect_named_files(root, "metadata.json", &mut metadata_paths)?;
    for path in &metadata_paths {
        let metadata: RawArmMetadata = json::read_strict(path, JSON_MAX_BYTES)?;
        metadata.validate()?;
        let leaf = path
            .parent()
            .ok_or_else(|| Error::new("metadata path has no parent"))?;
        validate_arm_leaf(leaf, &metadata)?;
    }
    Ok(metadata_paths)
}

fn collect_named_files(directory: &Path, name: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::new(format!(
            "evidence root is not a directory: {}",
            directory.display()
        )));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new(format!(
                "evidence link is forbidden: {}",
                path.display()
            )));
        }
        if metadata.file_type().is_dir() {
            collect_named_files(&path, name, output)?;
        } else if metadata.file_type().is_file() {
            if path.file_name().and_then(|value| value.to_str()) == Some(name) {
                output.push(path);
            }
        } else {
            return Err(Error::new(format!(
                "non-regular evidence member is forbidden: {}",
                path.display()
            )));
        }
    }
    output.sort();
    Ok(())
}

fn validate_arm_leaf(leaf: &Path, metadata: &RawArmMetadata) -> Result<()> {
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(leaf)? {
        let entry = entry?;
        let path = entry.path();
        let file_metadata = fs::symlink_metadata(&path)?;
        if !file_metadata.file_type().is_file() {
            return Err(Error::new(format!(
                "arm leaf contains a non-regular member: {}",
                path.display()
            )));
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| Error::new("arm member name is not UTF-8"))?
            .to_owned();
        if !actual.insert(name) {
            return Err(Error::new("duplicate arm member name"));
        }
    }
    let mut expected: BTreeSet<String> = COMMON_ARM_MEMBERS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    if metadata.class.has_latencies() {
        expected.insert("latencies.u64le".to_owned());
    }
    if actual != expected {
        return Err(Error::new(format!(
            "arm member set differs from class {:?}: expected {expected:?}, got {actual:?}",
            metadata.class
        )));
    }
    if metadata.class.has_latencies() {
        let bytes = fs::read(leaf.join("latencies.u64le"))?;
        decode_latencies(
            &bytes,
            metadata.class,
            metadata.drained_operations,
            metadata.latency_record_ceiling,
        )?;
    }
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_encoding_is_golden_little_endian_and_bounded() {
        let encoded = encode_latencies(EvidenceClass::A, &[1, 0x0102_0304_0506_0708])
            .expect("encode latencies");
        assert_eq!(&encoded[..8], LATENCY_MAGIC);
        assert_eq!(encoded[10], b'A');
        assert_eq!(&encoded[32..40], &1_u64.to_le_bytes());
        assert_eq!(&encoded[40..48], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(
            decode_latencies(&encoded, EvidenceClass::A, 2, 2).expect("decode"),
            vec![1, 0x0102_0304_0506_0708]
        );
        assert!(decode_latencies(&encoded, EvidenceClass::A, 2, 1).is_err());
    }

    #[test]
    fn malformed_latency_header_count_endian_crc_and_class_are_rejected() {
        let valid = encode_latencies(EvidenceClass::C, &[10, 20]).expect("valid encoding");
        for index in [0_usize, 8, 10, 11, 12, 16, 24, 28, 32, valid.len() - 1] {
            let mut malformed = valid.clone();
            malformed[index] ^= 1;
            assert!(decode_latencies(&malformed, EvidenceClass::C, 2, 2).is_err());
        }
        assert!(decode_latencies(&valid[..valid.len() - 1], EvidenceClass::C, 2, 2).is_err());
        assert!(decode_latencies(&valid, EvidenceClass::A, 2, 2).is_err());
        assert!(decode_latencies(&valid, EvidenceClass::S, 2, 2).is_err());
    }

    #[test]
    fn scout_and_direct_latency_encoding_is_forbidden() {
        assert!(encode_latencies(EvidenceClass::S, &[1]).is_err());
        assert!(encode_latencies(EvidenceClass::D, &[1]).is_err());
        assert!(encode_latencies(EvidenceClass::C, &[]).is_err());
        assert!(encode_latencies(EvidenceClass::A, &[0]).is_err());
    }
}
