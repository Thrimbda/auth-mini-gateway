use crate::schema::{MAX_ARCHIVE_MEMBERS, TASK_CAP_BYTES};
use crate::seal::{sha256_hex, ustar_path_parts, validate_relative_path, SealManifest};
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const BLOCK_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    pub path: String,
    pub bytes: Vec<u8>,
}

pub fn canonical_archive(root: &Path, seal: &SealManifest) -> Result<Vec<u8>> {
    seal.validate()?;
    if u64::try_from(seal.entries.len()).unwrap_or(u64::MAX) >= MAX_ARCHIVE_MEMBERS {
        return Err(Error::new(
            "seal member count exceeds canonical archive limit",
        ));
    }
    let mut members = Vec::with_capacity(seal.entries.len() + 1);
    for entry in &seal.entries {
        let bytes = fs::read(root.join(&entry.path))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != entry.bytes
            || sha256_hex(&bytes) != entry.sha256
        {
            return Err(Error::new(format!(
                "source member differs from seal: {}",
                entry.path
            )));
        }
        members.push(ArchiveMember {
            path: entry.path.clone(),
            bytes,
        });
    }
    let seal_bytes = fs::read(root.join("seal.json"))?;
    members.push(ArchiveMember {
        path: "seal.json".to_owned(),
        bytes: seal_bytes,
    });
    canonical_archive_from_members(&members)
}

pub fn canonical_archive_from_members(members: &[ArchiveMember]) -> Result<Vec<u8>> {
    let mut ordered = members.to_vec();
    ordered.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let mut unique = BTreeSet::new();
    let mut projected = 1_024_u64;
    for member in &ordered {
        validate_relative_path(&member.path)?;
        if !unique.insert(member.path.clone()) {
            return Err(Error::new("duplicate canonical archive path"));
        }
        let length = u64::try_from(member.bytes.len())
            .map_err(|_| Error::new("archive member length overflow"))?;
        let padded = length
            .checked_add(511)
            .map(|value| (value / 512) * 512)
            .ok_or_else(|| Error::new("archive padding overflow"))?;
        projected = projected
            .checked_add(512)
            .and_then(|value| value.checked_add(padded))
            .ok_or_else(|| Error::new("archive length overflow"))?;
    }
    if projected > TASK_CAP_BYTES {
        return Err(Error::new(
            "canonical archive projection exceeds bounded allocation limit",
        ));
    }
    let capacity = usize::try_from(projected)
        .map_err(|_| Error::new("canonical archive does not fit memory"))?;
    let mut output = Vec::with_capacity(capacity);
    for member in &ordered {
        output.extend_from_slice(&canonical_header(
            &member.path,
            u64::try_from(member.bytes.len()).map_err(|_| Error::new("member length overflow"))?,
        )?);
        output.extend_from_slice(&member.bytes);
        let padding = (BLOCK_BYTES - (member.bytes.len() % BLOCK_BYTES)) % BLOCK_BYTES;
        output.resize(output.len() + padding, 0);
    }
    output.resize(output.len() + 2 * BLOCK_BYTES, 0);
    if output.len() != capacity {
        return Err(Error::new("canonical archive projection mismatch"));
    }
    Ok(output)
}

pub fn parse_canonical_archive(bytes: &[u8]) -> Result<Vec<ArchiveMember>> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > TASK_CAP_BYTES
        || bytes.len() < 2 * BLOCK_BYTES
        || !bytes.len().is_multiple_of(BLOCK_BYTES)
    {
        return Err(Error::new(
            "canonical archive length is not block-aligned with two end blocks",
        ));
    }
    let mut offset = 0_usize;
    let mut members = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    let mut paths = BTreeSet::new();
    loop {
        let header_end = offset
            .checked_add(BLOCK_BYTES)
            .ok_or_else(|| Error::new("archive offset overflow"))?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| Error::new("truncated canonical archive header"))?;
        if header.iter().all(|byte| *byte == 0) {
            let second_end = header_end
                .checked_add(BLOCK_BYTES)
                .ok_or_else(|| Error::new("archive end offset overflow"))?;
            let second = bytes
                .get(header_end..second_end)
                .ok_or_else(|| Error::new("canonical archive has only one end block"))?;
            if !second.iter().all(|byte| *byte == 0) || second_end != bytes.len() {
                return Err(Error::new(
                    "canonical archive end blocks/trailing bytes are invalid",
                ));
            }
            break;
        }
        let name = parse_nul_field(&header[0..100], "name")?;
        let prefix = parse_nul_field(&header[345..500], "prefix")?;
        let path_bytes = if prefix.is_empty() {
            name
        } else {
            let mut path = prefix;
            path.push(b'/');
            path.extend_from_slice(&name);
            path
        };
        let path = String::from_utf8(path_bytes)
            .map_err(|_| Error::new("canonical archive path is not UTF-8"))?;
        validate_relative_path(&path)?;
        let size = parse_octal(&header[124..136], "size")?;
        let expected = canonical_header(&path, size)?;
        if header != expected {
            return Err(Error::new(format!(
                "canonical ustar metadata/checksum mismatch for {path}"
            )));
        }
        if previous
            .as_ref()
            .is_some_and(|value| value.as_slice() >= path.as_bytes())
            || !paths.insert(path.clone())
        {
            return Err(Error::new(
                "canonical archive paths are not strictly byte-sorted",
            ));
        }
        previous = Some(path.as_bytes().to_vec());
        let payload_start = header_end;
        let size_usize = usize::try_from(size)
            .map_err(|_| Error::new("archive member size does not fit usize"))?;
        let payload_end = payload_start
            .checked_add(size_usize)
            .ok_or_else(|| Error::new("archive payload offset overflow"))?;
        let payload = bytes
            .get(payload_start..payload_end)
            .ok_or_else(|| Error::new("truncated canonical archive payload"))?
            .to_vec();
        let padding = (BLOCK_BYTES - (size_usize % BLOCK_BYTES)) % BLOCK_BYTES;
        let next = payload_end
            .checked_add(padding)
            .ok_or_else(|| Error::new("archive padding offset overflow"))?;
        let padding_bytes = bytes
            .get(payload_end..next)
            .ok_or_else(|| Error::new("truncated canonical archive padding"))?;
        if padding_bytes.iter().any(|byte| *byte != 0) {
            return Err(Error::new("canonical archive padding is not zero"));
        }
        members.push(ArchiveMember {
            path,
            bytes: payload,
        });
        if u64::try_from(members.len()).unwrap_or(u64::MAX) > MAX_ARCHIVE_MEMBERS {
            return Err(Error::new("canonical archive member-count limit exceeded"));
        }
        offset = next;
    }
    Ok(members)
}

fn canonical_header(path: &str, size: u64) -> Result<[u8; BLOCK_BYTES]> {
    validate_relative_path(path)?;
    let (prefix, name) = ustar_path_parts(path)
        .ok_or_else(|| Error::new("path does not fit canonical ustar name/prefix"))?;
    let mut header = [0_u8; BLOCK_BYTES];
    write_bytes(&mut header[0..100], name.as_bytes(), "name")?;
    write_octal(&mut header[100..108], 0o444, "mode")?;
    write_octal(&mut header[108..116], 0, "uid")?;
    write_octal(&mut header[116..124], 0, "gid")?;
    write_octal(&mut header[124..136], size, "size")?;
    write_octal(&mut header[136..148], 0, "mtime")?;
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_octal(&mut header[329..337], 0, "devmajor")?;
    write_octal(&mut header[337..345], 0, "devminor")?;
    write_bytes(&mut header[345..500], prefix.as_bytes(), "prefix")?;
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum_text = format!("{checksum:06o}\0 ");
    if checksum_text.len() != 8 {
        return Err(Error::new("ustar checksum does not fit canonical field"));
    }
    header[148..156].copy_from_slice(checksum_text.as_bytes());
    Ok(header)
}

fn write_bytes(field: &mut [u8], value: &[u8], name: &str) -> Result<()> {
    if value.len() > field.len() {
        return Err(Error::new(format!("ustar {name} does not fit field")));
    }
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

fn write_octal(field: &mut [u8], value: u64, name: &str) -> Result<()> {
    let digits = field
        .len()
        .checked_sub(1)
        .ok_or_else(|| Error::new("empty ustar numeric field"))?;
    let text = format!("{value:0digits$o}\0");
    if text.len() != field.len() {
        return Err(Error::new(format!(
            "ustar {name} does not fit canonical octal field"
        )));
    }
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

fn parse_nul_field(field: &[u8], name: &str) -> Result<Vec<u8>> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(Error::new(format!("ustar {name} has bytes after NUL")));
    }
    Ok(field[..end].to_vec())
}

fn parse_octal(field: &[u8], name: &str) -> Result<u64> {
    let digits = field
        .strip_suffix(&[0])
        .ok_or_else(|| Error::new(format!("ustar {name} lacks NUL terminator")))?;
    if digits.is_empty() || digits.iter().any(|byte| !matches!(byte, b'0'..=b'7')) {
        return Err(Error::new(format!("ustar {name} is not canonical octal")));
    }
    let text = std::str::from_utf8(digits)
        .map_err(|_| Error::new(format!("ustar {name} is not ASCII")))?;
    u64::from_str_radix(text, 8)
        .map_err(|_| Error::new(format!("ustar {name} octal value overflow")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<ArchiveMember> {
        vec![
            ArchiveMember {
                path: "z".to_owned(),
                bytes: b"last".to_vec(),
            },
            ArchiveMember {
                path: "a/b".to_owned(),
                bytes: b"first".to_vec(),
            },
        ]
    }

    #[test]
    fn canonical_ustar_round_trip_and_golden_hash_are_stable() {
        let archive = canonical_archive_from_members(&fixture()).expect("archive");
        assert_eq!(archive.len(), 3_072);
        assert_eq!(
            sha256_hex(&archive),
            "a4a4f45d8839072a2228bb7ac4fcaabd0e6b3765827432b3a336933fdfbc09e1"
        );
        let parsed = parse_canonical_archive(&archive).expect("parse");
        assert_eq!(parsed[0].path, "a/b");
        assert_eq!(parsed[1].path, "z");
        assert_eq!(
            canonical_archive_from_members(&parsed).expect("reconstruct"),
            archive
        );
    }

    #[test]
    fn canonical_header_pins_all_metadata_and_checksum_bytes() {
        let archive = canonical_archive_from_members(&[ArchiveMember {
            path: "x".to_owned(),
            bytes: vec![1],
        }])
        .expect("archive");
        assert_eq!(&archive[100..108], b"0000444\0");
        assert_eq!(&archive[108..116], b"0000000\0");
        assert_eq!(&archive[116..124], b"0000000\0");
        assert_eq!(&archive[136..148], b"00000000000\0");
        assert_eq!(archive[156], b'0');
        assert_eq!(&archive[257..263], b"ustar\0");
        assert_eq!(&archive[263..265], b"00");
        assert!(archive[265..329].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn malformed_header_padding_end_blocks_order_and_trailing_data_are_rejected() {
        let valid = canonical_archive_from_members(&fixture()).expect("valid archive");
        for index in [100_usize, 148, 156, 257, 263] {
            let mut malformed = valid.clone();
            malformed[index] ^= 1;
            assert!(parse_canonical_archive(&malformed).is_err());
        }
        let mut bad_padding = valid.clone();
        bad_padding[512 + 5] = 1;
        assert!(parse_canonical_archive(&bad_padding).is_err());
        assert!(parse_canonical_archive(&valid[..valid.len() - 512]).is_err());
        let mut trailing = valid.clone();
        trailing.extend_from_slice(&[0; 512]);
        assert!(parse_canonical_archive(&trailing).is_err());

        let mut reordered = Vec::new();
        reordered.extend_from_slice(&valid[1024..2048]);
        reordered.extend_from_slice(&valid[..1024]);
        reordered.extend_from_slice(&valid[2048..]);
        assert!(parse_canonical_archive(&reordered).is_err());
    }

    #[test]
    fn unsigned_utf8_byte_sorting_is_canonical() {
        let archive = canonical_archive_from_members(&[
            ArchiveMember {
                path: "é".to_owned(),
                bytes: Vec::new(),
            },
            ArchiveMember {
                path: "z".to_owned(),
                bytes: Vec::new(),
            },
        ])
        .expect("archive");
        let parsed = parse_canonical_archive(&archive).expect("parse");
        assert_eq!(
            parsed.iter().map(|member| &member.path).collect::<Vec<_>>(),
            vec!["z", "é"]
        );
    }
}
