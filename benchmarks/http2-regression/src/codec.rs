use crate::schema::{CodecIdentity, ResolvedZstdParameters, ZstdParameterProgram};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use zstd_safe::{CCtx, CParameter, DCtx};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const NESTED_LOCK: &[u8] = include_bytes!("../Cargo.lock");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameInspection {
    pub compressed_bytes: u64,
    pub content_bytes: u64,
    pub checksum_present: bool,
    pub dictionary_id_present: bool,
    pub frame_count: u8,
}

#[must_use]
pub fn current_identity() -> CodecIdentity {
    CodecIdentity {
        binding_name: "zstd-safe".to_owned(),
        binding_version: "7.2.4".to_owned(),
        native_name: "libzstd".to_owned(),
        native_version: zstd_safe::version_string().to_owned(),
        native_version_number: zstd_safe::version_number(),
        native_source_package: "zstd-sys-2.0.16+zstd.1.5.7".to_owned(),
        nested_lock_sha256: sha256_hex(NESTED_LOCK),
        parameter_program: crate::schema::ZSTD_PROGRAM_SCHEMA.to_owned(),
    }
}

pub fn resolve_parameters(canonical_length: u64) -> Result<ResolvedZstdParameters> {
    let resolved = ResolvedZstdParameters {
        program: ZstdParameterProgram::fixed(),
        pledged_source_size: canonical_length,
    };
    resolved.validate()?;
    Ok(resolved)
}

pub fn encode(input: &[u8], parameters: &ResolvedZstdParameters) -> Result<Vec<u8>> {
    parameters.validate()?;
    let input_len = u64::try_from(input.len()).map_err(|_| Error::new("input length overflow"))?;
    if input_len != parameters.pledged_source_size {
        return Err(Error::new("input length differs from pledged source size"));
    }
    encode_at_level(input, parameters, parameters.program.compression_level)
}

fn encode_at_level(
    input: &[u8],
    parameters: &ResolvedZstdParameters,
    level: i32,
) -> Result<Vec<u8>> {
    let mut context = CCtx::create();
    zstd(
        context.set_parameter(CParameter::CompressionLevel(level)),
        "compressionLevel",
    )?;
    zstd(
        context.set_parameter(CParameter::NbWorkers(parameters.program.nb_workers)),
        "nbWorkers",
    )?;
    zstd(
        context.set_parameter(CParameter::ChecksumFlag(parameters.program.checksum_flag)),
        "checksumFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::ContentSizeFlag(
            parameters.program.content_size_flag,
        )),
        "contentSizeFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::DictIdFlag(parameters.program.dict_id_flag)),
        "dictIDFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::EnableLongDistanceMatching(
            parameters.program.long_distance_matching,
        )),
        "enableLongDistanceMatching",
    )?;
    zstd(
        context.set_pledged_src_size(Some(parameters.pledged_source_size)),
        "pledgedSrcSize",
    )?;
    let capacity = zstd_safe::compress_bound(input.len());
    let mut output = vec![0_u8; capacity];
    let written = zstd(context.compress2(&mut output, input), "compress2")?;
    output.truncate(written);
    inspect_frame(&output, parameters.pledged_source_size)?;
    Ok(output)
}

pub fn decode(compressed: &[u8], expected_length: u64) -> Result<Vec<u8>> {
    inspect_frame(compressed, expected_length)?;
    let output_len = usize::try_from(expected_length)
        .map_err(|_| Error::new("decompressed length does not fit usize"))?;
    let mut output = vec![0_u8; output_len];
    let mut context = DCtx::create();
    let written = zstd(context.decompress(&mut output, compressed), "decompress")?;
    if written != output_len {
        return Err(Error::new(
            "decompressed byte count differs from frame content size",
        ));
    }
    Ok(output)
}

pub fn inspect_frame(compressed: &[u8], expected_length: u64) -> Result<FrameInspection> {
    if compressed.len() < 5 || compressed[..4] != ZSTD_MAGIC {
        return Err(Error::new("payload is not a canonical Zstandard frame"));
    }
    let descriptor = compressed[4];
    if descriptor & 0b0001_1000 != 0 {
        return Err(Error::new(
            "Zstandard frame uses reserved/unused descriptor bits",
        ));
    }
    let checksum_present = descriptor & 0b0000_0100 != 0;
    let dictionary_id_present = descriptor & 0b0000_0011 != 0;
    if !checksum_present || dictionary_id_present {
        return Err(Error::new(
            "Zstandard checksum/dictionary-ID flags differ from intent",
        ));
    }
    let first_frame_bytes = zstd(
        zstd_safe::find_frame_compressed_size(compressed),
        "findFrameCompressedSize",
    )?;
    if first_frame_bytes != compressed.len() {
        return Err(Error::new(
            "Zstandard payload has trailing bytes or multiple frames",
        ));
    }
    let content_size = zstd_safe::get_frame_content_size(compressed)
        .map_err(|error| Error::new(format!("getFrameContentSize: {error:?}")))?
        .ok_or_else(|| Error::new("Zstandard frame omits content size"))?;
    if content_size != expected_length {
        return Err(Error::new(format!(
            "Zstandard frame content size {content_size} != expected {expected_length}"
        )));
    }
    Ok(FrameInspection {
        compressed_bytes: u64::try_from(compressed.len())
            .map_err(|_| Error::new("compressed length overflow"))?,
        content_bytes: content_size,
        checksum_present,
        dictionary_id_present,
        frame_count: 1,
    })
}

fn zstd(result: zstd_safe::SafeResult, operation: &str) -> Result<usize> {
    result.map_err(|code| {
        Error::new(format!(
            "Zstandard {operation} failed: {}",
            zstd_safe::get_error_name(code)
        ))
    })
}

pub fn self_test() -> Result<()> {
    let input = b"amg-http2-regression deterministic zstandard self-test";
    let parameters = resolve_parameters(u64::try_from(input.len()).unwrap_or(u64::MAX))?;
    let first = encode(input, &parameters)?;
    let second = encode(input, &parameters)?;
    if first != second || decode(&first, parameters.pledged_source_size)? != input {
        return Err(Error::new("deterministic Zstandard self-test mismatch"));
    }
    let identity = current_identity();
    identity.validate()?;
    if identity.native_version != "1.5.7" || identity.native_version_number != 10_507 {
        return Err(Error::new(format!(
            "unexpected pinned libzstd runtime {} ({})",
            identity.native_version, identity.native_version_number
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_alternate_level(input: &[u8], level: i32) -> Result<Vec<u8>> {
    let parameters = resolve_parameters(u64::try_from(input.len()).unwrap_or(u64::MAX))?;
    encode_at_level(input, &parameters, level)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_identity_and_parameter_vector_are_exact() {
        let identity = current_identity();
        identity.validate().expect("codec identity");
        assert_eq!(identity.native_version, "1.5.7");
        assert_eq!(identity.native_version_number, 10_507);
        let parameters = resolve_parameters(123).expect("parameters");
        assert_eq!(parameters.program, ZstdParameterProgram::fixed());
        assert_eq!(parameters.pledged_source_size, 123);
    }

    #[test]
    fn deterministic_frame_has_checksum_content_size_no_dict_and_one_frame() {
        let input = b"deterministic frame bytes deterministic frame bytes";
        let parameters = resolve_parameters(input.len() as u64).expect("parameters");
        let first = encode(input, &parameters).expect("encode");
        let second = encode(input, &parameters).expect("encode again");
        assert_eq!(first, second);
        assert_eq!(
            inspect_frame(&first, input.len() as u64).expect("frame"),
            FrameInspection {
                compressed_bytes: first.len() as u64,
                content_bytes: input.len() as u64,
                checksum_present: true,
                dictionary_id_present: false,
                frame_count: 1,
            }
        );
        assert_eq!(decode(&first, input.len() as u64).expect("decode"), input);
    }

    #[test]
    fn valid_different_level_frame_decodes_but_fails_exact_recompression() {
        let mut input = Vec::new();
        for index in 0_u32..50_000 {
            input.extend_from_slice(b"canonical/member/path/with/repeated/structure/");
            input.extend_from_slice(&(index % 997).to_le_bytes());
            input.extend_from_slice(b"/metadata-and-payload-boundary\n");
        }
        let parameters = resolve_parameters(input.len() as u64).expect("parameters");
        let authoritative = encode(&input, &parameters).expect("level 9");
        let alternate = encode_alternate_level(&input, 1).expect("level 1");
        assert_eq!(
            decode(&alternate, input.len() as u64).expect("valid alternate"),
            input
        );
        assert_ne!(alternate, authoritative);
    }

    #[test]
    fn trailing_and_multiple_frames_are_rejected() {
        let input = b"frame";
        let parameters = resolve_parameters(input.len() as u64).expect("parameters");
        let frame = encode(input, &parameters).expect("frame");
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode(&trailing, input.len() as u64).is_err());
        let mut multiple = frame.clone();
        multiple.extend_from_slice(&frame);
        assert!(decode(&multiple, input.len() as u64).is_err());
    }
}
