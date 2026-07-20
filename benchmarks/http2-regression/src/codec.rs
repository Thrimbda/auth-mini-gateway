use crate::schema::{
    CodecIdentity, ResolvedZstdParameters, ZstdParameterProgram, TASK_CAP_BYTES,
    ZSTD_SAFE_CHECKSUM, ZSTD_SYS_CHECKSUM,
};
use crate::seal::sha256_hex;
use crate::{Error, Result};
use zstd_safe::{CCtx, CParameter, DCtx, Strategy};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const NESTED_LOCK: &[u8] = include_bytes!("../Cargo.lock");
const CODEC_MODULE: &[u8] = include_bytes!("codec.rs");
const RESOLVER_ID: &[u8] = b"amg-http2-perf/zstd-level9-resolver/v1\0window=clamp(ceil_log2(max(1,size)),10,23);hash=min(window,21);chain=min(window,20);search=4;minMatch=4;targetLength=16;strategy=ZSTD_btlazy2";

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
        binding_package_checksum_sha256: ZSTD_SAFE_CHECKSUM.to_owned(),
        native_package_checksum_sha256: ZSTD_SYS_CHECKSUM.to_owned(),
        nested_lock_sha256: sha256_hex(NESTED_LOCK),
        codec_module_sha256: sha256_hex(CODEC_MODULE),
        resolver_sha256: sha256_hex(RESOLVER_ID),
        target_identity: crate::statistics::math_target_identity(),
        parameter_program: crate::schema::ZSTD_PROGRAM_SCHEMA.to_owned(),
    }
}

pub fn resolve_parameters(canonical_length: u64) -> Result<ResolvedZstdParameters> {
    if canonical_length > TASK_CAP_BYTES {
        return Err(Error::new(
            "canonical archive exceeds the bounded codec allocation limit",
        ));
    }
    let program = ZstdParameterProgram::fixed();
    let source_bits = 64_u32
        .checked_sub(canonical_length.max(1).saturating_sub(1).leading_zeros())
        .ok_or_else(|| Error::new("canonical length bit-width underflow"))?;
    let window_log = source_bits.clamp(10, 23);
    let hash_log = window_log.min(21);
    let chain_log = window_log.min(20);
    let search_log = 4;
    let min_match = 4;
    let target_length = 16;
    let strategy = 6;
    let ldm_hash_log = 0;
    let ldm_min_match = 0;
    let ldm_bucket_size_log = 0;
    let ldm_hash_rate_log = 0;
    let job_size = 0;
    let overlap_size_log = 0;
    let target_cblock_size = 0;
    let map = format!(
        "compressionLevel={}\nwindowLog={}\nhashLog={}\nchainLog={}\nsearchLog={}\nminMatch={}\ntargetLength={}\nstrategy={}\nnbWorkers={}\nchecksumFlag={}\ncontentSizeFlag={}\ndictIDFlag={}\nenableLongDistanceMatching={}\nldmHashLog={}\nldmMinMatch={}\nldmBucketSizeLog={}\nldmHashRateLog={}\njobSize={}\noverlapSizeLog={}\ntargetCBlockSize={}\npledgedSrcSize={}\n",
        program.compression_level,
        window_log,
        hash_log,
        chain_log,
        search_log,
        min_match,
        target_length,
        strategy,
        program.nb_workers,
        u8::from(program.checksum_flag),
        u8::from(program.content_size_flag),
        u8::from(program.dict_id_flag),
        u8::from(program.long_distance_matching),
        ldm_hash_log,
        ldm_min_match,
        ldm_bucket_size_log,
        ldm_hash_rate_log,
        job_size,
        overlap_size_log,
        target_cblock_size,
        canonical_length,
    );
    let resolved = ResolvedZstdParameters {
        program,
        pledged_source_size: canonical_length,
        window_log,
        hash_log,
        chain_log,
        search_log,
        min_match,
        target_length,
        strategy,
        ldm_hash_log,
        ldm_min_match,
        ldm_bucket_size_log,
        ldm_hash_rate_log,
        job_size,
        overlap_size_log,
        target_cblock_size,
        parameter_map_sha256: sha256_hex(map.as_bytes()),
    };
    resolved.validate()?;
    Ok(resolved)
}

pub fn encode(input: &[u8], parameters: &ResolvedZstdParameters) -> Result<Vec<u8>> {
    parameters.validate()?;
    if parameters != &resolve_parameters(parameters.pledged_source_size)? {
        return Err(Error::new(
            "Zstandard parameter map differs from the explicit sealed resolver output",
        ));
    }
    let input_len = u64::try_from(input.len()).map_err(|_| Error::new("input length overflow"))?;
    if input_len != parameters.pledged_source_size {
        return Err(Error::new("input length differs from pledged source size"));
    }
    if input_len > TASK_CAP_BYTES {
        return Err(Error::new("codec input exceeds bounded allocation limit"));
    }
    encode_at_level(input, parameters, parameters.program.compression_level)
}

fn encode_at_level(
    input: &[u8],
    parameters: &ResolvedZstdParameters,
    level: i32,
) -> Result<Vec<u8>> {
    let mut context = CCtx::create();
    zstd(context.load_dictionary(&[]), "loadDictionary(empty)")?;
    zstd(
        context.set_parameter(CParameter::CompressionLevel(level)),
        "compressionLevel",
    )?;
    for (parameter, name) in [
        (CParameter::WindowLog(parameters.window_log), "windowLog"),
        (CParameter::HashLog(parameters.hash_log), "hashLog"),
        (CParameter::ChainLog(parameters.chain_log), "chainLog"),
        (CParameter::SearchLog(parameters.search_log), "searchLog"),
        (CParameter::MinMatch(parameters.min_match), "minMatch"),
        (
            CParameter::TargetLength(parameters.target_length),
            "targetLength",
        ),
        (
            CParameter::Strategy(strategy_from_i32(parameters.strategy)?),
            "strategy",
        ),
    ] {
        zstd(context.set_parameter(parameter), name)?;
    }
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
    for (parameter, name) in [
        (
            CParameter::LdmHashLog(parameters.ldm_hash_log),
            "ldmHashLog",
        ),
        (
            CParameter::LdmMinMatch(parameters.ldm_min_match),
            "ldmMinMatch",
        ),
        (
            CParameter::LdmBucketSizeLog(parameters.ldm_bucket_size_log),
            "ldmBucketSizeLog",
        ),
        (
            CParameter::LdmHashRateLog(parameters.ldm_hash_rate_log),
            "ldmHashRateLog",
        ),
        (CParameter::JobSize(parameters.job_size), "jobSize"),
        (
            CParameter::OverlapSizeLog(parameters.overlap_size_log),
            "overlapSizeLog",
        ),
        (
            CParameter::TargetCBlockSize(parameters.target_cblock_size),
            "targetCBlockSize",
        ),
    ] {
        zstd(context.set_parameter(parameter), name)?;
    }
    zstd(
        context.set_pledged_src_size(Some(parameters.pledged_source_size)),
        "pledgedSrcSize",
    )?;
    let capacity = zstd_safe::compress_bound(input.len());
    if u64::try_from(capacity).unwrap_or(u64::MAX) > TASK_CAP_BYTES {
        return Err(Error::new(
            "Zstandard compression bound exceeds the output allocation limit",
        ));
    }
    let mut output = vec![0_u8; capacity];
    let written = zstd(context.compress2(&mut output, input), "compress2")?;
    output.truncate(written);
    inspect_frame(&output, parameters.pledged_source_size)?;
    Ok(output)
}

pub fn decode(compressed: &[u8], expected_length: u64) -> Result<Vec<u8>> {
    if expected_length > TASK_CAP_BYTES
        || u64::try_from(compressed.len()).unwrap_or(u64::MAX) > TASK_CAP_BYTES
    {
        return Err(Error::new(
            "Zstandard frame exceeds bounded allocation limits",
        ));
    }
    inspect_frame(compressed, expected_length)?;
    let output_len = usize::try_from(expected_length)
        .map_err(|_| Error::new("decompressed length does not fit usize"))?;
    let mut output = vec![0_u8; output_len];
    let mut context = DCtx::create();
    zstd(
        context.load_dictionary(&[]),
        "decoder loadDictionary(empty)",
    )?;
    let written = zstd(context.decompress(&mut output, compressed), "decompress")?;
    if written != output_len {
        return Err(Error::new(
            "decompressed byte count differs from frame content size",
        ));
    }
    Ok(output)
}

pub fn current_executable_sha256() -> Result<String> {
    let executable = std::env::current_exe()?;
    let metadata = std::fs::symlink_metadata(&executable)?;
    if !metadata.file_type().is_file() || metadata.len() > TASK_CAP_BYTES {
        return Err(Error::new(
            "verifier executable is not a bounded regular file",
        ));
    }
    Ok(sha256_hex(&std::fs::read(executable)?))
}

fn strategy_from_i32(value: i32) -> Result<Strategy> {
    match value {
        6 => Ok(Strategy::ZSTD_btlazy2),
        _ => Err(Error::new("unsupported resolved Zstandard strategy")),
    }
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
    let mut context = CCtx::create();
    zstd(
        context.set_parameter(CParameter::CompressionLevel(level)),
        "alternate compressionLevel",
    )?;
    zstd(
        context.set_parameter(CParameter::NbWorkers(0)),
        "alternate nbWorkers",
    )?;
    zstd(
        context.set_parameter(CParameter::ChecksumFlag(true)),
        "alternate checksumFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::ContentSizeFlag(true)),
        "alternate contentSizeFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::DictIdFlag(false)),
        "alternate dictIDFlag",
    )?;
    zstd(
        context.set_parameter(CParameter::EnableLongDistanceMatching(false)),
        "alternate enableLongDistanceMatching",
    )?;
    zstd(
        context.set_pledged_src_size(Some(parameters.pledged_source_size)),
        "alternate pledgedSrcSize",
    )?;
    let mut output = vec![0_u8; zstd_safe::compress_bound(input.len())];
    let written = zstd(context.compress2(&mut output, input), "alternate compress2")?;
    output.truncate(written);
    inspect_frame(&output, parameters.pledged_source_size)?;
    Ok(output)
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

    #[test]
    fn explicit_parameter_and_identity_drift_are_rejected() {
        let input = b"explicit-parameter-fixture";
        let mut parameters = resolve_parameters(input.len() as u64).expect("parameters");
        parameters.window_log += 1;
        assert!(encode(input, &parameters).is_err());

        let mut identity = current_identity();
        identity.binding_package_checksum_sha256 = "00".repeat(32);
        assert!(identity.validate().is_err());
    }

    #[test]
    fn declared_expansion_bombs_fail_before_preallocation() {
        assert!(resolve_parameters(TASK_CAP_BYTES + 1).is_err());
        assert!(decode(&[0; 5], TASK_CAP_BYTES + 1).is_err());
    }
}
