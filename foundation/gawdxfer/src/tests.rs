//! Unit tests for the `gawdxfer` GX bulk-transfer contract.

use super::*;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_nanos();
    std::env::temp_dir().join(format!("gawdxfer-{label}-{}-{nanos}", std::process::id()))
}

#[test]
fn compute_chunks_handles_empty_exact_and_partial_files() {
    assert_eq!(compute_chunks(0, MIN_CHUNK_SIZE).unwrap(), 1);
    assert_eq!(compute_chunks(u64::from(MIN_CHUNK_SIZE) * 2, MIN_CHUNK_SIZE).unwrap(), 2);
    assert_eq!(compute_chunks(u64::from(MIN_CHUNK_SIZE) * 2 + 1, MIN_CHUNK_SIZE).unwrap(), 3);
    assert_eq!(compute_chunks(1, 0), Err(ChunkPlanError::ZeroChunkSize));
    assert_eq!(
        compute_chunks(1, MIN_CHUNK_SIZE - 1),
        Err(ChunkPlanError::ChunkSizeTooSmall {
            chunk_size: MIN_CHUNK_SIZE - 1,
            min: MIN_CHUNK_SIZE
        })
    );
    assert_eq!(
        compute_chunks(1, MAX_CHUNK_SIZE + 1),
        Err(ChunkPlanError::ChunkSizeTooLarge {
            chunk_size: MAX_CHUNK_SIZE + 1,
            max: MAX_CHUNK_SIZE
        })
    );
}

#[test]
fn compute_chunks_rejects_counts_that_do_not_fit_wire_type() {
    let file_size = (u64::from(u32::MAX) + 1) * u64::from(MIN_CHUNK_SIZE);
    assert!(matches!(
        compute_chunks(file_size, MIN_CHUNK_SIZE),
        Err(ChunkPlanError::TooManyChunks { .. })
    ));
}

#[test]
fn binary_frame_round_trips_header_and_raw_payload() {
    let header =
        ChunkFrameHeader::new("xfer-1".into(), 7, hash_bytes(b"payload")).with_request_id("req-9");
    let frame = encode_binary_frame(&header, b"payload").unwrap();
    let (decoded, payload): (ChunkFrameHeader, &[u8]) = decode_binary_frame(&frame).unwrap();
    assert_eq!(decoded, header);
    assert_eq!(payload, b"payload");
    assert!(frame.ends_with(b"payload"), "payload is carried as raw bytes");
}

#[test]
fn binary_frame_rejects_malformed_lengths() {
    assert_eq!(decode_binary_frame::<ChunkFrameHeader>(&[1, 2, 3]), Err(FrameError::TooShort));

    let over_cap = ((MAX_BINARY_FRAME_HEADER_BYTES + 1) as u32).to_be_bytes();
    assert_eq!(
        decode_binary_frame::<ChunkFrameHeader>(&over_cap),
        Err(FrameError::HeaderTooLarge {
            len: MAX_BINARY_FRAME_HEADER_BYTES + 1,
            max: MAX_BINARY_FRAME_HEADER_BYTES,
        })
    );

    let mut truncated = 8u32.to_be_bytes().to_vec();
    truncated.extend_from_slice(br#"{"x""#);
    assert_eq!(
        decode_binary_frame::<ChunkFrameHeader>(&truncated),
        Err(FrameError::Truncated { needed: 12, actual: truncated.len() })
    );
}

#[test]
fn chunk_frame_header_shape_is_bounded_and_sha256_hex() {
    let valid = ChunkFrameHeader::new("xfer-1".into(), 0, hash_bytes(b"chunk"));
    assert_eq!(valid.shape_error(), None);

    let mut wrong_type = valid.clone();
    wrong_type.message_type = "not.gx.chunk".into();
    assert!(wrong_type.shape_error().unwrap().contains("frame type"));

    let mut empty_transfer = valid.clone();
    empty_transfer.transfer_id.clear();
    assert!(empty_transfer.shape_error().unwrap().contains("transfer_id"));

    let oversized_request = valid.clone().with_request_id("r".repeat(MAX_REQUEST_ID_BYTES + 1));
    assert!(oversized_request.shape_error().unwrap().contains("request_id"));

    let mut uppercase_hash = valid.clone();
    uppercase_hash.chunk_hash = hash_bytes(b"chunk").to_uppercase();
    assert!(uppercase_hash.shape_error().unwrap().contains("lowercase hex"));

    let mut short_hash = valid;
    short_hash.chunk_hash = "abc".into();
    assert!(short_hash.shape_error().unwrap().contains("64 lowercase hex"));

    let zero_total =
        ChunkFrameHeader::new("xfer-1".into(), 0, hash_bytes(b"chunk")).with_total_chunks(0);
    assert!(zero_total.shape_error().unwrap().contains("total_chunks"));

    let out_of_range =
        ChunkFrameHeader::new("xfer-1".into(), 2, hash_bytes(b"chunk")).with_total_chunks(2);
    assert!(out_of_range.shape_error().unwrap().contains("out of range"));
}

fn valid_summary() -> TransferSummary {
    TransferSummary {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        filename: "artifact.so".into(),
        file_size: 2048,
        phase: "transferring".into(),
        chunks_done: 1,
        total_chunks: 2,
        bytes_transferred: 1024,
    }
}

#[test]
fn gx_control_messages_shape_check_bounded_metadata() {
    let init_download =
        InitDownload { path: "/tmp/artifact.so".into(), chunk_size: Some(MIN_CHUNK_SIZE) };
    assert_eq!(init_download.shape_error(), None);

    let mut bad_download = init_download.clone();
    bad_download.path = "bad\0path".into();
    assert!(bad_download.shape_error().unwrap().contains("NUL"));

    let mut bad_download = init_download;
    bad_download.chunk_size = Some(1);
    assert!(bad_download.shape_error().unwrap().contains("below minimum"));

    let init_upload = InitUpload {
        path: "/tmp".into(),
        filename: "artifact.so".into(),
        file_size: 5,
        file_hash: String::new(),
        chunk_size: MIN_CHUNK_SIZE,
        total_chunks: 1,
        mode: Some("0644".into()),
    };
    assert_eq!(init_upload.shape_error(), None);

    let mut bad_upload = init_upload.clone();
    bad_upload.filename = "../artifact.so".into();
    assert!(bad_upload.shape_error().unwrap().contains("path separators"));

    let mut bad_upload = init_upload.clone();
    bad_upload.file_hash = hash_bytes(b"artifact").to_uppercase();
    assert!(bad_upload.shape_error().unwrap().contains("lowercase hex"));

    let mut bad_upload = init_upload.clone();
    bad_upload.total_chunks = 2;
    assert!(bad_upload.shape_error().unwrap().contains("total_chunks"));

    let mut bad_upload = init_upload;
    bad_upload.mode = Some("09".into());
    assert!(bad_upload.shape_error().unwrap().contains("octal"));
}

#[test]
fn gx_result_and_status_messages_shape_check_counts_and_hashes() {
    let file_hash = hash_bytes(b"hello");
    let download = InitDownloadResult {
        transfer_id: "xfer-1".into(),
        file_size: 5,
        file_hash: file_hash.clone(),
        chunk_size: MIN_CHUNK_SIZE,
        total_chunks: 1,
        filename: "artifact.so".into(),
    };
    assert_eq!(download.shape_error(), None);

    let mut bad_download = download.clone();
    bad_download.filename = ".".into();
    assert!(bad_download.shape_error().unwrap().contains("relative directory"));

    let upload = InitUploadResult {
        transfer_id: "xfer-1".into(),
        chunk_size: MIN_CHUNK_SIZE,
        total_chunks: 1,
    };
    assert_eq!(upload.shape_error(), None);

    let mut bad_upload = upload;
    bad_upload.total_chunks = 0;
    assert!(bad_upload.shape_error().unwrap().contains("total_chunks"));

    let progress = Progress {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        path: "/tmp/artifact.so".into(),
        filename: "artifact.so".into(),
        chunks_done: 1,
        total_chunks: 2,
        bytes_transferred: 1024,
        file_size: 2048,
        elapsed_ms: 1,
        rate_bps: 1024,
    };
    assert_eq!(progress.shape_error(), None);

    let mut bad_progress = progress;
    bad_progress.bytes_transferred = 4096;
    assert!(bad_progress.shape_error().unwrap().contains("bytes_transferred"));

    let complete = Complete {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        path: "/tmp/artifact.so".into(),
        filename: "artifact.so".into(),
        file_size: 5,
        file_hash,
        elapsed_ms: 1,
    };
    assert_eq!(complete.shape_error(), None);

    let mut bad_complete = complete;
    bad_complete.file_hash = "not-a-hash".into();
    assert!(bad_complete.shape_error().unwrap().contains("file_hash"));
}

#[test]
fn gx_lifecycle_messages_shape_check_errors_resume_and_lists() {
    let chunk_header = ChunkHeader {
        transfer_id: "xfer-1".into(),
        chunk_index: 0,
        chunk_hash: hash_bytes(b"chunk"),
    };
    assert_eq!(chunk_header.shape_error(), None);

    let mut bad_chunk_header = chunk_header;
    bad_chunk_header.chunk_hash = "abc".into();
    assert!(bad_chunk_header.shape_error().unwrap().contains("chunk_hash"));

    let ok_ack = ChunkAck { transfer_id: "xfer-1".into(), chunk_index: 0, ok: true, error: None };
    assert_eq!(ok_ack.shape_error(), None);

    let failed_ack =
        ChunkAck { transfer_id: "xfer-1".into(), chunk_index: 0, ok: false, error: None };
    assert!(failed_ack.shape_error().unwrap().contains("must carry an error"));

    let transfer_error = TransferError {
        transfer_id: String::new(),
        code: "FILE_NOT_FOUND".into(),
        message: "missing".into(),
        recoverable: false,
    };
    assert_eq!(transfer_error.shape_error(), None);

    let mut bad_error = transfer_error;
    bad_error.code = "bad code".into();
    assert!(bad_error.shape_error().unwrap().contains("printable ASCII"));

    let abort = Abort { transfer_id: "xfer-1".into(), reason: "operator".into() };
    assert_eq!(abort.shape_error(), None);

    let resume = Resume { transfer_id: "xfer-1".into() };
    assert_eq!(resume.shape_error(), None);

    let resume_result = ResumeResult {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        chunks_received: vec![0],
        total_chunks: 1,
        chunk_size: MIN_CHUNK_SIZE,
        file_size: 5,
        file_hash: hash_bytes(b"hello"),
    };
    assert_eq!(resume_result.shape_error(), None);

    let mut bad_resume_result = resume_result;
    bad_resume_result.chunks_received = vec![1];
    assert!(bad_resume_result.shape_error().unwrap().contains("out-of-range"));

    let duplicate_resume_result = ResumeResult {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        chunks_received: vec![0, 0],
        total_chunks: 2,
        chunk_size: MIN_CHUNK_SIZE,
        file_size: u64::from(MIN_CHUNK_SIZE) * 2,
        file_hash: hash_bytes(&vec![b'x'; MIN_CHUNK_SIZE as usize * 2]),
    };
    assert!(duplicate_resume_result.shape_error().unwrap().contains("duplicate"));

    let status = StatusResult {
        transfer_id: "xfer-1".into(),
        direction: Direction::Download,
        phase: "paused".into(),
        filename: "artifact.so".into(),
        file_size: 2048,
        chunks_done: 1,
        total_chunks: 2,
        bytes_transferred: 1024,
        elapsed_ms: 1,
        error_count: 0,
    };
    assert_eq!(status.shape_error(), None);

    let mut bad_status = status;
    bad_status.phase = "mystery".into();
    assert!(bad_status.shape_error().unwrap().contains("phase"));

    let summary = valid_summary();
    assert_eq!(summary.shape_error(), None);

    let mut bad_summary = summary.clone();
    bad_summary.chunks_done = 3;
    assert!(bad_summary.shape_error().unwrap().contains("chunks_done"));

    let list = ListResult { transfers: vec![summary.clone()] };
    assert_eq!(list.shape_error(), None);

    let oversized_list = ListResult { transfers: vec![summary; MAX_TRANSFER_SUMMARIES + 1] };
    assert!(oversized_list.shape_error().unwrap().contains("transfers"));
}

#[test]
fn transfer_config_shape_check_bounds_manager_pressure() {
    let valid = TransferConfig::new(4, DEFAULT_CHUNK_SIZE, 1024 * 1024 * 1024, 3600);
    assert_eq!(valid.shape_error(), None);

    let mut bad = valid.clone();
    bad.max_concurrent = 0;
    assert!(bad.shape_error().unwrap().contains("max_concurrent"));

    let mut bad = valid.clone();
    bad.max_concurrent = MAX_CONCURRENT_TRANSFERS + 1;
    assert!(bad.shape_error().unwrap().contains("transfer limit"));

    let mut bad = valid.clone();
    bad.chunk_size = 1;
    assert!(bad.shape_error().unwrap().contains("below minimum"));

    let mut bad = valid.clone();
    bad.max_file_size = 0;
    assert!(bad.shape_error().unwrap().contains("max_file_size"));

    let mut bad = valid.clone();
    bad.stale_timeout_secs = 0;
    assert!(bad.shape_error().unwrap().contains("stale_timeout_secs"));

    let mut bad = valid;
    bad.max_chunk_retries = 0;
    assert!(bad.shape_error().unwrap().contains("max_chunk_retries"));

    let retry_overflow = TransferConfig::new(
        1,
        MIN_CHUNK_SIZE,
        u64::from(u32::MAX) * u64::from(MIN_CHUNK_SIZE),
        3600,
    );
    assert!(retry_overflow.shape_error().unwrap().contains("overflow"));
}

#[test]
fn transfer_plan_serves_raw_chunks_and_assembler_rebuilds_12mib_artifact() {
    let size = 12 * 1024 * 1024 + 7;
    let artifact: Vec<u8> =
        (0..size).map(|i| ((i as u8).wrapping_mul(31)).wrapping_add(17)).collect();
    let plan = TransferPlan::from_bytes("artifact-xfer", &artifact, DEFAULT_CHUNK_SIZE)
        .expect("valid transfer plan");
    assert_eq!(plan.file_size, artifact.len() as u64);
    assert_eq!(
        plan.total_chunks,
        compute_chunks(artifact.len() as u64, DEFAULT_CHUNK_SIZE).unwrap()
    );

    let mut assembler = ChunkAssembler::new(plan.clone()).expect("assembler");
    let mut total_wire_bytes = 0usize;
    for chunk_index in 0..plan.total_chunks {
        let frame = plan.encode_chunk(&artifact, chunk_index).expect("encode chunk");
        let (header, _payload): (ChunkFrameHeader, &[u8]) =
            decode_binary_frame(&frame).expect("decode encoded chunk");
        assert_eq!(header.total_chunks, Some(plan.total_chunks));
        total_wire_bytes += frame.len();
        let accepted = assembler.accept_binary_frame(&frame).expect("accept chunk");
        assert_eq!(accepted.chunk_index, chunk_index);
        assert!(!accepted.duplicate);
    }

    assert!(
        total_wire_bytes < artifact.len() * 2,
        "GX frames should carry raw bytes, not a hex-doubled artifact"
    );
    assert_eq!(assembler.bytes_received(), artifact.len() as u64);
    let rebuilt = assembler.finish().expect("complete artifact");
    assert_eq!(rebuilt, artifact);
}

/// `missing_chunks` reports exactly the gaps, so a stalled puller can re-request only those
/// indices and resume rather than restart. Out-of-order + re-requested (duplicate) acceptance
/// converges to an empty gap set.
#[test]
fn missing_chunks_tracks_gaps_for_resume_without_restart() {
    let chunk_size = MIN_CHUNK_SIZE;
    let artifact = vec![0xC7u8; chunk_size as usize * 5 + 11];
    let plan = TransferPlan::from_bytes("artifact-resume", &artifact, chunk_size)
        .expect("valid transfer plan");
    let total = plan.total_chunks;
    assert!(total >= 6, "fixture spans several chunks");

    let mut assembler = ChunkAssembler::new(plan.clone()).expect("assembler");
    // A fresh assembler is missing every chunk, in order.
    assert_eq!(assembler.missing_chunks(), (0..total).collect::<Vec<_>>());

    // Accept the even chunks only (a lossy first pass).
    for chunk_index in (0..total).step_by(2) {
        let frame = plan.encode_chunk(&artifact, chunk_index).expect("encode chunk");
        assembler.accept_binary_frame(&frame).expect("accept chunk");
    }
    let gaps = assembler.missing_chunks();
    assert_eq!(gaps, (0..total).filter(|i| i % 2 == 1).collect::<Vec<_>>(), "odd chunks remain");
    assert!(!assembler.is_complete());

    // Resume: re-request exactly the gaps (re-accepting a held chunk is an idempotent no-op).
    for chunk_index in gaps {
        let frame = plan.encode_chunk(&artifact, chunk_index).expect("encode chunk");
        assembler.accept_binary_frame(&frame).expect("accept gap chunk");
    }
    assert!(assembler.missing_chunks().is_empty(), "no gaps after resume");
    assert!(assembler.is_complete());
    assert_eq!(assembler.finish().expect("complete artifact"), artifact);
}

#[test]
fn file_chunk_receiver_rebuilds_12mib_artifact_without_full_file_buffering() {
    let size = 12 * 1024 * 1024 + 7;
    let artifact: Vec<u8> =
        (0..size).map(|i| ((i as u8).wrapping_mul(19)).wrapping_add(23)).collect();
    let plan = TransferPlan::from_bytes("artifact-file-xfer", &artifact, DEFAULT_CHUNK_SIZE)
        .expect("valid transfer plan");
    let temp_path = unique_temp_path("receiver.tmp");
    let final_path = unique_temp_path("receiver.final");

    let mut receiver = FileChunkReceiver::create(plan.clone(), &temp_path).expect("file receiver");
    for chunk_index in (0..plan.total_chunks).rev() {
        let frame = plan.encode_chunk(&artifact, chunk_index).expect("encode chunk");
        let accepted = receiver.accept_binary_frame(&frame).expect("accept chunk");
        assert_eq!(accepted.chunk_index, chunk_index);
    }
    assert_eq!(receiver.bytes_received(), artifact.len() as u64);
    let persisted = receiver.persist(&final_path).expect("persist verified file");
    assert_eq!(persisted, final_path);
    assert_eq!(hash_file(&final_path).expect("hash persisted"), plan.file_hash);
    assert_eq!(fs::read(&final_path).expect("read persisted"), artifact);

    let _ = fs::remove_file(&temp_path);
    let _ = fs::remove_file(&final_path);
}

#[test]
fn file_chunk_receiver_rejects_declared_over_cap_before_creating_temp_file() {
    let temp_path = unique_temp_path("receiver-over-cap.tmp");
    let plan = TransferPlan::new(
        "huge-file-xfer",
        DEFAULT_MAX_FILE_TRANSFER_BYTES + 1,
        hash_bytes(b"declared-hash"),
        DEFAULT_CHUNK_SIZE,
    )
    .expect("valid plan metadata");

    let err = FileChunkReceiver::with_options(
        plan,
        &temp_path,
        FileChunkReceiverOptions {
            max_file_size: DEFAULT_MAX_FILE_TRANSFER_BYTES,
            ..Default::default()
        },
    )
    .expect_err("over-cap file must be rejected");

    assert!(matches!(
        err,
        TransferChunkError::FileExceedsTransferLimit {
            file_size,
            max_file_size
        } if file_size == DEFAULT_MAX_FILE_TRANSFER_BYTES + 1
            && max_file_size == DEFAULT_MAX_FILE_TRANSFER_BYTES
    ));
    assert!(!temp_path.exists(), "over-cap rejection must not create a temp file");
}

#[test]
fn file_chunk_receiver_rejects_corrupt_payloads_and_corrupt_duplicate_chunks() {
    let artifact = vec![b'x'; MIN_CHUNK_SIZE as usize + 1];
    let plan = TransferPlan::from_bytes("artifact-file-xfer", &artifact, MIN_CHUNK_SIZE)
        .expect("valid transfer plan");
    let temp_path = unique_temp_path("receiver-corrupt.tmp");

    let mut receiver = FileChunkReceiver::create(plan.clone(), &temp_path).expect("file receiver");
    let (mut header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    header.chunk_hash = hash_bytes(b"not-the-payload");
    assert!(matches!(
        receiver.accept_chunk(&header, payload),
        Err(TransferChunkError::ChunkHashMismatch { .. })
    ));

    let (header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    assert_eq!(
        receiver.accept_chunk(&header, payload).expect("accept original"),
        ChunkAccept { chunk_index: 0, duplicate: false, complete: false }
    );

    {
        let mut file =
            OpenOptions::new().write(true).open(&temp_path).expect("open temp for corruption");
        file.seek(SeekFrom::Start(0)).expect("seek temp");
        file.write_all(b"z").expect("corrupt first byte");
    }

    assert!(matches!(
        receiver.accept_chunk(&header, payload),
        Err(TransferChunkError::DuplicateChunkMismatch { chunk_index: 0 })
    ));

    let _ = fs::remove_file(&temp_path);
}

#[test]
fn chunk_assembler_rejects_declared_file_size_above_default_memory_cap_before_allocating() {
    let plan = TransferPlan::new(
        "huge-xfer",
        DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES + 1,
        hash_bytes(b"declared-hash"),
        DEFAULT_CHUNK_SIZE,
    )
    .expect("valid plan metadata");

    assert!(matches!(
        ChunkAssembler::new(plan),
        Err(TransferChunkError::FileExceedsInMemoryLimit {
            file_size,
            max_file_size
        }) if file_size == DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES + 1
            && max_file_size == DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES
    ));
}

#[test]
fn chunk_assembler_rejects_forged_plan_shape_before_allocating() {
    let bad_chunk_size = TransferPlan {
        transfer_id: "forged-xfer".into(),
        file_size: DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES,
        file_hash: hash_bytes(b"declared-hash"),
        chunk_size: 1,
        total_chunks: DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES as u32,
    };
    assert!(matches!(
        ChunkAssembler::with_max_file_size(bad_chunk_size, 0),
        Err(TransferChunkError::PlanShape(error)) if error.contains("below minimum")
    ));

    let bad_count = TransferPlan {
        transfer_id: "forged-xfer".into(),
        file_size: u64::from(MIN_CHUNK_SIZE),
        file_hash: hash_bytes(b"declared-hash"),
        chunk_size: MIN_CHUNK_SIZE,
        total_chunks: u32::MAX,
    };
    assert!(matches!(
        ChunkAssembler::with_max_file_size(bad_count, 0),
        Err(TransferChunkError::PlanShape(error)) if error.contains("total_chunks")
    ));
}

#[test]
fn transfer_plan_sender_helpers_reject_forged_plan_shape() {
    let artifact = vec![b'x'; MIN_CHUNK_SIZE as usize];
    let bad_chunk_size = TransferPlan {
        transfer_id: "forged-xfer".into(),
        file_size: artifact.len() as u64,
        file_hash: hash_bytes(&artifact),
        chunk_size: 1,
        total_chunks: artifact.len() as u32,
    };
    assert!(matches!(
        bad_chunk_size.chunk_bounds(0),
        Err(TransferChunkError::PlanShape(error)) if error.contains("below minimum")
    ));
    assert!(matches!(
        bad_chunk_size.encode_chunk(&artifact, 0),
        Err(TransferChunkError::PlanShape(error)) if error.contains("below minimum")
    ));

    let bad_count = TransferPlan {
        transfer_id: "forged-xfer".into(),
        file_size: artifact.len() as u64,
        file_hash: hash_bytes(&artifact),
        chunk_size: MIN_CHUNK_SIZE,
        total_chunks: 2,
    };
    assert!(matches!(
        bad_count.chunk_request(0),
        Err(TransferChunkError::PlanShape(error)) if error.contains("total_chunks")
    ));
}

#[test]
fn chunk_assembler_custom_memory_cap_and_zero_opt_out_are_explicit() {
    let artifact = b"chunked-artifact".to_vec();
    let plan = TransferPlan::from_bytes("artifact-xfer", &artifact, MIN_CHUNK_SIZE)
        .expect("valid transfer plan");

    assert!(matches!(
        ChunkAssembler::with_max_file_size(plan.clone(), artifact.len() as u64 - 1),
        Err(TransferChunkError::FileExceedsInMemoryLimit { .. })
    ));
    assert!(
        ChunkAssembler::with_max_file_size(plan, 0).is_ok(),
        "0 is the explicit unbounded in-memory opt-out"
    );
}

#[test]
fn chunk_assembler_rejects_wrong_transfer_and_corrupt_payloads() {
    let artifact = vec![b'x'; MIN_CHUNK_SIZE as usize + 1];
    let plan = TransferPlan::from_bytes("artifact-xfer", &artifact, MIN_CHUNK_SIZE)
        .expect("valid transfer plan");
    let (mut header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    let mut assembler = ChunkAssembler::new(plan.clone()).expect("assembler");

    header.transfer_id = "other-transfer".into();
    assert!(matches!(
        assembler.accept_chunk(&header, payload),
        Err(TransferChunkError::TransferIdMismatch { .. })
    ));

    let (mut header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    header.total_chunks = Some(plan.total_chunks + 1);
    assert!(matches!(
        assembler.accept_chunk(&header, payload),
        Err(TransferChunkError::TotalChunksMismatch { .. })
    ));

    let (mut header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    header.chunk_hash = hash_bytes(b"not-the-payload");
    assert!(matches!(
        assembler.accept_chunk(&header, payload),
        Err(TransferChunkError::ChunkHashMismatch { .. })
    ));

    let (header, payload) = plan.chunk(&artifact, 0).expect("first chunk");
    assert_eq!(
        assembler.accept_chunk(&header, payload).expect("accept original"),
        ChunkAccept { chunk_index: 0, duplicate: false, complete: false }
    );
    assert_eq!(
        assembler.accept_chunk(&header, payload).expect("accept duplicate"),
        ChunkAccept { chunk_index: 0, duplicate: true, complete: false }
    );
}

#[test]
fn transfer_plan_builds_bounded_chunk_requests() {
    let artifact = vec![b'x'; MIN_CHUNK_SIZE as usize + 1];
    let plan = TransferPlan::from_bytes("artifact-xfer", &artifact, MIN_CHUNK_SIZE)
        .expect("valid transfer plan");
    let req = plan.chunk_request(1).expect("chunk request");
    assert_eq!(req, ChunkRequest { transfer_id: "artifact-xfer".into(), chunk_index: 1 });
    assert_eq!(req.shape_error(), None);
    assert!(matches!(
        plan.chunk_request(plan.total_chunks),
        Err(TransferChunkError::ChunkOutOfRange { .. })
    ));

    let bad = ChunkRequest::new("not printable".into(), 0);
    assert!(bad.shape_error().unwrap().contains("printable ASCII"));
}

#[test]
fn registry_transfer_id_is_shape_checked_and_artifact_bound() {
    let artifact_hash = hash_bytes(b"artifact");
    let transfer_id = registry_transfer_id(&artifact_hash, DEFAULT_CHUNK_SIZE, u64::MAX, u64::MAX);

    assert!(transfer_id.len() <= MAX_TRANSFER_ID_BYTES);
    assert!(registry_transfer_id_shape_error(&transfer_id, &artifact_hash, DEFAULT_CHUNK_SIZE)
        .is_none());

    assert!(registry_transfer_id_shape_error("not printable", &artifact_hash, DEFAULT_CHUNK_SIZE,)
        .unwrap()
        .contains("printable ASCII"));
    assert!(registry_transfer_id_shape_error(
        &format!("registry.bad.{DEFAULT_CHUNK_SIZE}.0.42"),
        &artifact_hash,
        DEFAULT_CHUNK_SIZE,
    )
    .unwrap()
    .contains("artifact_hash"));
    assert!(registry_transfer_id_shape_error(
        &format!("registry.{artifact_hash}.not-decimal.0.42"),
        &artifact_hash,
        DEFAULT_CHUNK_SIZE,
    )
    .unwrap()
    .contains("decimal"));
    assert!(registry_transfer_id_shape_error(
        &format!("registry.{artifact_hash}.1024.0.42"),
        &artifact_hash,
        DEFAULT_CHUNK_SIZE,
    )
    .unwrap()
    .contains("chunk_size"));
    assert!(registry_transfer_id_shape_error(
        &format!("registry.{artifact_hash}.{DEFAULT_CHUNK_SIZE}.0.42.extra"),
        &artifact_hash,
        DEFAULT_CHUNK_SIZE,
    )
    .unwrap()
    .contains("must match"));
    assert!(registry_transfer_id_shape_error(&transfer_id, "not-a-hash", DEFAULT_CHUNK_SIZE)
        .unwrap()
        .contains("artifact_hash"));
}

#[test]
fn sha256_helpers_match_known_digest_and_stream_regions() {
    let data = b"abc123xyz";
    assert_eq!(
        hash_bytes(data),
        "604365fa1146d17e81aa41ef72ef03b07a5d3c2e44cfa6f9b817606779eccae6"
    );
    assert_eq!(hash_reader(Cursor::new(data)).unwrap(), hash_bytes(data));
    assert_eq!(hash_region(Cursor::new(data), 3, 3).unwrap(), hash_bytes(b"123"));
    let short = hash_region(Cursor::new(data), 7, 3)
        .expect_err("region hashing must not silently hash a truncated region");
    assert_eq!(short.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn upload_init_wire_keeps_existing_gx_field_names() {
    let req = InitUpload {
        path: "/tmp".into(),
        filename: "artifact.so".into(),
        file_size: 12,
        file_hash: "abc".into(),
        chunk_size: DEFAULT_CHUNK_SIZE,
        total_chunks: 1,
        mode: Some("0644".into()),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"file_size\":12"));
    assert!(json.contains("\"file_hash\":\"abc\""));
    assert!(json.contains("\"chunk_size\":262144"));
    assert!(json.contains("\"total_chunks\":1"));
}
