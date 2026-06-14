//! `gawdxfer` - the GAWD bulk-transfer contract.
//!
//! This crate is the transport-neutral core of the existing GX/STP work from `sctl`: typed init,
//! chunk, ack, progress, resume, status, completion, and error messages; a binary chunk-frame codec;
//! chunk-count math; and streaming SHA-256 helpers. It intentionally knows nothing about TCP, HTTP,
//! WebSockets, axum, tokio, temp files, or UI progress channels.
//!
//! Alpha transports and control surfaces should adapt this contract instead of inventing local
//! one-off artifact transfer formats. Large artifacts do not belong in one hex-encoded JSON
//! envelope; they should move as bounded raw chunks with per-chunk integrity and whole-file
//! verification.
//!
//! Where this lives: `gawdxfer` is *shared GAWD foundation* (the `gawd_*` cross-system namespace),
//! not Alpha cosmology — it sits under `foundation/`, beside `cosmos/`, and `sctl` shares the same
//! contract. It is slated to externalize into its own crate/repo (and, eventually, a `gx` CLI).
//!
//! Map of this file (the impl is grouped by responsibility; tests live in `tests.rs`):
//! - **Caps & schema strings** — the `*_BYTES`/size bounds and the `GX_*` message-type names.
//! - **Wire messages** — the typed init / chunk / ack / progress / resume / status / list / error
//!   structs, each with a `shape_error()` pressure guard (the validation helpers sit alongside them).
//! - **Binary frame codec** — [`ChunkFrameHeader`] + [`encode_binary_frame`] / [`decode_binary_frame`].
//! - **Transfer engine** — [`TransferPlan`] (sender), [`ChunkAssembler`] / [`FileChunkReceiver`]
//!   (receivers), and chunk-count math ([`compute_chunks`]).
//! - **Hashing** — streaming SHA-256 helpers ([`hash_bytes`] / [`hash_reader`] / [`hash_file`]).
//!
//! When this crate externalizes, the sections above become real modules.

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default GX chunk size: 256 KiB.
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
/// Smallest accepted nonzero chunk size.
pub const MIN_CHUNK_SIZE: u32 = 1024;
/// Largest chunk size recommended for substrate-managed artifact shipping.
///
/// This keeps single chunk frames comfortably below transport frame caps while letting callers reduce
/// dispatch count for large artifacts.
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// Default file-size cap for [`ChunkAssembler`]'s in-memory receiver.
///
/// Larger transfers should use a streaming/file-backed receiver. Passing `0` to
/// [`ChunkAssembler::with_max_file_size`] is the explicit unbounded opt-out for lab/demo callers that
/// accept allocating whatever the transfer plan declares.
pub const DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES: u64 = 128 * 1024 * 1024;
/// Default file-size cap for file-backed transfer receivers.
///
/// This mirrors the existing sctl STP manager default. Callers that own tighter admission policy can
/// lower it with [`FileChunkReceiverOptions`]; lab/demo callers can pass `0` to opt out explicitly.
pub const DEFAULT_MAX_FILE_TRANSFER_BYTES: u64 = 1024 * 1024 * 1024;
/// Streaming hash block size: 64 KiB.
pub const HASH_BLOCK_BYTES: usize = 64 * 1024;
/// Maximum JSON header bytes in a binary GX frame.
pub const MAX_BINARY_FRAME_HEADER_BYTES: usize = 1024 * 1024;
/// Maximum bytes in a transfer id. UUIDs are 36 bytes; this leaves room for scoped ids without
/// letting a chunk header become metadata storage.
pub const MAX_TRANSFER_ID_BYTES: usize = 128;
/// Maximum bytes in an optional request id.
pub const MAX_REQUEST_ID_BYTES: usize = 256;
/// Maximum bytes in a path carried by GX control/status metadata.
pub const MAX_PATH_BYTES: usize = 4096;
/// Maximum bytes in a filename carried by GX control/status metadata.
pub const MAX_FILENAME_BYTES: usize = 255;
/// Maximum bytes in an optional POSIX-style mode string.
pub const MAX_MODE_BYTES: usize = 16;
/// Maximum bytes in an error code.
pub const MAX_ERROR_CODE_BYTES: usize = 64;
/// Maximum bytes in human-readable reason/error text.
pub const MAX_REASON_BYTES: usize = 1024;
/// Maximum transfer summaries carried in one list reply.
pub const MAX_TRANSFER_SUMMARIES: usize = 1024;
/// Maximum concurrently active transfers for shared manager configs.
pub const MAX_CONCURRENT_TRANSFERS: usize = MAX_TRANSFER_SUMMARIES;
/// Maximum chunk indexes carried in one resume reply under the default in-memory transfer cap.
pub const MAX_RESUME_CHUNKS_RECEIVED: usize =
    (DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES / MIN_CHUNK_SIZE as u64) as usize;
/// Lowercase SHA-256 hex digest length.
pub const SHA256_HEX_BYTES: usize = 64;
/// Namespace prefix for Alpha registry-issued artifact transfer ids.
pub const REGISTRY_TRANSFER_ID_NAMESPACE: &str = "registry";

pub const GX_DOWNLOAD_INIT: &str = "gx.download.init";
pub const GX_DOWNLOAD_INIT_RESULT: &str = "gx.download.init.result";
pub const GX_UPLOAD_INIT: &str = "gx.upload.init";
pub const GX_UPLOAD_INIT_RESULT: &str = "gx.upload.init.result";
pub const GX_CHUNK_REQUEST: &str = "gx.chunk.request";
pub const GX_CHUNK: &str = "gx.chunk";
pub const GX_CHUNK_ACK: &str = "gx.chunk.ack";
pub const GX_RESUME: &str = "gx.resume";
pub const GX_RESUME_RESULT: &str = "gx.resume.result";
pub const GX_ABORT: &str = "gx.abort";
pub const GX_STATUS: &str = "gx.status";
pub const GX_STATUS_RESULT: &str = "gx.status.result";
pub const GX_LIST: &str = "gx.list";
pub const GX_LIST_RESULT: &str = "gx.list.result";
/// Alpha transport schema used to carry a raw GX chunk through `transport-tcp`.
///
/// The schema belongs next to the GX chunk contract so producers do not need a sibling creature
/// dependency just to name the raw chunk lane.
pub const TRANSPORT_GX_CHUNK_SCHEMA: &str = "transport.gx.chunk";

/// Transfer direction from the receiver's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Upload,
    Download,
}

/// Transfer lifecycle phase for manager implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Init,
    Transferring,
    Paused,
    Verifying,
    Complete,
    Failed(String),
    Aborted,
}

impl Phase {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Phase::Init => "init",
            Phase::Transferring => "transferring",
            Phase::Paused => "paused",
            Phase::Verifying => "verifying",
            Phase::Complete => "complete",
            Phase::Failed(_) => "failed",
            Phase::Aborted => "aborted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitDownload {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

impl InitDownload {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) = text_field_shape_error("path", &self.path, MAX_PATH_BYTES, false) {
            return Some(error);
        }
        if let Some(chunk_size) = self.chunk_size {
            if let Some(error) = chunk_size_shape_error(chunk_size) {
                return Some(error);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitDownloadResult {
    pub transfer_id: String,
    pub file_size: u64,
    pub file_hash: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub filename: String,
}

impl InitDownloadResult {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) = transfer_plan_shape_error(
            &self.transfer_id,
            self.file_size,
            &self.file_hash,
            self.chunk_size,
            self.total_chunks,
        ) {
            return Some(error);
        }
        filename_shape_error(&self.filename)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitUpload {
    pub path: String,
    pub filename: String,
    pub file_size: u64,
    /// Whole-file SHA-256 hash. If empty, the receiver computes it after all chunks arrive.
    #[serde(default)]
    pub file_hash: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl InitUpload {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) = text_field_shape_error("path", &self.path, MAX_PATH_BYTES, false) {
            return Some(error);
        }
        if let Some(error) = filename_shape_error(&self.filename) {
            return Some(error);
        }
        if !self.file_hash.is_empty() {
            if let Some(error) = sha256_hex_shape_error("file_hash", &self.file_hash) {
                return Some(error);
            }
        }
        match compute_chunks(self.file_size, self.chunk_size) {
            Ok(expected) if expected == self.total_chunks => {}
            Ok(expected) => {
                return Some(format!(
                    "total_chunks {} does not match expected {expected}",
                    self.total_chunks
                ));
            }
            Err(error) => return Some(error.to_string()),
        }
        if let Some(mode) = &self.mode {
            if let Some(error) = mode_shape_error(mode) {
                return Some(error);
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitUploadResult {
    pub transfer_id: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
}

impl InitUploadResult {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = chunk_size_shape_error(self.chunk_size) {
            return Some(error);
        }
        if self.total_chunks == 0 {
            return Some("total_chunks must be greater than zero".to_string());
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkHeader {
    pub transfer_id: String,
    pub chunk_index: u32,
    pub chunk_hash: String,
}

impl ChunkHeader {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        sha256_hex_shape_error("chunk_hash", &self.chunk_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub transfer_id: String,
    pub chunk_index: u32,
}

impl ChunkRequest {
    #[must_use]
    pub fn new(transfer_id: String, chunk_index: u32) -> Self {
        Self { transfer_id, chunk_index }
    }

    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
    }
}

/// Build the transfer id shape Alpha registries issue for artifact pulls.
#[must_use]
pub fn registry_transfer_id(artifact_hash: &str, chunk_size: u32, seq: u64, corr: u64) -> String {
    format!("{REGISTRY_TRANSFER_ID_NAMESPACE}.{artifact_hash}.{chunk_size}.{seq}.{corr}")
}

/// Validate a registry-issued artifact transfer id before lookup or chunk routing.
#[must_use]
pub fn registry_transfer_id_shape_error(
    transfer_id: &str,
    artifact_hash: &str,
    chunk_size: u32,
) -> Option<String> {
    if let Some(error) = chunk_id_shape_error("transfer_id", transfer_id, MAX_TRANSFER_ID_BYTES) {
        return Some(error);
    }
    if let Some(error) = sha256_hex_shape_error("artifact_hash", artifact_hash) {
        return Some(error);
    }
    if let Some(error) = chunk_size_shape_error(chunk_size) {
        return Some(error);
    }

    let mut parts = transfer_id.split('.');
    let namespace = parts.next();
    let id_artifact_hash = parts.next();
    let id_chunk_size = parts.next();
    let seq = parts.next();
    let corr = parts.next();
    if parts.next().is_some() || namespace != Some(REGISTRY_TRANSFER_ID_NAMESPACE) {
        return Some(
            "GX transfer_id must match registry.{artifact_hash}.{chunk_size}.{seq}.{corr}"
                .to_string(),
        );
    }
    let (Some(id_artifact_hash), Some(id_chunk_size), Some(seq), Some(corr)) =
        (id_artifact_hash, id_chunk_size, seq, corr)
    else {
        return Some(
            "GX transfer_id must match registry.{artifact_hash}.{chunk_size}.{seq}.{corr}"
                .to_string(),
        );
    };
    if id_artifact_hash != artifact_hash {
        return Some("GX transfer_id does not belong to artifact_hash".to_string());
    }
    if seq.is_empty()
        || corr.is_empty()
        || id_chunk_size.is_empty()
        || !id_chunk_size.bytes().all(|b| b.is_ascii_digit())
        || !seq.bytes().all(|b| b.is_ascii_digit())
        || !corr.bytes().all(|b| b.is_ascii_digit())
    {
        return Some("GX transfer_id chunk_size, seq, and corr must be decimal".to_string());
    }
    if id_chunk_size != chunk_size.to_string() {
        return Some("GX transfer_id does not belong to chunk_size".to_string());
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkFrameHeader {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub transfer_id: String,
    pub chunk_index: u32,
    /// Optional transfer-level chunk count. The canonical STP chunk header does not require this,
    /// but Alpha's raw transport lane can use it to retire per-transfer routing state after the
    /// declared final chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    pub chunk_hash: String,
}

impl ChunkFrameHeader {
    #[must_use]
    pub fn new(transfer_id: String, chunk_index: u32, chunk_hash: String) -> Self {
        Self {
            message_type: GX_CHUNK.to_string(),
            request_id: None,
            transfer_id,
            chunk_index,
            total_chunks: None,
            chunk_hash,
        }
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn with_total_chunks(mut self, total_chunks: u32) -> Self {
        self.total_chunks = Some(total_chunks);
        self
    }

    /// Validate chunk-frame metadata before retaining, routing, or queueing a chunk.
    ///
    /// This is a shape/pressure guard only. It does not prove that `chunk_hash` matches the payload;
    /// receivers still verify that against the bytes they receive.
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if self.message_type != GX_CHUNK {
            return Some(format!("GX chunk frame type must be `{GX_CHUNK}`"));
        }
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(request_id) = &self.request_id {
            if let Some(error) =
                chunk_id_shape_error("request_id", request_id, MAX_REQUEST_ID_BYTES)
            {
                return Some(error);
            }
        }
        if let Some(error) = sha256_hex_shape_error("chunk_hash", &self.chunk_hash) {
            return Some(error);
        }
        if let Some(total_chunks) = self.total_chunks {
            if total_chunks == 0 {
                return Some("total_chunks must be greater than zero".to_string());
            }
            if self.chunk_index >= total_chunks {
                return Some(format!(
                    "chunk_index {} out of range for total_chunks {total_chunks}",
                    self.chunk_index
                ));
            }
        }
        None
    }
}

fn chunk_id_shape_error(field: &str, value: &str, max_bytes: usize) -> Option<String> {
    if value.is_empty() {
        return Some(format!("{field} must not be empty"));
    }
    if value.len() > max_bytes {
        return Some(format!("{field} is {} bytes, exceeds {max_bytes} byte limit", value.len()));
    }
    if value.contains('\0') {
        return Some(format!("{field} contains NUL byte"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Some(format!("{field} must be printable ASCII without whitespace"));
    }
    None
}

fn text_field_shape_error(
    field: &str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Option<String> {
    if !allow_empty && value.is_empty() {
        return Some(format!("{field} must not be empty"));
    }
    if value.len() > max_bytes {
        return Some(format!("{field} is {} bytes, exceeds {max_bytes} byte limit", value.len()));
    }
    if value.contains('\0') {
        return Some(format!("{field} contains NUL byte"));
    }
    None
}

fn filename_shape_error(filename: &str) -> Option<String> {
    if let Some(error) = text_field_shape_error("filename", filename, MAX_FILENAME_BYTES, false) {
        return Some(error);
    }
    if filename == "." || filename == ".." {
        return Some("filename must not be a relative directory marker".to_string());
    }
    if filename.contains('/') || filename.contains('\\') {
        return Some("filename must not contain path separators".to_string());
    }
    None
}

fn mode_shape_error(mode: &str) -> Option<String> {
    if let Some(error) = text_field_shape_error("mode", mode, MAX_MODE_BYTES, false) {
        return Some(error);
    }
    if !mode.bytes().all(|b| matches!(b, b'0'..=b'7')) {
        return Some("mode must be octal digits".to_string());
    }
    None
}

fn chunk_size_shape_error(chunk_size: u32) -> Option<String> {
    compute_chunks(0, chunk_size).err().map(|error| error.to_string())
}

fn sha256_hex_shape_error(field: &str, value: &str) -> Option<String> {
    if value.len() != SHA256_HEX_BYTES {
        return Some(format!("{field} must be {SHA256_HEX_BYTES} lowercase hex bytes"));
    }
    if !value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Some(format!("{field} must be lowercase hex"));
    }
    None
}

fn transfer_plan_shape_error(
    transfer_id: &str,
    file_size: u64,
    file_hash: &str,
    chunk_size: u32,
    total_chunks: u32,
) -> Option<String> {
    TransferPlan {
        transfer_id: transfer_id.to_string(),
        file_size,
        file_hash: file_hash.to_string(),
        chunk_size,
        total_chunks,
    }
    .shape_error()
}

fn phase_shape_error(phase: &str) -> Option<String> {
    if let Some(error) = text_field_shape_error("phase", phase, MAX_ERROR_CODE_BYTES, false) {
        return Some(error);
    }
    match phase {
        "init" | "transferring" | "paused" | "verifying" | "complete" | "failed" | "aborted" => {
            None
        }
        _ => Some("phase must be a known GX lifecycle phase".to_string()),
    }
}

fn progress_counts_shape_error(
    chunks_done: u32,
    total_chunks: u32,
    bytes_transferred: u64,
    file_size: u64,
) -> Option<String> {
    if total_chunks == 0 {
        return Some("total_chunks must be greater than zero".to_string());
    }
    if chunks_done > total_chunks {
        return Some(format!("chunks_done {chunks_done} exceeds total_chunks {total_chunks}"));
    }
    if bytes_transferred > file_size {
        return Some(format!(
            "bytes_transferred {bytes_transferred} exceeds file_size {file_size}"
        ));
    }
    None
}

impl From<ChunkHeader> for ChunkFrameHeader {
    fn from(header: ChunkHeader) -> Self {
        Self::new(header.transfer_id, header.chunk_index, header.chunk_hash)
    }
}

/// A transport-neutral transfer plan for a byte object.
///
/// This is the reusable core of the sctl GX manager's chunk lifecycle without sctl's HTTP, tokio,
/// temp-file, or activity-log concerns. A transport/session layer owns who asked for the transfer
/// and where replies are routed; this plan owns only byte bounds and integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    pub transfer_id: String,
    pub file_size: u64,
    pub file_hash: String,
    pub chunk_size: u32,
    pub total_chunks: u32,
}

impl TransferPlan {
    /// Build a plan for bytes whose whole-object SHA-256 is already known.
    pub fn new(
        transfer_id: impl Into<String>,
        file_size: u64,
        file_hash: impl Into<String>,
        chunk_size: u32,
    ) -> Result<Self, TransferPlanError> {
        let transfer_id = transfer_id.into();
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Err(TransferPlanError::InvalidTransferId(error));
        }
        let file_hash = file_hash.into();
        if let Some(error) = sha256_hex_shape_error("file_hash", &file_hash) {
            return Err(TransferPlanError::InvalidFileHash(error));
        }
        let total_chunks = compute_chunks(file_size, chunk_size)?;
        Ok(Self { transfer_id, file_size, file_hash, chunk_size, total_chunks })
    }

    /// Validate a transfer plan before it is used to allocate receiver state or serve chunks.
    ///
    /// The fields are public so callers can persist or serialize plans, but receiver code must not
    /// trust a hand-built instance. This check keeps chunk-size and chunk-count metadata consistent
    /// with the shared GX bounds.
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = sha256_hex_shape_error("file_hash", &self.file_hash) {
            return Some(error);
        }
        match compute_chunks(self.file_size, self.chunk_size) {
            Ok(expected) if expected == self.total_chunks => None,
            Ok(expected) => Some(format!(
                "total_chunks {} does not match expected {expected}",
                self.total_chunks
            )),
            Err(error) => Some(error.to_string()),
        }
    }

    /// Build a plan by hashing the complete byte object once.
    pub fn from_bytes(
        transfer_id: impl Into<String>,
        bytes: &[u8],
        chunk_size: u32,
    ) -> Result<Self, TransferPlanError> {
        Self::new(transfer_id, bytes.len() as u64, hash_bytes(bytes), chunk_size)
    }

    /// Return the byte range for `chunk_index` in a source object.
    pub fn chunk_bounds(&self, chunk_index: u32) -> Result<Range<usize>, TransferChunkError> {
        if let Some(error) = self.shape_error() {
            return Err(TransferChunkError::PlanShape(error));
        }
        if chunk_index >= self.total_chunks {
            return Err(TransferChunkError::ChunkOutOfRange {
                chunk_index,
                total_chunks: self.total_chunks,
            });
        }
        let start_u64 = u64::from(chunk_index) * u64::from(self.chunk_size);
        let end_u64 = (start_u64 + u64::from(self.chunk_size)).min(self.file_size).max(start_u64);
        let start = usize::try_from(start_u64)
            .map_err(|_| TransferChunkError::FileTooLarge { file_size: self.file_size })?;
        let end = usize::try_from(end_u64)
            .map_err(|_| TransferChunkError::FileTooLarge { file_size: self.file_size })?;
        Ok(start..end)
    }

    /// Build the typed request for a chunk in this plan.
    pub fn chunk_request(&self, chunk_index: u32) -> Result<ChunkRequest, TransferChunkError> {
        self.chunk_bounds(chunk_index)?;
        Ok(ChunkRequest::new(self.transfer_id.clone(), chunk_index))
    }

    /// Borrow one source chunk and build its GX chunk header.
    pub fn chunk<'a>(
        &self,
        source: &'a [u8],
        chunk_index: u32,
    ) -> Result<(ChunkFrameHeader, &'a [u8]), TransferChunkError> {
        if source.len() as u64 != self.file_size {
            return Err(TransferChunkError::SourceSizeMismatch {
                expected: self.file_size,
                actual: source.len() as u64,
            });
        }
        let range = self.chunk_bounds(chunk_index)?;
        let payload = &source[range];
        let header =
            ChunkFrameHeader::new(self.transfer_id.clone(), chunk_index, hash_bytes(payload))
                .with_total_chunks(self.total_chunks);
        Ok((header, payload))
    }

    /// Encode one source chunk as a binary GX frame.
    pub fn encode_chunk(
        &self,
        source: &[u8],
        chunk_index: u32,
    ) -> Result<Vec<u8>, TransferChunkError> {
        let (header, payload) = self.chunk(source, chunk_index)?;
        encode_binary_frame(&header, payload).map_err(TransferChunkError::Frame)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferPlanError {
    ChunkPlan(ChunkPlanError),
    InvalidTransferId(String),
    InvalidFileHash(String),
}

impl fmt::Display for TransferPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferPlanError::ChunkPlan(e) => write!(f, "{e}"),
            TransferPlanError::InvalidTransferId(e) => write!(f, "{e}"),
            TransferPlanError::InvalidFileHash(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TransferPlanError {}

impl From<ChunkPlanError> for TransferPlanError {
    fn from(error: ChunkPlanError) -> Self {
        TransferPlanError::ChunkPlan(error)
    }
}

/// In-memory GX chunk receiver for a single byte-object transfer.
///
/// Transports feed it decoded GX chunks. It bounds chunk indices and lengths from the transfer plan,
/// verifies per-chunk hashes before retaining payload bytes, and verifies the whole-object hash on
/// finish. It is intentionally not a transport queue, retry engine, or policy gate.
#[derive(Debug, Clone)]
pub struct ChunkAssembler {
    plan: TransferPlan,
    received: Vec<bool>,
    bytes_received: u64,
    buffer: Vec<u8>,
}

impl ChunkAssembler {
    pub fn new(plan: TransferPlan) -> Result<Self, TransferChunkError> {
        Self::with_max_file_size(plan, DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES)
    }

    pub fn with_max_file_size(
        plan: TransferPlan,
        max_file_size: u64,
    ) -> Result<Self, TransferChunkError> {
        if let Some(error) = plan.shape_error() {
            return Err(TransferChunkError::PlanShape(error));
        }
        if max_file_size != 0 && plan.file_size > max_file_size {
            return Err(TransferChunkError::FileExceedsInMemoryLimit {
                file_size: plan.file_size,
                max_file_size,
            });
        }
        let buffer_len = usize::try_from(plan.file_size)
            .map_err(|_| TransferChunkError::FileTooLarge { file_size: plan.file_size })?;
        Ok(Self {
            received: vec![false; plan.total_chunks as usize],
            bytes_received: 0,
            buffer: vec![0u8; buffer_len],
            plan,
        })
    }

    #[must_use]
    pub fn plan(&self) -> &TransferPlan {
        &self.plan
    }

    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    #[must_use]
    pub fn chunks_done(&self) -> u32 {
        self.received.iter().filter(|received| **received).count() as u32
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|received| *received)
    }

    pub fn accept_binary_frame(&mut self, frame: &[u8]) -> Result<ChunkAccept, TransferChunkError> {
        let (header, payload): (ChunkFrameHeader, &[u8]) =
            decode_binary_frame(frame).map_err(TransferChunkError::Frame)?;
        self.accept_chunk(&header, payload)
    }

    pub fn accept_chunk(
        &mut self,
        header: &ChunkFrameHeader,
        payload: &[u8],
    ) -> Result<ChunkAccept, TransferChunkError> {
        if let Some(error) = header.shape_error() {
            return Err(TransferChunkError::HeaderShape(error));
        }
        if let Some(total_chunks) = header.total_chunks {
            if total_chunks != self.plan.total_chunks {
                return Err(TransferChunkError::TotalChunksMismatch {
                    expected: self.plan.total_chunks,
                    actual: total_chunks,
                });
            }
        }
        if header.transfer_id != self.plan.transfer_id {
            return Err(TransferChunkError::TransferIdMismatch {
                expected: self.plan.transfer_id.clone(),
                actual: header.transfer_id.clone(),
            });
        }
        let range = self.plan.chunk_bounds(header.chunk_index)?;
        let expected_len = range.len();
        if payload.len() != expected_len {
            return Err(TransferChunkError::ChunkLengthMismatch {
                chunk_index: header.chunk_index,
                expected: expected_len,
                actual: payload.len(),
            });
        }
        let actual_hash = hash_bytes(payload);
        if actual_hash != header.chunk_hash {
            return Err(TransferChunkError::ChunkHashMismatch {
                chunk_index: header.chunk_index,
                expected: header.chunk_hash.clone(),
                actual: actual_hash,
            });
        }

        let slot = header.chunk_index as usize;
        let duplicate = self.received[slot];
        if duplicate {
            if self.buffer[range.clone()] != *payload {
                return Err(TransferChunkError::DuplicateChunkMismatch {
                    chunk_index: header.chunk_index,
                });
            }
        } else {
            self.buffer[range].copy_from_slice(payload);
            self.received[slot] = true;
            self.bytes_received += payload.len() as u64;
        }

        Ok(ChunkAccept { chunk_index: header.chunk_index, duplicate, complete: self.is_complete() })
    }

    /// The chunk indices not yet accepted, ascending. Empty once [`is_complete`](Self::is_complete)
    /// is true.
    ///
    /// This is what makes **resume without a new wire op** possible: a puller whose transfer stalled
    /// (a dropped chunk, a paused link) re-requests only these gaps via `FetchGxChunk` rather than
    /// restarting from chunk 0. The registry is content-addressed and stateless, so re-requesting a
    /// chunk is idempotent — no `Resume` handler is needed on the wire.
    #[must_use]
    pub fn missing_chunks(&self) -> Vec<u32> {
        self.received
            .iter()
            .enumerate()
            .filter_map(|(i, got)| if *got { None } else { Some(i as u32) })
            .collect()
    }

    pub fn finish(self) -> Result<Vec<u8>, TransferChunkError> {
        if !self.is_complete() {
            return Err(TransferChunkError::Incomplete {
                chunks_done: self.chunks_done(),
                total_chunks: self.plan.total_chunks,
            });
        }
        let actual = hash_bytes(&self.buffer);
        if actual != self.plan.file_hash {
            return Err(TransferChunkError::WholeHashMismatch {
                expected: self.plan.file_hash,
                actual,
            });
        }
        Ok(self.buffer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAccept {
    pub chunk_index: u32,
    pub duplicate: bool,
    pub complete: bool,
}

/// Configuration for [`FileChunkReceiver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunkReceiverOptions {
    /// Maximum declared file size. `0` is an explicit unbounded opt-out.
    pub max_file_size: u64,
    /// Pre-allocate the temp file to the plan's declared size before accepting chunks.
    pub preallocate: bool,
    /// Sync file data after every accepted new chunk.
    ///
    /// This is intentionally off by default. The original sctl STP manager synced each chunk, which
    /// is durable but can dominate transfer time for small and medium files. The shared primitive
    /// syncs once during [`FileChunkReceiver::finish`] unless this flag is enabled.
    pub sync_each_chunk: bool,
}

impl Default for FileChunkReceiverOptions {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_TRANSFER_BYTES,
            preallocate: true,
            sync_each_chunk: false,
        }
    }
}

/// File-backed GX chunk receiver for a single byte-object transfer.
///
/// This is the reusable, transport-neutral core of sctl's upload path: chunks are verified one at a
/// time, written to their declared file offset, and the complete temp file is streamed through
/// SHA-256 before it can be finalized. Unlike [`ChunkAssembler`], this does not allocate the whole
/// transfer in memory.
#[derive(Debug)]
pub struct FileChunkReceiver {
    plan: TransferPlan,
    received: Vec<bool>,
    bytes_received: u64,
    temp_path: PathBuf,
    file: File,
    sync_each_chunk: bool,
}

impl FileChunkReceiver {
    pub fn create(
        plan: TransferPlan,
        temp_path: impl Into<PathBuf>,
    ) -> Result<Self, TransferChunkError> {
        Self::with_options(plan, temp_path, FileChunkReceiverOptions::default())
    }

    pub fn with_options(
        plan: TransferPlan,
        temp_path: impl Into<PathBuf>,
        options: FileChunkReceiverOptions,
    ) -> Result<Self, TransferChunkError> {
        if let Some(error) = plan.shape_error() {
            return Err(TransferChunkError::PlanShape(error));
        }
        if options.max_file_size != 0 && plan.file_size > options.max_file_size {
            return Err(TransferChunkError::FileExceedsTransferLimit {
                file_size: plan.file_size,
                max_file_size: options.max_file_size,
            });
        }
        let temp_path = temp_path.into();
        let file =
            OpenOptions::new().create_new(true).read(true).write(true).open(&temp_path).map_err(
                |error| TransferChunkError::Io {
                    operation: "create temp file",
                    message: error.to_string(),
                },
            )?;
        if options.preallocate {
            if let Err(error) = file.set_len(plan.file_size) {
                let _ = std::fs::remove_file(&temp_path);
                return Err(TransferChunkError::Io {
                    operation: "preallocate temp file",
                    message: error.to_string(),
                });
            }
        }
        Ok(Self {
            received: vec![false; plan.total_chunks as usize],
            bytes_received: 0,
            temp_path,
            file,
            sync_each_chunk: options.sync_each_chunk,
            plan,
        })
    }

    #[must_use]
    pub fn plan(&self) -> &TransferPlan {
        &self.plan
    }

    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    #[must_use]
    pub fn chunks_done(&self) -> u32 {
        self.received.iter().filter(|received| **received).count() as u32
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|received| *received)
    }

    pub fn accept_binary_frame(&mut self, frame: &[u8]) -> Result<ChunkAccept, TransferChunkError> {
        let (header, payload): (ChunkFrameHeader, &[u8]) =
            decode_binary_frame(frame).map_err(TransferChunkError::Frame)?;
        self.accept_chunk(&header, payload)
    }

    pub fn accept_chunk(
        &mut self,
        header: &ChunkFrameHeader,
        payload: &[u8],
    ) -> Result<ChunkAccept, TransferChunkError> {
        if let Some(error) = header.shape_error() {
            return Err(TransferChunkError::HeaderShape(error));
        }
        if let Some(total_chunks) = header.total_chunks {
            if total_chunks != self.plan.total_chunks {
                return Err(TransferChunkError::TotalChunksMismatch {
                    expected: self.plan.total_chunks,
                    actual: total_chunks,
                });
            }
        }
        if header.transfer_id != self.plan.transfer_id {
            return Err(TransferChunkError::TransferIdMismatch {
                expected: self.plan.transfer_id.clone(),
                actual: header.transfer_id.clone(),
            });
        }

        let range = self.plan.chunk_bounds(header.chunk_index)?;
        let expected_len = range.len();
        if payload.len() != expected_len {
            return Err(TransferChunkError::ChunkLengthMismatch {
                chunk_index: header.chunk_index,
                expected: expected_len,
                actual: payload.len(),
            });
        }
        let actual_hash = hash_bytes(payload);
        if actual_hash != header.chunk_hash {
            return Err(TransferChunkError::ChunkHashMismatch {
                chunk_index: header.chunk_index,
                expected: header.chunk_hash.clone(),
                actual: actual_hash,
            });
        }

        let slot = header.chunk_index as usize;
        let offset = u64::try_from(range.start)
            .map_err(|_| TransferChunkError::FileTooLarge { file_size: self.plan.file_size })?;
        let duplicate = self.received[slot];
        if duplicate {
            let mut existing = vec![0u8; expected_len];
            self.file.seek(SeekFrom::Start(offset)).map_err(|error| TransferChunkError::Io {
                operation: "seek duplicate chunk",
                message: error.to_string(),
            })?;
            self.file.read_exact(&mut existing).map_err(|error| TransferChunkError::Io {
                operation: "read duplicate chunk",
                message: error.to_string(),
            })?;
            if existing != payload {
                return Err(TransferChunkError::DuplicateChunkMismatch {
                    chunk_index: header.chunk_index,
                });
            }
        } else {
            self.file.seek(SeekFrom::Start(offset)).map_err(|error| TransferChunkError::Io {
                operation: "seek chunk",
                message: error.to_string(),
            })?;
            self.file.write_all(payload).map_err(|error| TransferChunkError::Io {
                operation: "write chunk",
                message: error.to_string(),
            })?;
            if self.sync_each_chunk {
                self.file.sync_data().map_err(|error| TransferChunkError::Io {
                    operation: "sync chunk",
                    message: error.to_string(),
                })?;
            }
            self.received[slot] = true;
            self.bytes_received += payload.len() as u64;
        }

        Ok(ChunkAccept { chunk_index: header.chunk_index, duplicate, complete: self.is_complete() })
    }

    /// Verify the complete temp file and return its path.
    ///
    /// The returned file has been synced once. The caller still owns final placement and cleanup.
    pub fn finish(self) -> Result<PathBuf, TransferChunkError> {
        if !self.is_complete() {
            return Err(TransferChunkError::Incomplete {
                chunks_done: self.chunks_done(),
                total_chunks: self.plan.total_chunks,
            });
        }
        self.file.sync_data().map_err(|error| TransferChunkError::Io {
            operation: "sync completed file",
            message: error.to_string(),
        })?;
        drop(self.file);
        let actual = hash_file(&self.temp_path).map_err(|error| TransferChunkError::Io {
            operation: "hash completed file",
            message: error.to_string(),
        })?;
        if actual != self.plan.file_hash {
            return Err(TransferChunkError::WholeHashMismatch {
                expected: self.plan.file_hash,
                actual,
            });
        }
        Ok(self.temp_path)
    }

    /// Verify and atomically rename the temp file to `final_path`.
    pub fn persist(self, final_path: impl AsRef<Path>) -> Result<PathBuf, TransferChunkError> {
        let temp_path = self.finish()?;
        let final_path = final_path.as_ref();
        std::fs::rename(&temp_path, final_path).map_err(|error| TransferChunkError::Io {
            operation: "rename completed file",
            message: error.to_string(),
        })?;
        Ok(final_path.to_path_buf())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferChunkError {
    FileTooLarge { file_size: u64 },
    FileExceedsInMemoryLimit { file_size: u64, max_file_size: u64 },
    FileExceedsTransferLimit { file_size: u64, max_file_size: u64 },
    SourceSizeMismatch { expected: u64, actual: u64 },
    ChunkOutOfRange { chunk_index: u32, total_chunks: u32 },
    TransferIdMismatch { expected: String, actual: String },
    TotalChunksMismatch { expected: u32, actual: u32 },
    PlanShape(String),
    HeaderShape(String),
    ChunkLengthMismatch { chunk_index: u32, expected: usize, actual: usize },
    ChunkHashMismatch { chunk_index: u32, expected: String, actual: String },
    DuplicateChunkMismatch { chunk_index: u32 },
    Incomplete { chunks_done: u32, total_chunks: u32 },
    WholeHashMismatch { expected: String, actual: String },
    Io { operation: &'static str, message: String },
    Frame(FrameError),
}

impl fmt::Display for TransferChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferChunkError::FileTooLarge { file_size } => {
                write!(f, "file size {file_size} does not fit this platform")
            }
            TransferChunkError::FileExceedsInMemoryLimit { file_size, max_file_size } => {
                write!(f, "file size {file_size} exceeds in-memory transfer limit {max_file_size}")
            }
            TransferChunkError::FileExceedsTransferLimit { file_size, max_file_size } => {
                write!(f, "file size {file_size} exceeds transfer limit {max_file_size}")
            }
            TransferChunkError::SourceSizeMismatch { expected, actual } => {
                write!(f, "source is {actual} bytes, expected {expected}")
            }
            TransferChunkError::ChunkOutOfRange { chunk_index, total_chunks } => {
                write!(f, "chunk index {chunk_index} out of range for {total_chunks} chunks")
            }
            TransferChunkError::TransferIdMismatch { expected, actual } => {
                write!(f, "chunk transfer_id `{actual}` does not match expected `{expected}`")
            }
            TransferChunkError::TotalChunksMismatch { expected, actual } => {
                write!(f, "chunk total_chunks {actual} does not match expected {expected}")
            }
            TransferChunkError::PlanShape(error) => write!(f, "{error}"),
            TransferChunkError::HeaderShape(error) => write!(f, "{error}"),
            TransferChunkError::ChunkLengthMismatch { chunk_index, expected, actual } => {
                write!(f, "chunk {chunk_index} is {actual} bytes, expected {expected}")
            }
            TransferChunkError::ChunkHashMismatch { chunk_index, expected, actual } => {
                write!(f, "chunk {chunk_index} hash mismatch: expected {expected}, got {actual}")
            }
            TransferChunkError::DuplicateChunkMismatch { chunk_index } => {
                write!(f, "duplicate chunk {chunk_index} does not match retained bytes")
            }
            TransferChunkError::Incomplete { chunks_done, total_chunks } => {
                write!(f, "transfer incomplete: {chunks_done}/{total_chunks} chunks received")
            }
            TransferChunkError::WholeHashMismatch { expected, actual } => {
                write!(f, "whole-file hash mismatch: expected {expected}, got {actual}")
            }
            TransferChunkError::Io { operation, message } => {
                write!(f, "{operation} failed: {message}")
            }
            TransferChunkError::Frame(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TransferChunkError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkAck {
    pub transfer_id: String,
    pub chunk_index: u32,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ChunkAck {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        match (&self.ok, &self.error) {
            (true, Some(error)) => text_field_shape_error("error", error, MAX_REASON_BYTES, true),
            (false, Some(error)) => text_field_shape_error("error", error, MAX_REASON_BYTES, false),
            (false, None) => Some("failed chunk ack must carry an error".to_string()),
            (true, None) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub transfer_id: String,
    pub direction: Direction,
    pub path: String,
    pub filename: String,
    pub chunks_done: u32,
    pub total_chunks: u32,
    pub bytes_transferred: u64,
    pub file_size: u64,
    pub elapsed_ms: u64,
    pub rate_bps: u64,
}

impl Progress {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = text_field_shape_error("path", &self.path, MAX_PATH_BYTES, false) {
            return Some(error);
        }
        if let Some(error) = filename_shape_error(&self.filename) {
            return Some(error);
        }
        progress_counts_shape_error(
            self.chunks_done,
            self.total_chunks,
            self.bytes_transferred,
            self.file_size,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Complete {
    pub transfer_id: String,
    pub direction: Direction,
    pub path: String,
    pub filename: String,
    pub file_size: u64,
    pub file_hash: String,
    pub elapsed_ms: u64,
}

impl Complete {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = text_field_shape_error("path", &self.path, MAX_PATH_BYTES, false) {
            return Some(error);
        }
        if let Some(error) = filename_shape_error(&self.filename) {
            return Some(error);
        }
        sha256_hex_shape_error("file_hash", &self.file_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferError {
    pub transfer_id: String,
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl TransferError {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if !self.transfer_id.is_empty() {
            if let Some(error) =
                chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
            {
                return Some(error);
            }
        }
        if let Some(error) = chunk_id_shape_error("code", &self.code, MAX_ERROR_CODE_BYTES) {
            return Some(error);
        }
        text_field_shape_error("message", &self.message, MAX_REASON_BYTES, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abort {
    pub transfer_id: String,
    pub reason: String,
}

impl Abort {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        text_field_shape_error("reason", &self.reason, MAX_REASON_BYTES, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    pub transfer_id: String,
}

impl Resume {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeResult {
    pub transfer_id: String,
    pub direction: Direction,
    pub chunks_received: Vec<u32>,
    pub total_chunks: u32,
    pub chunk_size: u32,
    pub file_size: u64,
    pub file_hash: String,
}

impl ResumeResult {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) = transfer_plan_shape_error(
            &self.transfer_id,
            self.file_size,
            &self.file_hash,
            self.chunk_size,
            self.total_chunks,
        ) {
            return Some(error);
        }
        if self.chunks_received.len() > MAX_RESUME_CHUNKS_RECEIVED {
            return Some(format!(
                "chunks_received has {} entries, exceeds {MAX_RESUME_CHUNKS_RECEIVED} entry limit",
                self.chunks_received.len()
            ));
        }
        if self.chunks_received.len() > self.total_chunks as usize {
            return Some(format!(
                "chunks_received has {} entries, exceeds total_chunks {}",
                self.chunks_received.len(),
                self.total_chunks
            ));
        }
        if let Some(chunk_index) = self
            .chunks_received
            .iter()
            .copied()
            .find(|chunk_index| *chunk_index >= self.total_chunks)
        {
            return Some(format!(
                "chunks_received contains out-of-range chunk_index {chunk_index}"
            ));
        }
        let mut seen = HashSet::with_capacity(self.chunks_received.len());
        if let Some(chunk_index) =
            self.chunks_received.iter().copied().find(|chunk_index| !seen.insert(*chunk_index))
        {
            return Some(format!("chunks_received contains duplicate chunk_index {chunk_index}"));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub transfer_id: String,
    pub direction: Direction,
    pub phase: String,
    pub filename: String,
    pub file_size: u64,
    pub chunks_done: u32,
    pub total_chunks: u32,
    pub bytes_transferred: u64,
    pub elapsed_ms: u64,
    pub error_count: u32,
}

impl StatusResult {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = phase_shape_error(&self.phase) {
            return Some(error);
        }
        if let Some(error) = filename_shape_error(&self.filename) {
            return Some(error);
        }
        progress_counts_shape_error(
            self.chunks_done,
            self.total_chunks,
            self.bytes_transferred,
            self.file_size,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSummary {
    pub transfer_id: String,
    pub direction: Direction,
    pub filename: String,
    pub file_size: u64,
    pub phase: String,
    pub chunks_done: u32,
    pub total_chunks: u32,
    pub bytes_transferred: u64,
}

impl TransferSummary {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if let Some(error) =
            chunk_id_shape_error("transfer_id", &self.transfer_id, MAX_TRANSFER_ID_BYTES)
        {
            return Some(error);
        }
        if let Some(error) = filename_shape_error(&self.filename) {
            return Some(error);
        }
        if let Some(error) = phase_shape_error(&self.phase) {
            return Some(error);
        }
        progress_counts_shape_error(
            self.chunks_done,
            self.total_chunks,
            self.bytes_transferred,
            self.file_size,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListResult {
    pub transfers: Vec<TransferSummary>,
}

impl ListResult {
    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if self.transfers.len() > MAX_TRANSFER_SUMMARIES {
            return Some(format!(
                "transfers has {} entries, exceeds {MAX_TRANSFER_SUMMARIES} entry limit",
                self.transfers.len()
            ));
        }
        self.transfers.iter().find_map(TransferSummary::shape_error)
    }
}

/// Configuration shared by transfer manager implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferConfig {
    pub max_concurrent: usize,
    pub chunk_size: u32,
    pub max_file_size: u64,
    pub stale_timeout_secs: u64,
    pub max_chunk_retries: u32,
}

impl TransferConfig {
    #[must_use]
    pub fn new(
        max_concurrent: usize,
        chunk_size: u32,
        max_file_size: u64,
        stale_timeout_secs: u64,
    ) -> Self {
        Self { max_concurrent, chunk_size, max_file_size, stale_timeout_secs, max_chunk_retries: 3 }
    }

    #[must_use]
    pub fn shape_error(&self) -> Option<String> {
        if self.max_concurrent == 0 {
            return Some("max_concurrent must be greater than zero".to_string());
        }
        if self.max_concurrent > MAX_CONCURRENT_TRANSFERS {
            return Some(format!(
                "max_concurrent {} exceeds {MAX_CONCURRENT_TRANSFERS} transfer limit",
                self.max_concurrent
            ));
        }
        if let Some(error) = chunk_size_shape_error(self.chunk_size) {
            return Some(error);
        }
        if self.max_file_size == 0 {
            return Some("max_file_size must be greater than zero".to_string());
        }
        let max_chunks = match compute_chunks(self.max_file_size, self.chunk_size) {
            Ok(max_chunks) => max_chunks,
            Err(error) => return Some(error.to_string()),
        };
        if self.stale_timeout_secs == 0 {
            return Some("stale_timeout_secs must be greater than zero".to_string());
        }
        if self.max_chunk_retries == 0 {
            return Some("max_chunk_retries must be greater than zero".to_string());
        }
        if self.max_chunk_retries > u32::MAX / max_chunks {
            return Some(format!(
                "max_chunk_retries {} can overflow retry accounting for {max_chunks} chunks",
                self.max_chunk_retries
            ));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkPlanError {
    ZeroChunkSize,
    ChunkSizeTooSmall { chunk_size: u32, min: u32 },
    ChunkSizeTooLarge { chunk_size: u32, max: u32 },
    TooManyChunks { chunks: u64, max: u32 },
}

impl fmt::Display for ChunkPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChunkPlanError::ZeroChunkSize => write!(f, "chunk size must be nonzero"),
            ChunkPlanError::ChunkSizeTooSmall { chunk_size, min } => {
                write!(f, "chunk size {chunk_size} is below minimum {min}")
            }
            ChunkPlanError::ChunkSizeTooLarge { chunk_size, max } => {
                write!(f, "chunk size {chunk_size} exceeds maximum {max}")
            }
            ChunkPlanError::TooManyChunks { chunks, max } => {
                write!(f, "{chunks} chunks exceeds u32 chunk-count limit {max}")
            }
        }
    }
}

impl std::error::Error for ChunkPlanError {}

/// Compute the number of chunks needed for `file_size` and `chunk_size`.
///
/// Empty files still use one empty chunk so the transfer lifecycle has a chunk to ack.
pub fn compute_chunks(file_size: u64, chunk_size: u32) -> Result<u32, ChunkPlanError> {
    if chunk_size == 0 {
        return Err(ChunkPlanError::ZeroChunkSize);
    }
    if chunk_size < MIN_CHUNK_SIZE {
        return Err(ChunkPlanError::ChunkSizeTooSmall { chunk_size, min: MIN_CHUNK_SIZE });
    }
    if chunk_size > MAX_CHUNK_SIZE {
        return Err(ChunkPlanError::ChunkSizeTooLarge { chunk_size, max: MAX_CHUNK_SIZE });
    }
    let chunks = if file_size == 0 { 1 } else { file_size.div_ceil(u64::from(chunk_size)) };
    u32::try_from(chunks).map_err(|_| ChunkPlanError::TooManyChunks { chunks, max: u32::MAX })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    HeaderTooLarge { len: usize, max: usize },
    Truncated { needed: usize, actual: usize },
    FrameTooLarge,
    HeaderEncode(String),
    HeaderDecode(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooShort => write!(f, "binary frame is shorter than its length prefix"),
            FrameError::HeaderTooLarge { len, max } => {
                write!(f, "binary frame header is {len} bytes, exceeds {max} byte limit")
            }
            FrameError::Truncated { needed, actual } => {
                write!(f, "binary frame is truncated: needs {needed} bytes, got {actual}")
            }
            FrameError::FrameTooLarge => write!(f, "binary frame length overflow"),
            FrameError::HeaderEncode(e) => write!(f, "binary frame header encode failed: {e}"),
            FrameError::HeaderDecode(e) => write!(f, "binary frame header decode failed: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode a binary GX frame: `[header_len: u32 BE][JSON header][raw payload]`.
///
/// The payload is copied as raw bytes, never JSON-encoded.
pub fn encode_binary_frame<H: Serialize>(
    header: &H,
    payload: &[u8],
) -> Result<Vec<u8>, FrameError> {
    let header_bytes =
        serde_json::to_vec(header).map_err(|e| FrameError::HeaderEncode(e.to_string()))?;
    if header_bytes.len() > MAX_BINARY_FRAME_HEADER_BYTES {
        return Err(FrameError::HeaderTooLarge {
            len: header_bytes.len(),
            max: MAX_BINARY_FRAME_HEADER_BYTES,
        });
    }
    let header_len: u32 = header_bytes.len().try_into().map_err(|_| FrameError::FrameTooLarge)?;
    let capacity = 4usize
        .checked_add(header_bytes.len())
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(FrameError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&header_len.to_be_bytes());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode a binary GX frame encoded by [`encode_binary_frame`].
pub fn decode_binary_frame<H: DeserializeOwned>(data: &[u8]) -> Result<(H, &[u8]), FrameError> {
    if data.len() < 4 {
        return Err(FrameError::TooShort);
    }
    let header_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if header_len > MAX_BINARY_FRAME_HEADER_BYTES {
        return Err(FrameError::HeaderTooLarge {
            len: header_len,
            max: MAX_BINARY_FRAME_HEADER_BYTES,
        });
    }
    let payload_offset = 4usize.checked_add(header_len).ok_or(FrameError::FrameTooLarge)?;
    if data.len() < payload_offset {
        return Err(FrameError::Truncated { needed: payload_offset, actual: data.len() });
    }
    let header = serde_json::from_slice(&data[4..payload_offset])
        .map_err(|e| FrameError::HeaderDecode(e.to_string()))?;
    Ok((header, &data[payload_offset..]))
}

/// Compute SHA-256 of a byte slice. Returns lowercase hex.
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    sha256_hex(hasher)
}

/// Compute SHA-256 of a reader by streaming in [`HASH_BLOCK_BYTES`] blocks.
pub fn hash_reader(mut reader: impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BLOCK_BYTES];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(sha256_hex(hasher))
}

/// Compute SHA-256 of a file by streaming. The file is not buffered fully in memory.
pub fn hash_file(path: impl AsRef<Path>) -> io::Result<String> {
    hash_reader(std::fs::File::open(path)?)
}

/// Compute SHA-256 of an exact reader region by seeking to `offset` and reading `len` bytes.
pub fn hash_region(mut reader: impl Read + Seek, offset: u64, len: usize) -> io::Result<String> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = [0u8; HASH_BLOCK_BYTES];
    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("region ended {remaining} bytes before requested length"),
            ));
        }
        hasher.update(&buf[..n]);
        remaining -= n;
    }
    Ok(sha256_hex(hasher))
}

/// Compute SHA-256 of an exact file region by streaming only that region.
pub fn hash_file_region(path: impl AsRef<Path>, offset: u64, len: usize) -> io::Result<String> {
    hash_region(std::fs::File::open(path)?, offset, len)
}

fn sha256_hex(hasher: Sha256) -> String {
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests;
