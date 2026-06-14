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
mod tests {
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
        let header = ChunkFrameHeader::new("xfer-1".into(), 7, hash_bytes(b"payload"))
            .with_request_id("req-9");
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

        let ok_ack =
            ChunkAck { transfer_id: "xfer-1".into(), chunk_index: 0, ok: true, error: None };
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
        assert_eq!(
            gaps,
            (0..total).filter(|i| i % 2 == 1).collect::<Vec<_>>(),
            "odd chunks remain"
        );
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

        let mut receiver =
            FileChunkReceiver::create(plan.clone(), &temp_path).expect("file receiver");
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

        let mut receiver =
            FileChunkReceiver::create(plan.clone(), &temp_path).expect("file receiver");
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
        let transfer_id =
            registry_transfer_id(&artifact_hash, DEFAULT_CHUNK_SIZE, u64::MAX, u64::MAX);

        assert!(transfer_id.len() <= MAX_TRANSFER_ID_BYTES);
        assert!(registry_transfer_id_shape_error(&transfer_id, &artifact_hash, DEFAULT_CHUNK_SIZE)
            .is_none());

        assert!(registry_transfer_id_shape_error(
            "not printable",
            &artifact_hash,
            DEFAULT_CHUNK_SIZE,
        )
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
}
