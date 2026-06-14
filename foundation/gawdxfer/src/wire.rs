//! GX wire messages — the typed init / chunk / ack / progress / resume / status / list / error
//! structs, each carrying a `shape_error()` pressure guard.
//!
//! The shared field-shape validation helpers live here too (at the end of the module): they guard
//! these wire types and are also reused by the [`frame`](crate::frame) and
//! [`engine`](crate::engine) modules, so the two cross-module helpers are `pub(crate)`.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::consts::*;
use crate::engine::{compute_chunks, TransferPlan};

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

// ---- shared field-shape validation helpers ----
//
// Kept alongside the wire messages they guard. `chunk_id_shape_error` and `sha256_hex_shape_error`
// are `pub(crate)` because the frame and engine modules reuse them; the rest are wire-internal.

pub(crate) fn chunk_id_shape_error(field: &str, value: &str, max_bytes: usize) -> Option<String> {
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

pub(crate) fn sha256_hex_shape_error(field: &str, value: &str) -> Option<String> {
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
