//! GX transfer engine — the sender plan and the receivers.
//!
//! [`TransferPlan`] is the sender (chunk bounds, headers, encoded frames); [`ChunkAssembler`] is the
//! in-memory receiver and [`FileChunkReceiver`] the file-backed one; [`compute_chunks`] is the
//! chunk-count math. Transport/session concerns (who asked, where replies route) stay out of here.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::consts::*;
use crate::frame::{decode_binary_frame, encode_binary_frame, ChunkFrameHeader, FrameError};
use crate::hash::{hash_bytes, hash_file};
use crate::wire::{chunk_id_shape_error, sha256_hex_shape_error, ChunkRequest};

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
