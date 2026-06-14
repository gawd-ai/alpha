//! GX bulk-transfer caps and message-type schema strings.
//!
//! The byte/size bounds that guard every wire shape, plus the `gx.*` and `transport.gx.chunk`
//! message-type names producers and consumers agree on. Pure data — no behaviour.

/// Default GX chunk size: 256 KiB.
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
/// Smallest accepted nonzero chunk size.
pub const MIN_CHUNK_SIZE: u32 = 1024;
/// Largest chunk size recommended for substrate-managed artifact shipping.
///
/// This keeps single chunk frames comfortably below transport frame caps while letting callers reduce
/// dispatch count for large artifacts.
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// Default file-size cap for [`ChunkAssembler`](crate::ChunkAssembler)'s in-memory receiver.
///
/// Larger transfers should use a streaming/file-backed receiver. Passing `0` to
/// [`ChunkAssembler::with_max_file_size`](crate::ChunkAssembler::with_max_file_size) is the explicit
/// unbounded opt-out for lab/demo callers that accept allocating whatever the transfer plan declares.
pub const DEFAULT_MAX_IN_MEMORY_TRANSFER_BYTES: u64 = 128 * 1024 * 1024;
/// Default file-size cap for file-backed transfer receivers.
///
/// This mirrors the existing sctl STP manager default. Callers that own tighter admission policy can
/// lower it with [`FileChunkReceiverOptions`](crate::FileChunkReceiverOptions); lab/demo callers can
/// pass `0` to opt out explicitly.
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
