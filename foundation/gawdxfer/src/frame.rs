//! Binary GX frame codec — `[header_len: u32 BE][JSON header][raw payload]`.
//!
//! [`ChunkFrameHeader`] is the per-chunk frame header; [`encode_binary_frame`] /
//! [`decode_binary_frame`] move a chunk as bounded raw bytes (the payload is never JSON-encoded).

use std::fmt;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::consts::*;
use crate::wire::{chunk_id_shape_error, sha256_hex_shape_error, ChunkHeader};

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

impl From<ChunkHeader> for ChunkFrameHeader {
    fn from(header: ChunkHeader) -> Self {
        Self::new(header.transfer_id, header.chunk_index, header.chunk_hash)
    }
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
