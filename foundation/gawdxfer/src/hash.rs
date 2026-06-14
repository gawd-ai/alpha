//! Streaming SHA-256 helpers shared by the GX plan and receivers.
//!
//! [`hash_bytes`] for a slice; [`hash_reader`] / [`hash_file`] stream in
//! [`HASH_BLOCK_BYTES`](crate::HASH_BLOCK_BYTES) blocks; the `*_region` variants hash an exact span.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::consts::HASH_BLOCK_BYTES;

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
