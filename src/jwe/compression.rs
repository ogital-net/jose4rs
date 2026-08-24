//! DEFLATE compression for the JWE `zip` header parameter (RFC 7516
//! Section 4.1.3), matching jose4j's `DeflateRFC1951CompressionAlgorithm`.
//!
//! The wire format is **raw DEFLATE** (RFC 1951) -- no zlib or gzip wrapper --
//! which is what jose4j produces with `new Deflater(level, /* nowrap= */ true)`
//! and what the JWE `DEF` identifier implies.
//!
//! Compression is applied to the plaintext *before* content encryption and
//! removed *after* decryption, keyed off the `zip` protected header. Only the
//! registered `DEF` identifier is supported.
//!
//! ## Zip-bomb protection
//!
//! Decompression of attacker-controlled input can expand enormously, so
//! [`decompress`] enforces a caller-supplied cap on the decompressed size. The
//! default (mirroring jose4j's `org.jose4j.zip.decompress-max-bytes`) is
//! [`DEFAULT_MAX_DECOMPRESSED_SIZE`].

use std::io::Read as _;

use crate::error::JoseError;

/// The `zip` header value for DEFLATE compression (RFC 7516 Section 4.1.3).
pub(crate) const DEFLATE_ID: &str = "DEF";

/// Default upper bound on decompressed size, in bytes (200 KiB). Matches
/// jose4j's default `org.jose4j.zip.decompress-max-bytes` value.
pub(crate) const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 204_800;

/// Returns `true` if `zip_value` names the supported compression algorithm
/// (`DEF`).
pub(crate) fn is_deflate(zip_value: &str) -> bool {
    zip_value.eq_ignore_ascii_case(DEFLATE_ID)
}

/// Compresses `data` with raw DEFLATE (RFC 1951), default compression level.
pub(crate) fn compress(data: &[u8]) -> Result<Vec<u8>, JoseError> {
    let mut encoder = flate2::read::DeflateEncoder::new(data, flate2::Compression::default());
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    encoder
        .read_to_end(&mut out)
        .map_err(|e| JoseError::new(format!("DEFLATE compression failed: {e}")))?;
    Ok(out)
}

/// Decompresses raw DEFLATE (RFC 1951) `data`, rejecting output that would
/// exceed `max_size` bytes.
///
/// The cap is enforced by reading at most `max_size + 1` bytes: if the decoder
/// produces more than `max_size` bytes the input is treated as a zip bomb and
/// rejected, regardless of whether the stream is otherwise well-formed.
pub(crate) fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, JoseError> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    // Read one byte past the cap so an oversized stream is detectable.
    let mut out = Vec::with_capacity(data.len().min(max_size));
    let mut limited = decoder.by_ref().take((max_size as u64) + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| JoseError::new(format!("DEFLATE decompression failed: {e}")))?;
    if out.len() > max_size {
        return Err(JoseError::new(format!(
            "decompressed data exceeds the {max_size} byte limit"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        // Highly compressible input exercises the encoder meaningfully.
        let data = b"Hello world! Hello world! Hello world! Hello world!";
        let compressed = compress(data).unwrap();
        assert!(compressed.len() < data.len());
        let back = decompress(&compressed, DEFAULT_MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn round_trip_incompressible() {
        let data: Vec<u8> = (0u8..=255).collect();
        let compressed = compress(&data).unwrap();
        let back = decompress(&compressed, DEFAULT_MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn raw_deflate_interop_vector() {
        // Produced by jose4j / java.util.zip with nowrap=true (raw RFC 1951),
        // compressing "Hello world!". Verified against flate2 raw DEFLATE.
        let raw: &[u8] = &[
            0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00,
        ];
        let back = decompress(raw, DEFAULT_MAX_DECOMPRESSED_SIZE).unwrap();
        assert_eq!(back, b"Hello world!");
        // Our own compressor must decode to the same bytes.
        let ours = compress(b"Hello world!").unwrap();
        assert_eq!(
            decompress(&ours, DEFAULT_MAX_DECOMPRESSED_SIZE).unwrap(),
            b"Hello world!"
        );
    }

    #[test]
    fn enforces_decompression_cap() {
        // 1 MiB of zeros compresses to ~1 KiB; decompressing with a small cap
        // must be rejected (zip-bomb guard).
        let data = vec![0u8; 1 << 20];
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < 4096);
        let err = decompress(&compressed, 1024).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
        // At or above the real size it succeeds.
        let back = decompress(&compressed, 1 << 20).unwrap();
        assert_eq!(back.len(), 1 << 20);
    }

    #[test]
    fn rejects_malformed_stream() {
        assert!(decompress(b"not a deflate stream", 1024).is_err());
    }

    #[test]
    fn deflate_id_case_insensitive() {
        assert!(is_deflate("DEF"));
        assert!(is_deflate("def"));
        assert!(!is_deflate("GZIP"));
    }
}
