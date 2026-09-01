mod aes_hmac;
#[cfg(feature = "zip")]
mod compression;
mod content_enc_alg;
mod kdf;
mod key_mgmt_alg;

use std::sync::LazyLock;

pub use content_enc_alg::ContentEncryptionAlgorithm;
pub use key_mgmt_alg::KeyManagementAlgorithm;
use simd_json::{
    ValueBuilder,
    derived::{MutableObject, TypedObjectValue as _, ValueObjectAccessAsScalar as _},
    prelude::Writable as _,
};

use crate::{
    BufferRef, base64,
    crypto::mem::Zeroizing,
    error::JoseError,
    jwa::{AlgorithmConstraints, ConstraintType},
    jwk::JsonWebKey,
    jwx::{HeaderParameter, JsonWebStructure},
};

static DEFAULT_BLOCK: LazyLock<AlgorithmConstraints<KeyManagementAlgorithm>> =
    LazyLock::new(|| {
        AlgorithmConstraints::new(
            ConstraintType::Block,
            [
                KeyManagementAlgorithm::Rsa15,
                KeyManagementAlgorithm::Pbes2Hs256A128Kw,
                KeyManagementAlgorithm::Pbes2Hs384A192Kw,
                KeyManagementAlgorithm::Pbes2Hs512A256Kw,
            ],
        )
    });

pub(super) const MAX_TAG_LEN: usize = 32;
pub(super) const MAX_CEK_LEN: usize = 64;
pub(super) const MAX_IV_LEN: usize = 24;

pub(super) struct ContentEncryptionParts {
    ciphertext: Vec<u8>,
    tag: [u8; MAX_TAG_LEN],
    tag_len: usize,
}

/// A parsed or in-progress JWE. After parsing with
/// [`JsonWebStructure::set_compact_serialization`], decrypt by calling
/// [`JsonWebEncryption::payload`].
pub struct JsonWebEncryption<'a> {
    buffer: Vec<u8>,
    header: Option<simd_json::owned::Value>,
    encoded_header: Option<BufferRef>,
    encrypted_key: Option<BufferRef>,
    iv: Option<BufferRef>,
    ciphertext: Option<BufferRef>,
    auth_tag: Option<BufferRef>,
    plaintext: Option<BufferRef>,
    algorithm_constraints: &'a AlgorithmConstraints<KeyManagementAlgorithm>,
    /// Maximum decompressed size accepted when the `zip` header requests
    /// DEFLATE decompression. Only used with the `zip` feature; without it the
    /// field is absent and any `zip` header is rejected at decrypt time.
    #[cfg(feature = "zip")]
    max_decompressed_size: usize,
}

// Redacted Debug: shows the header algorithms and which parts are populated,
// never the plaintext/ciphertext or key material.
impl std::fmt::Debug for JsonWebEncryption<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonWebEncryption")
            .field("alg", &self.algorithm())
            .field("enc", &self.encryption_method())
            .field("has_header", &self.header.is_some())
            .field("has_encrypted_key", &self.encrypted_key.is_some())
            .field("has_ciphertext", &self.ciphertext.is_some())
            .field("has_plaintext", &self.plaintext.is_some())
            .finish()
    }
}

impl<'a> JsonWebEncryption<'a> {
    /// Creates a new, empty JWE. Set the `alg` and `enc` headers, a payload,
    /// and a key, then call [`JsonWebEncryption::encrypt`]; or parse an
    /// existing token with
    /// [`JsonWebStructure::set_compact_serialization`] and decrypt it.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            header: None,
            encoded_header: None,
            encrypted_key: None,
            iv: None,
            ciphertext: None,
            auth_tag: None,
            plaintext: None,
            algorithm_constraints: &DEFAULT_BLOCK,
            #[cfg(feature = "zip")]
            max_decompressed_size: compression::DEFAULT_MAX_DECOMPRESSED_SIZE,
        }
    }

    /// Enables DEFLATE compression of the plaintext before encryption by
    /// setting the `zip` protected header to `DEF` (RFC 7516 Section 4.1.3),
    /// matching jose4j's `enableDefaultCompression`.
    ///
    /// Only available with the `zip` feature. The payload is compressed when
    /// [`JsonWebEncryption::encrypt`] runs; decryption transparently
    /// decompresses when the `zip` header is present.
    #[cfg(feature = "zip")]
    pub fn enable_default_compression(&mut self) {
        self.set_header(HeaderParameter::Zip, compression::DEFLATE_ID);
    }

    /// Sets the maximum decompressed size (in bytes) accepted when the `zip`
    /// header requests DEFLATE decompression. Guards against zip bombs in
    /// attacker-controlled tokens. Defaults to 200 KiB (204800 bytes), matching
    /// jose4j's `org.jose4j.zip.decompress-max-bytes` default.
    ///
    /// Only available with the `zip` feature.
    #[cfg(feature = "zip")]
    pub fn set_max_decompressed_size(&mut self, max: usize) {
        self.max_decompressed_size = max;
    }

    /// Compresses `plaintext` if the `zip` protected header requests DEFLATE.
    /// Returns the bytes to encrypt: the compressed payload, or the original
    /// slice when no `zip` header is present.
    #[cfg(feature = "zip")]
    fn maybe_compress<'b>(
        &self,
        plaintext: &'b [u8],
    ) -> Result<std::borrow::Cow<'b, [u8]>, JoseError> {
        match self.header(HeaderParameter::Zip) {
            Some(zip) if compression::is_deflate(zip) => {
                compression::compress(plaintext).map(std::borrow::Cow::Owned)
            }
            Some(zip) => Err(JoseError::InvalidAlgorithm(format!(
                "unsupported zip header value: {zip}"
            ))),
            None => Ok(std::borrow::Cow::Borrowed(plaintext)),
        }
    }

    /// Decompresses `plaintext` (the freshly decrypted payload) if the `zip`
    /// protected header requests DEFLATE, enforcing the decompressed-size cap.
    #[cfg(feature = "zip")]
    fn maybe_decompress<'b>(
        &self,
        plaintext: &'b [u8],
    ) -> Result<std::borrow::Cow<'b, [u8]>, JoseError> {
        match self.header(HeaderParameter::Zip) {
            Some(zip) if compression::is_deflate(zip) => {
                compression::decompress(plaintext, self.max_decompressed_size)
                    .map(std::borrow::Cow::Owned)
            }
            Some(zip) => Err(JoseError::InvalidAlgorithm(format!(
                "unsupported zip header value: {zip}"
            ))),
            None => Ok(std::borrow::Cow::Borrowed(plaintext)),
        }
    }

    fn decrypt(&mut self, management_key: &JsonWebKey) -> Result<&[u8], JoseError> {
        let key_mgmt_alg = self.get_key_mgmt_alg(true)?;
        let content_enc_alg = self.get_content_enc_alg()?;

        let ciphertext_ref = self
            .ciphertext
            .ok_or(JoseError::new("missing ciphertext"))?;
        let encrypted_key_ref = self
            .encrypted_key
            .ok_or(JoseError::new("missing encrypted key"))?;
        let headers = self
            .header
            .as_ref()
            .ok_or(JoseError::new("missing header"))?;

        let cek = key_mgmt_alg.manage_decrypt(
            management_key,
            encrypted_key_ref.get(&self.buffer),
            headers,
        )?;
        // The unwrapped/agreed CEK must match the content-encryption algorithm's
        // key size. A wrong-length CEK would otherwise reach the AEAD/CBC init
        // asserts and panic; reject it here instead (defense against malformed
        // RSA/KW outputs and mismatched alg/enc pairs).
        if cek.len() != content_enc_alg.key_len() {
            return Err(JoseError::InvalidKey(format!(
                "content encryption key length ({}) does not match enc algorithm ({})",
                cek.len(),
                content_enc_alg.key_len()
            )));
        }
        let iv_ref = self.iv.ok_or(JoseError::new("missing IV"))?;
        let auth_tag_ref = self
            .auth_tag
            .ok_or(JoseError::new("missing authentication tag"))?;
        let aad_ref = self
            .encoded_header
            .ok_or(JoseError::new("missing encoded header"))?;

        // Decrypt the ciphertext in place within `self.buffer`, avoiding the two
        // extra copies the old path made (a mutable `Box` of the ciphertext and a
        // final `extend_from_slice` of the plaintext). The plaintext overwrites
        // the ciphertext region and we point a `BufferRef` at it.
        //
        // The iv, auth_tag, and aad (encoded header) occupy disjoint regions of
        // `self.buffer` from the ciphertext. The borrow checker can't prove that
        // on its own, so we carve the buffer into disjoint sub-slices with
        // `split_at_mut`, which yields a mutable ciphertext slice alongside
        // immutable views of the rest -- fully zero-copy.
        let buf = self.buffer.as_mut_slice();
        let (aad_r, iv_r, ct_r, tag_r) = (aad_ref, iv_ref, ciphertext_ref, auth_tag_ref);

        // Split at the ciphertext boundaries so the ciphertext is uniquely
        // mutable; everything before and after stays immutable.
        let (before_ct, ct_and_after) = buf.split_at_mut(ct_r.start_idx);
        let (ct, after_ct) = ct_and_after.split_at_mut(ct_r.len());

        let aad = aad_r.get(before_ct);
        let iv = iv_r.get(before_ct);
        // auth_tag lies after the ciphertext in the buffer layout.
        let auth_tag = &after_ct[tag_r.start_idx - ct_r.end_idx..tag_r.end_idx - ct_r.end_idx];

        let plaintext_len = content_enc_alg.decrypt(iv, ct, auth_tag, aad, &cek)?.len();

        let plaintext = BufferRef::new(ct_r.start_idx, ct_r.start_idx + plaintext_len);

        // If the `zip` header requests DEFLATE, decompress the freshly
        // decrypted payload. Without the `zip` feature any `zip` header is
        // rejected (we cannot honor it). Decompression allocates a new buffer,
        // so the result is appended to `self.buffer` and the ref repointed.
        #[cfg(feature = "zip")]
        let plaintext = {
            let decrypted = plaintext.get(&self.buffer);
            match self.maybe_decompress(decrypted)? {
                std::borrow::Cow::Borrowed(_) => plaintext,
                std::borrow::Cow::Owned(decompressed) => {
                    let start = self.buffer.len();
                    self.buffer.extend_from_slice(&decompressed);
                    BufferRef::new(start, self.buffer.len())
                }
            }
        };
        #[cfg(not(feature = "zip"))]
        {
            if self.header(HeaderParameter::Zip).is_some() {
                return Err(JoseError::InvalidAlgorithm(
                    "zip header present but jose4rs was built without the `zip` feature".into(),
                ));
            }
        }

        self.plaintext = Some(plaintext);

        Ok(plaintext.get(&self.buffer))
    }

    /// Encrypts the payload set by [`JsonWebStructure::set_payload`] using
    /// `management_key` and the key management and content encryption
    /// algorithms named by the `alg` and `enc` headers. After encryption,
    /// the compact serialization can be produced.
    ///
    /// # Errors
    ///
    /// Returns an error if the `alg`/`enc` headers are missing or unsupported,
    /// if no plaintext payload has been set, or if key management or content
    /// encryption fails.
    pub fn encrypt(&mut self, management_key: &JsonWebKey) -> Result<(), JoseError> {
        let key_mgmt_alg = self.get_key_mgmt_alg(true)?;
        let content_enc_alg = self.get_content_enc_alg()?;

        let plaintext_ref = self
            .plaintext
            .ok_or(JoseError::new("missing plaintext payload"))?;

        // If the `zip` header requests DEFLATE, compress the payload first and
        // repoint `plaintext` at the compressed bytes (appended to the buffer).
        // Without the `zip` feature any `zip` header is rejected here rather
        // than silently producing a token the recipient reads as uncompressed.
        #[cfg(feature = "zip")]
        let plaintext_ref = {
            let raw = plaintext_ref.get(&self.buffer);
            match self.maybe_compress(raw)? {
                std::borrow::Cow::Borrowed(_) => plaintext_ref,
                std::borrow::Cow::Owned(compressed) => {
                    let start = self.buffer.len();
                    self.buffer.extend_from_slice(&compressed);
                    let r = BufferRef::new(start, self.buffer.len());
                    self.plaintext = Some(r);
                    r
                }
            }
        };
        #[cfg(not(feature = "zip"))]
        {
            if self.header(HeaderParameter::Zip).is_some() {
                return Err(JoseError::InvalidAlgorithm(
                    "zip header present but jose4rs was built without the `zip` feature".into(),
                ));
            }
        }

        // Single CSPRNG call for both the random CEK and content IV.
        let cek_len = content_enc_alg.key_len();
        let iv_len = content_enc_alg.iv_len();
        let mut rand_buf = Zeroizing::new([0u8; MAX_CEK_LEN + MAX_IV_LEN]);
        crate::crypto::rand::rand_bytes_buf(&mut rand_buf[..cek_len + iv_len]);

        // Key management: wrap the random CEK. This may also set header
        // parameters (epk, iv, tag, p2s, p2c). ECDH-ES/dir derive their
        // own CEK and ignore the random bytes.
        let mut headers = self.header.take().ok_or(JoseError::new("missing header"))?;
        let keys = key_mgmt_alg.manage_encrypt(
            management_key,
            &content_enc_alg,
            &rand_buf[..cek_len],
            &mut headers,
        )?;

        // Serialize header JSON and base64url-encode directly into the buffer.
        let header_json = headers.encode();
        self.header = Some(headers);
        let iv = &rand_buf[cek_len..cek_len + iv_len];

        // For AEAD algorithms (GCM, ChaCha20) the ciphertext is the same
        // length as the plaintext, so we can encrypt directly in the buffer
        // and avoid all intermediate allocations.
        if let Some(aead_alg) = content_enc_alg.aead_algorithm() {
            let pt_len = plaintext_ref.len();

            // Write all parts into the buffer in final layout order.
            let encoded_header_ref =
                base64::url_encode_append(header_json.as_bytes(), &mut self.buffer);
            self.encoded_header = Some(encoded_header_ref);

            if let Some(ek) = &keys.encrypted_key {
                let start = self.buffer.len();
                self.buffer.extend_from_slice(ek);
                self.encrypted_key = Some(BufferRef::new(start, self.buffer.len()));
            }

            let iv_start = self.buffer.len();
            self.buffer.extend_from_slice(iv);
            self.iv = Some(BufferRef::new(iv_start, self.buffer.len()));

            // Copy plaintext to the end of the buffer for in-place encryption.
            let ct_start = self.buffer.len();
            self.buffer
                .extend_from_within(plaintext_ref.start_idx..plaintext_ref.end_idx);
            self.ciphertext = Some(BufferRef::new(ct_start, ct_start + pt_len));

            // split_at_mut gives us &[u8] AAD (encoded header) and &mut [u8]
            // ciphertext from disjoint regions of the same buffer.
            let (before_ct, ct_region) = self.buffer.split_at_mut(ct_start);
            let aad = encoded_header_ref.get(before_ct);
            let ct = &mut ct_region[..pt_len];

            let ctx =
                crate::crypto::aead::EvpAeadCtx::init(aead_alg, keys.content_encryption_key());
            let mut tag = [0u8; MAX_TAG_LEN];
            let tag_len = aead_alg.max_tag_len();
            ctx.encrypt(iv, aad, ct, &mut tag[..tag_len])?;

            let tag_start = self.buffer.len();
            self.buffer.extend_from_slice(&tag[..tag_len]);
            self.auth_tag = Some(BufferRef::new(tag_start, self.buffer.len()));
        } else {
            // CBC-HMAC: ciphertext has padding, use the existing allocating path.
            let plaintext = plaintext_ref.get(&self.buffer);
            let encoded_header = base64::url_encode(header_json.as_bytes());

            let parts = content_enc_alg.encrypt(
                plaintext,
                &encoded_header,
                keys.content_encryption_key(),
                iv,
            )?;

            let start = self.buffer.len();
            self.buffer.extend_from_slice(&encoded_header);
            self.encoded_header = Some(BufferRef::new(start, self.buffer.len()));

            if let Some(ek) = &keys.encrypted_key {
                let start = self.buffer.len();
                self.buffer.extend_from_slice(ek);
                self.encrypted_key = Some(BufferRef::new(start, self.buffer.len()));
            }

            let start = self.buffer.len();
            self.buffer.extend_from_slice(iv);
            self.iv = Some(BufferRef::new(start, self.buffer.len()));

            let start = self.buffer.len();
            self.buffer.extend_from_slice(&parts.ciphertext);
            self.ciphertext = Some(BufferRef::new(start, self.buffer.len()));

            let start = self.buffer.len();
            self.buffer.extend_from_slice(&parts.tag[..parts.tag_len]);
            self.auth_tag = Some(BufferRef::new(start, self.buffer.len()));
        }

        Ok(())
    }

    /// Parses a JWE compact serialization, readying it for decryption.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a well-formed five-part JWE
    /// compact serialization.
    pub fn from_compact_serialization(
        compact_serialization: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<Self, JoseError> {
        let mut jwe = Self::new();
        jwe.set_compact_serialization(compact_serialization)?;
        Ok(jwe)
    }

    /// Sets the `alg` (key management) header to a typed algorithm.
    pub fn set_algorithm(&mut self, alg: KeyManagementAlgorithm) {
        self.set_header(HeaderParameter::Algorithm, alg.name());
    }

    /// Sets the `enc` (content encryption) header to a typed algorithm.
    pub fn set_encryption_method(&mut self, enc: ContentEncryptionAlgorithm) {
        self.set_header(HeaderParameter::EncryptionMethod, enc.name());
    }

    /// Returns the key management algorithm header value, if set.
    pub fn algorithm(&self) -> Option<&str> {
        self.header(HeaderParameter::Algorithm)
    }

    /// Returns the content encryption (`enc`) header value, if set.
    pub fn encryption_method(&self) -> Option<&str> {
        self.header(HeaderParameter::EncryptionMethod)
    }

    #[inline]
    fn set_parts(
        &mut self,
        encoded_header: &[u8],
        encoded_encrypted_key: &[u8],
        encoded_iv: &[u8],
        encoded_ciphertext: &[u8],
        encoded_auth_tag: &[u8],
    ) -> Result<(), JoseError> {
        let mut need = 0usize;
        // 2 copies of the encoded header are needed since simd json de-escapes in place
        need += encoded_header.len();
        for part in [
            encoded_header,
            encoded_encrypted_key,
            encoded_iv,
            encoded_auth_tag,
        ] {
            need += base64::url_decode_size(part.len());
        }
        need += base64::url_decode_size(encoded_ciphertext.len()) * 2;

        self.buffer.reserve_exact(need);

        let start_idx = self.buffer.len();
        self.buffer.extend_from_slice(encoded_header);
        let encoded_header_ref = BufferRef::new(start_idx, self.buffer.len());

        let encrypted_key = base64::url_decode_append(encoded_encrypted_key, &mut self.buffer)?;
        let iv = base64::url_decode_append(encoded_iv, &mut self.buffer)?;
        let ciphertext = base64::url_decode_append(encoded_ciphertext, &mut self.buffer)?;
        let auth_tag = base64::url_decode_append(encoded_auth_tag, &mut self.buffer)?;

        let json_buf = base64::url_decode_append(encoded_header, &mut self.buffer)?;
        let header = simd_json::to_owned_value(json_buf.get_mut(&mut self.buffer))
            .map_err(JoseError::json)?;
        // The decoded header JSON was only needed to build the owned `Value`;
        // it is the last thing appended, so truncate it away to avoid retaining
        // dead bytes for the struct's lifetime. All other parts sit at lower
        // offsets and are unaffected by truncating the tail.
        self.buffer.truncate(json_buf.start_idx);
        // A JWE protected header must be a JSON object; rejecting anything else
        // here keeps `set_header_name` (which inserts into the map) infallible.
        if !header.is_object() {
            return Err(JoseError::InvalidHeader(
                "JWE protected header is not a JSON object".into(),
            ));
        }

        // RFC 7516 Section 4.1.11: reject unsupported critical extensions. This
        // implementation supports no JWE critical extensions, so any `crit`
        // name is rejected.
        crate::jwx::check_crit(&header, &[])?;

        self.header = Some(header);
        self.encoded_header = Some(encoded_header_ref);
        self.encrypted_key = Some(encrypted_key);
        self.iv = Some(iv);
        self.ciphertext = Some(ciphertext);
        self.auth_tag = Some(auth_tag);

        Ok(())
    }

    fn get_key_mgmt_alg(
        &self,
        check_constraints: bool,
    ) -> Result<KeyManagementAlgorithm, JoseError> {
        let alg = self
            .header(HeaderParameter::Algorithm)
            .ok_or(JoseError::InvalidAlgorithm(
                "encryption key management algorithm header not set".into(),
            ))?;
        let alg = KeyManagementAlgorithm::try_from(alg)?;
        if check_constraints {
            self.algorithm_constraints.check_constraint(alg)?;
        }
        Ok(alg)
    }

    fn get_content_enc_alg(&self) -> Result<ContentEncryptionAlgorithm, JoseError> {
        let alg =
            self.header(HeaderParameter::EncryptionMethod)
                .ok_or(JoseError::InvalidAlgorithm(
                    "content encryption header not set".into(),
                ))?;
        ContentEncryptionAlgorithm::try_from(alg)
    }
}

impl<'a> JsonWebStructure<'a, KeyManagementAlgorithm> for JsonWebEncryption<'a> {
    fn set_compact_serialization(
        &mut self,
        compact_serialization: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError> {
        let compact_serialization = compact_serialization.as_ref();

        let delimeter_indexes = {
            let mut iter = memchr::memchr_iter(b'.', compact_serialization);

            let mut indexes = [0usize; 4];
            for idx in &mut indexes {
                match iter.next() {
                    Some(i) => *idx = i,
                    None => return Err(JoseError::MalformedToken("not enough parts".into())),
                }
            }
            if iter.next().is_some() {
                return Err(JoseError::MalformedToken("too many parts".into()));
            }
            indexes
        };
        let (encoded_header, encoded_encrypted_key, encoded_iv, encoded_ciphertext, encoded_auth_tag) =
            // SAFETY: these indexes are checked above
            unsafe {
                (compact_serialization.get_unchecked(..delimeter_indexes[0]),
                compact_serialization.get_unchecked((delimeter_indexes[0] + 1)..delimeter_indexes[1]),
                compact_serialization.get_unchecked((delimeter_indexes[1] + 1)..delimeter_indexes[2]),
                compact_serialization.get_unchecked((delimeter_indexes[2] + 1)..delimeter_indexes[3]),
                compact_serialization.get_unchecked((delimeter_indexes[3] + 1)..))
            };

        self.set_parts(
            encoded_header,
            encoded_encrypted_key,
            encoded_iv,
            encoded_ciphertext,
            encoded_auth_tag,
        )
    }

    fn set_payload(&mut self, payload: impl AsRef<[u8]>) {
        let start = self.buffer.len();
        self.buffer.extend_from_slice(payload.as_ref());
        self.plaintext = Some(BufferRef::new(start, self.buffer.len()));
    }

    fn set_header_value(&mut self, name: impl Into<String>, value: simd_json::owned::Value) {
        if let Some(ref mut header) = self.header {
            header.insert(name.into(), value).unwrap();
        } else {
            let mut header = simd_json::owned::Value::object();
            header.insert(name.into(), value).unwrap();
            self.header = Some(header);
        }
    }

    fn header_name(&self, name: impl AsRef<str>) -> Option<&str> {
        match self.header {
            Some(ref header) => header.get_str(name.as_ref()),
            None => None,
        }
    }

    fn set_algorithm_constraints(
        &mut self,
        algorithm_constraints: &'a AlgorithmConstraints<KeyManagementAlgorithm>,
    ) {
        self.algorithm_constraints = algorithm_constraints;
    }
}

impl<'a> JsonWebEncryption<'a> {
    /// Returns the plaintext, decrypting the JWE if necessary.
    ///
    /// If the JWE was just encrypted by this instance (no incoming compact
    /// serialization), the stored plaintext is returned directly. Otherwise
    /// the JWE is decrypted using `management_key` and the result is cached
    /// on the instance for subsequent calls.
    ///
    /// This mirrors jose4j's `JsonWebEncryption.getPayload()` /
    /// `getPlaintextBytes()`.
    ///
    /// # Errors
    ///
    /// Returns an error if no plaintext is available and either decryption
    /// fails, key management fails, or content encryption fails.
    pub fn payload(&mut self, management_key: &JsonWebKey) -> Result<&[u8], JoseError> {
        if let Some(plain) = self.plaintext {
            return Ok(plain.get(&self.buffer));
        }
        self.decrypt(management_key)
    }

    /// Produces the JWE compact serialization from the parsed/encrypted state.
    /// Does not require a key -- encryption produces all required parts;
    /// the caller may invoke this on a parsed token to re-serialize it.
    ///
    /// # Errors
    ///
    /// Returns an error if any required part (encoded header, IV, ciphertext,
    /// auth tag) is missing.
    pub fn compact_serialization(&self) -> Result<String, JoseError> {
        let encoded_header = self
            .encoded_header
            .as_ref()
            .ok_or(JoseError::new("missing encoded header"))?
            .get(&self.buffer);
        let encrypted_key = self
            .encrypted_key
            .as_ref()
            .map_or(&[][..], |r| r.get(&self.buffer));
        let iv = self
            .iv
            .as_ref()
            .ok_or(JoseError::new("missing IV"))?
            .get(&self.buffer);
        let ciphertext = self
            .ciphertext
            .as_ref()
            .ok_or(JoseError::new("missing ciphertext"))?
            .get(&self.buffer);
        let auth_tag = self
            .auth_tag
            .as_ref()
            .ok_or(JoseError::new("missing authentication tag"))?
            .get(&self.buffer);

        let mut out = Vec::with_capacity(
            encoded_header.len()
                + base64::url_encode_size(encrypted_key.len())
                + base64::url_encode_size(iv.len())
                + base64::url_encode_size(ciphertext.len())
                + base64::url_encode_size(auth_tag.len())
                + 4,
        );

        out.extend_from_slice(encoded_header);
        out.push(b'.');
        base64::url_encode_append(encrypted_key, &mut out);
        out.push(b'.');
        base64::url_encode_append(iv, &mut out);
        out.push(b'.');
        base64::url_encode_append(ciphertext, &mut out);
        out.push(b'.');
        base64::url_encode_append(auth_tag, &mut out);

        // SAFETY: base64url + encoded header are pure ASCII, always valid UTF-8.
        unsafe { Ok(String::from_utf8_unchecked(out)) }
    }
}

pub(super) struct ContentEncryptionKeys {
    cek: Zeroizing<[u8; MAX_CEK_LEN]>,
    cek_len: usize,
    encrypted_key: Option<Box<[u8]>>,
}

impl ContentEncryptionKeys {
    pub(super) fn new(cek: &[u8], encrypted_key: impl Into<Box<[u8]>>) -> Self {
        let mut buf = [0u8; MAX_CEK_LEN];
        buf[..cek.len()].copy_from_slice(cek);
        Self {
            cek: Zeroizing::new(buf),
            cek_len: cek.len(),
            encrypted_key: Some(encrypted_key.into()),
        }
    }

    pub(super) fn direct(cek: &[u8]) -> Self {
        let mut buf = [0u8; MAX_CEK_LEN];
        buf[..cek.len()].copy_from_slice(cek);
        Self {
            cek: Zeroizing::new(buf),
            cek_len: cek.len(),
            encrypted_key: None,
        }
    }

    pub(super) fn content_encryption_key(&self) -> &[u8] {
        &self.cek[..self.cek_len]
    }
}

impl Default for JsonWebEncryption<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_payload_test() {
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
    }

    #[test]
    fn decrypt_direct_aes128gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"IJRDL_AZnmxvH-peVRKlqQ"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0..BSnJ5pKU_3r48H7j.AlyooSZG5J9ptIB0.5iOBvkIeRM1Eolu7IuCl-A";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn non_object_protected_header_rejected() {
        // A JWE protected header that decodes to valid JSON but is not an object
        // must be rejected at parse time (so set_header_name can never panic).
        // BASE64URL(`[1,2,3]`) below is a JSON array, not an object.
        let enc = |b: &[u8]| String::from_utf8(base64::url_encode(b).into_vec()).unwrap();
        let compact = format!(
            "{}.{}.{}.{}.{}",
            enc(b"[1,2,3]"),
            enc(b""),
            enc(b"iv"),
            enc(b"ct"),
            enc(b"tag")
        );
        let mut jwe = JsonWebEncryption::new();
        assert!(jwe.set_compact_serialization(&compact).is_err());
    }

    #[test]
    fn decrypt_direct_xc20p_test() {
        let jwk_json = r#"{"kty":"oct","k":"Sr1D4Rnf31x2SYXdy8AtLDBAgx-cLJaXtAmGS-OVIg4"}"#;
        let compact_serialization = "eyJlbmMiOiJYQzIwUCIsImFsZyI6ImRpciJ9..nTYOzMHBUV3ZFTU3HouBBUUHOZqTQZQt.30val_-t-HDPAORH.-PXYFmoBz38m1FvhWDU7wQ";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a128kw_aes128gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"FIGC8LqlqWb54bYvJ5SmQQ"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.7resHW5tgwGvw55a2Oip5eh2N2aIY8LD.WZ_NOTsConezmjhY.APwSSzZtm9UFHJ2w.mU7HqwUp60rrGKUAQYk3KQ";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a192kw_aes192gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"8w8grvvZwVE7F-6yDkjVM6o0TAlUHPL9"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiQTE5MktXIn0.AACsXBLF0VNOTwUSn46f9g8HF4GikY8RCOvo5cmncoM.bgEIHamtLkVRFtA7.M4tmWLdpCrGi9xsS.IVe0J3ygjik9sNHeEcmynQ";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a256kw_aes256gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"CS_tmvFw4q5Cq0pgyEL_qWKuSRpQhORz9isr1JOznlA"}"#;
        let compact_serialization = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.F2pPFvjOkbcy-8b82GW6-k-pRf_Xt4E86rrnfT3mu5l6L_UFgVT_zg.MkdVsy1RfnBcAa09.VXpyRJgjsidpHjOZ.jG-LtZ66DjsR4xjl-omB9g";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a128gcmkw_aes128gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"igcAcnmqrH1AKzS-eRU_tg"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwidGFnIjoiLXVFSWRvUGlMRWd3S1BWc3U4aDVxZyIsImFsZyI6IkExMjhHQ01LVyIsIml2IjoiMGk5M1JPNnpwMEoyQUNOQSJ9.SnwjKiCl2nh9Rq-DPRnT4w.3XBcHerOuADcD2z1.gLSiXSsHFy2I26u8.uHm1o-m2npb1PaKvRAVlrA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a192gcmkw_aes192gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"py4_mB3pwNvaBP_AeRXK3EbHZLfR885h"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTkyR0NNIiwidGFnIjoiYnd1blBaTS1fR0htSnBjdkFGU2JhZyIsImFsZyI6IkExOTJHQ01LVyIsIml2IjoidDRHeGpHazlGRnhTTHFPbSJ9.X2TluvzdJzwo_qAr8wQVlHTcZE0jzqkD.pOB0FT5S1y79vH7k.W9VWEPrvkLrn6KXO.44D01A72-6F1OooRf6o6_g";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_a256gcmkw_aes256gcm_test() {
        let jwk_json = r#"{"kty":"oct","k":"gQ14yfhrE4QMuhONasBWxA1rKYZc64gE1IMZE0noF8g"}"#;
        let compact_serialization = "eyJlbmMiOiJBMjU2R0NNIiwidGFnIjoiVlBZY2Nja0JuNTRwOWZud2lxaF9UZyIsImFsZyI6IkEyNTZHQ01LVyIsIml2IjoicVRqUDZkaG1LVUhMSzVBbiJ9.TS-9CZ05cjAGUG7KVleHk-tavMZmzPk6nmq35VjuW3c.9yXc5U_nNUDk_f0x.U9EmScMPibMcZ0l0.DaZQesDpYazEH8JEfN-SSQ";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_rsa1_5_aes128gcm_test() {
        let jwk_json = r#"{"kty":"RSA","d":"T6hCveYlQX57XLdG9OJPqMlnDVd2z0PpeN2uy8VZmcnXYJPWbro9sUeiqn3fXbJSRjdX1cbZ-gvB7lTleNhu2chBtLz_EMFeI0CHRdvrUJowiTPo5s1geY6J1rUPnptH7310_UmZO9oRKGXcYuQmllPbyaHQmGJsvyx3s1vyMDm_oE9ZqM63lmnoot4M3a6uZBCK2tEgZY1hjgPG-FuYIld-Cig2WY5CbBfGbid_syywIMJnT9MCDZwKNtBtGu5gndJokGe1V5xE0mTP0HTk1ZsKJSc8CbUgvBHka-JxzK60Lzbci45irDA_sG_BMqrb6p9H_WEJzGCXCK8xjD6GAQ","e":"AQAB","n":"u9d-ES2R1Gjn7sfhwGq-0AmUCD1ZOiqsZ9Jh8qBmRi9R5GVQpApuWMWsdG-Cr4u3a4dsvYTvWrEdRjdNgFliLQQ7g5lPkJWUv-COuSOtSZf1tvCxGkqkPuwiiQ3DwVD44KhZjxfviyhazyJiPG5T9L93gKQg9bYP7ovtba9JXDrCTZqg2jY9DjMplyYuSdbi-8ZNS5QkIZjyAn79ff2qmpZjUgL4lgWE4rGuDa_pFDfGGOc_d9B0KYEY6QfwUO4luVHZD5OWVGdFLrVF4XeHIDnSHA59aURmFussAW1RQXCZvycJqCNVvXQNqZaBS3_t9yVyBPnBjZvgFuMHSQjb7w"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBMV81In0.ALTnHZYE2Ya3W0kKayAw0FRwWPnRUqVIeh5NSID8_UCWULr6hu61VQ_RDIjAf4lAFEgd3zervScgM-Um_DYDFJKyDA47yS4fJbBPTj7dhK-m0KtLtlQOIq3zYRm42k5k2JzrdE5C5eYWD0llb_8tSVI7LbCakTeFpzql2ZoJ1Wydq-o4VQFWJb6YRaCOoFPKu_QagSexhnec-YpedKbgh0e8i7YUC_jkPQTB1v5JoLN7GVuPLOEWP_qQttm9afLmXXYpy819GBhFNs50ojA_52SbJ6H8Nab30QPJVrdelhc3ntXtb0wL5aQm7gdmfhhQdxl5CGMcEUFHAtjsc-OiWA.ziTkm7itkyEuZFKv.wSheMbIxBbGEIbIm.UkXoYxVPxgMPn7L_LUHrmw";

        let constraints =
            AlgorithmConstraints::new(ConstraintType::Permit, [KeyManagementAlgorithm::Rsa15]);
        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_rsa_oaep_aes128gcm_test() {
        let jwk_json = r#"{"kty":"RSA","d":"dLyPkVwoIwvouaow09eGL9LxrO9jPXhHl04VR3C4kRXJ_toWcdkDW55VC71sOUzdkgkUyTeYdxmBcdRGiB1m2QrpAU9TqYxjExbEU-B6ksFQOIDfsxw9o89uwZu32WOUxbpIDlGPMox9YzQZWT-mrWUaAf2xDVhr5O7vD1D6hotthaz7ImKzNuU5LxCi8613eErwYtEWSCfmS7YsHpRftXLw6_mlbKAGurn6P7xG7JwHVVQo1bfXmBG__cTy7f2WQSfJ0_tpsI9JGk1ynTe_lGrVy4JDcY6lmvgoZoGXWI37zQ-z7H2w9NEkY6bzBx0goeTIunNSdej4C7Yy1K-PoQ","e":"AQAB","n":"kdYNxU2ZDLAf4hwy0cx6YopmyjCG04gslLBw2bZVO0XqMx9Q2ZosBRVWlGZ6V8P9uvjUnntVUF84LJxaoa5JJulFBcKJlCJ-hhHgjBiqThj16s6Yx7SAcH8z1Ge8BL2Q0pK83_nl0x9yITrLu6Wpq3WaVlp4BYMAl5pwdq33zKjSO_RP7ceAOw5yqTa2ki-qtvJk13u9KhESM-6lOJ9CbuyIR5VotBTESclL8D1jp3tj6lU7el51HENgCNdkcVuR7I5Az3QEpPJEFuKBHk1qcCbI9Iym7nIEhZcUkGU0nuqFmvnoxhwj1E2hLfMpywOX2HBbDxbUPBI8FE6EWqILXw"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.jan1qM0bNrNSaJdmWAB1U_5_7MHPszqRv49FxGmZPOIjdXM_WFSAXFY_4rwbYPcsNrT2RI8ApzAT6wupTnFEee-b96QcGHMbYAKEx6UUzc8x62jSUH8yL1_UVsWtmumLB7tl3ClTYgNCqq_V5LoDqJk8TlbhXgW4XtO2csja7RxA_yuicfJX6XsfXNr5-HI-bzl1tPfqlEzvq_17xrWbr87YiV3IiRVMOufEqIKRHuOnoFY2y1hb4oUvLcMQOAX45cxdPk6RRo5TciuWw-YRnqtbBhKqX3oWRkUdiTjcCDKG7HusxMYWhabLuUV-mGb30-ZilHBWOV8GyTryAanykA.42_c-llv-yqWkyZu._3f3BeFlDT-pfsL3.5IE1HPsku4FxBEBXaAUkMg";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_rsa_oaep256_aes128gcm_test() {
        let jwk_json = r#"{"kty":"RSA","d":"Tc1vgT4DEw9GbkhqjFL1NRzyZKHFzxu2jMLjRXfqDSSGn2hp6WQ9e0u18wZLdubnrSY_T4K3b2tXmZUwkAQm3xkgJRybe6fvWoUzBqNFEgmhyfuhaa6OiALTBiuWvcBbycFoTRT0fzXLUZISBNkzz1cNOo5r9qwTgVBBZVUfyru-3zfv4FaPYjB4sLXsv2wtQkk3QZ3IJJq0jb3r9KGu2cJJtcpq-g2qBG0ZFBTwFrGypzVId95uLXi26Cwz5FUxbifZdaZ1x53sKReTcCB8QwmdNTb5Kb3542jPDynB-91tKfl2wxHIeb0YXr9Ln8YG0ARWYNe_2AtlEqKcJElC8Q","e":"AQAB","n":"94ujBOpnRLVfpLYpLApCkT129ZZKIkWFKebLrk98a9xaOrMiZjzilrJWiRzwerj3bNJxd9wX_Q08iaqrIQslmVdpcgcEWmv3LnbVqrhVksNfRXFQhwWLs8GY9MW44GVV21OE_WfYrbpIhjG1XdMd6NG_pBNFPV80JFZvk7SZNyi9BgJIWNnS8mbCcVW1M3JBDSPPh4qKKrBWTbBGsNgZJKRR8VXiV5IfBT1coYnJN-AWGghW7ERzKzGIym1o0Ini8qs2fQCuNL4uZyTusXMc49jPnwMwEv8dTIxTElk4SOYyeMwUnvJgew-7s6X2Km3cuzNrtxEWaBL2goM6cgRkhw"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.uTSiOLgsyLhB0YTuemCUSsToPHXcJdJdMM10DMYhpbqMuVKV-0o88xpfxqYpcS2U8S5EtTtisnqpzFBUNva_8vX7bxDG4152q9hwsdeHMx_xTTj6Z2DfgKLfB5bcJ03mnTOxymAN_q2dNCd7Os-DDO11XigsDJY2iR9h3a-1SEAXioZtsJLt8AMYj5Wze5DgjNVkRT6xB8I0po5vDt2DMMYI5gpfZmJ_WHll2iQEADPfD3gIZ2hfvHJXJi7K4IW2SxWauxIY2gjaC18ZjQ1BN8vdE4mVNzwlwmBB8Lk_FCP1FSuNuJqXzLAXcx0LLAZxCQZspT80YGvArkC6waYgOQ.ZCAJ3gbYHCFFTE7t.wyi63SIX4UGUPX8L.w3BHtV_O4CeE47H-c_ftSw";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_rsa_oaep384_aes128gcm_test() {
        let jwk_json = r#"{"kty":"RSA","d":"a9vFqvpJ1icq6ZC1o27foGByQIPrK59zfRn-YJm2TnFAME532n0L4wEXbG94KiIBP-G2IasKPBR3OnVgdSdSLRUhlGdXP0J4VKZg3fq_okwo8YDDSL9qt38ov7IyTCAC--EE5EBmcif6Zvzy98kTbeA5lE8JAhChWzZFfBjuJCOgly0c0IBHa0KAI9fXS4JHlejILuGZNYbIFMTLam8J6sP55NZ-6ZyABdR0amfcNi-7gK1vJr_v6AHtpihfxFVi75wTedE29REFdpGmN_YtEY7g88-qDmELQ6jEETkkgmNckAhI9x145r0WnWyRnEjlMY0_pjGz9EKNi_c7XLqt4Q","e":"AQAB","n":"gYooyl4mlYdhPyT25jy9YPF83uORlMkprlIFmrQuk67Z6cZ3KniBQe2VZmE6Lkk9ON-jigHusaqYOKf3MSoujy2YFVwLI-NJaCSUyz-Hb6Ks24cY2ks6iyMEiTCv8Cw1H_Ux1B0GNGLXRhrrRHnNval89mUYqcLXG-vi9kWhe5qcVXq8PE06-xvotYDJSQR-__ypnl8uD14cYSbH-_a1hS63qigyCzAEJM-mPJp9M3Ob9R0b06XPvRs0pP-QOzGVFkl6YRZRoxcDPKJhYk56VCcSGMCCneP5zPVmn5KCdrGXrqHnSs1UNWGEL5nz1WVNKS34Qq1iG2bIz3dTRDWhxQ"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMzg0In0.GjlgUXM3DdHstkRJmWxEu1hlUOAXVdi4QacIKHJ2tOTGK1isCipPS6SriwG2DFV-NzHI8Xq5RHG1SuWdqkfyspzh3DeMQqhe05_K9EQP4Wwuu2hoB21Ef81Ygzov_ZMM8oDYc5fZQcihQZzkgLruaqyAN92anSmwhk0ZqLOkhSkqanNJW4heMmFfjDN-Xz06mk0DtNygPnOi3QITvkLroG2rwQXn2Dxc-jcA44_kbM4TJdHO2akHD29XSfkFYRf1imGIXw805A7hR6amIyzcpZxnBAzoq07Lh_OOhclFOfOb5Cf0sJzsIEQ1zNNd5R5CES6xnY6AnrvZzXsOHiwmEA.MtjJokYigbw2ixlD.mzAuYJonvNCbViyf.hl-jC9xrH0mgy8oYYAFksw";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_rsa_oaep512_aes128gcm_test() {
        let jwk_json = r#"{"kty":"RSA","d":"PKVgChiq7aJjnyHCtdseL_IGe4jrDBsauYQDYve7kZ5fCTPV5MbSCVPTWFgDlTgNJLwpkNMcUSiwqDjpK3TMxpNmAdx2kyac4G-uVq8QGlJ30zZKJGlrdlKcwKm5TIo0vkIIlCY4dSUTUXIZFbEloGg-_KeECjCuBsQISQs6G8J-ds4ulYNhn_xqNr22h8wWtdQV_6N1xN-m31MAxR5PobmCJauuBZE_SZrl3xcFemi25kc-VFL1shEg9J5jMG7hIMCRdU39DxWNQKfbfa85XMUP1pf9XCODpJVzz1ho1nPy1bYrI3TssvQanITeJGKB_BGQw2XXCyfFiLRO2AYshQ","e":"AQAB","n":"gGw7c9FKQd61aQ2r-SISRcxSdwY_-0lRlrDwRGIGFSRTilWatcz8ry0k4oGVWvGrDnHjCm-pFV_Cd1-Kgx9PaUIrgLxmM5vH2BGofRzEYYcaOhFubKLzbuYgd_WxdFIIUzxqOfEADXqdZc-qK9_3aQp5ppIiE60Nr15DsA77M8yv1gcbN0l-ZvKSO253rvxpqQjHybMsCxfY7P8CvYk5TtUo1-4b_6l_V9FNktns4NKzs_jmFHPiSF3j2hfvQ8tF9eAsfxQvuI_Rm-i2b97pic_jeEkNa8q4760L_FTucB1HFK0L6LNXYHVfLSOvhmAl1JotmoOPNi4vGjlweTIn0Q"}"#;
        let compact_serialization = "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtNTEyIn0.YArIgWGVRn5d8viiV3ThNq-jKPi_FvK3jM3Vp0SRtsz3sRxSOUNgWR69iZt6H5dGE9RlAanETEYeMQtlpW00fx1isLgIG3k3hZHdg1FPSorhSbzhgwFj0oq3l60kklaVc7QBhUPZ3ahDMK_svITfahDJiNUk6w0Fk6G4yq3f3IV3ax8JAF6A8jD5629onun8cGGVOAB0TaBnX5vNXdok3bUYjDTE3Yqp7qHxVKbDQKhkGARaOePPCkbGjvcxyEACny1d1OlT5sKi6osGTP2Z3uOkSjpTBFvsMsXS8r0AlgM2YsULjCMjD-R7y4rtIkSaEG51gso8Rz9jmaP0FyxYnQ.Czmgbp1E3vPlp8Gc._CLceMemxtbHzbgg.21fixbxi-CDjjNyeUaWxtA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_ecdh_es_aes128gcm_test() {
        let jwk_json = r#"{"kty":"EC","d":"tYmAw8_d9e9k9qNxT-z7HzcEP7DBRrkuwHvm6wr50y4","crv":"P-256","x":"IDEAPm-D1g6IWl4KTI9xPmz1TdlkqXQrIipfhbBDyXY","y":"NXJYgyrEb084r7ybsAfpf4YhVjeUuCVDqp-qiTn7pY4"}"#;
        let compact_serialization = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJyb2lDVFpjV2tBTkd6X0ZxTXJQNkNHeVpFaDdpakwyaTZWNmxjWElFMkMwIiwieSI6InBNdFZEbHliM2VWMTUwbTNpakhxYmJqOXk4cEw4d2p2X09xVFkyaXhUWjAifSwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IkVDREgtRVMifQ..o7lofEA4sH1uhqk_.NXlZFyPqcttXJcQC.6U6HB5GeHJiumZeZfDVghA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_ecdh_es_x25519_aes128gcm_test() {
        let jwk_json = r#"{"kty":"OKP","d":"l6O0knpVLqWT5RDt6tivYSmoOhv7dF_qXEMfTjTxNY4","crv":"X25519","x":"QfjAvWo5cahODIFx0AB9lzYyHQMVApVjVFkL-GXSQwk"}"#;
        let compact_serialization = "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IjhUYlJocjhKTXpmOERkNWdGMWRQV0ltbkJFdERLdUh6VmRUMm5ncGQxaXcifSwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IkVDREgtRVMifQ..eb5fvCTSN8JXESTE.Yi8k1Ec3K6M6yl4X.Bqi6JZ1Gnj5rV4qn6c2SEA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_ecdh_es_a128kw_aes128gcm_test() {
        let jwk_json = r#"{"kty":"EC","d":"UMzcFmZ1qT1ce7sdrslokS283y_9Q3DNVaaVwfWzPQU","crv":"P-256","x":"s2vTfNFGZT7rKIUpYJR_cwsBh4jgaBhGsZaf3zzu8p4","y":"xZhHibBxK1sr6EqgTElAMBatWywWF5TqCgM6T9uxzmA"}"#;
        let compact_serialization = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJZX0JSS2staW1rVzRmN1hFX2pfUEFaUVplTkFzd19VdlhlX0t4aThFdGFzIiwieSI6InRaUzJ3cXd4bWoxeWFKUk9jcTRtb0IyT2F4RW8yMGJuUGU4S0M4X2IwUjAifSwiZW5jIjoiQTEyOEdDTSIsImFsZyI6IkVDREgtRVMrQTEyOEtXIn0.FG62JuAfcIeGSvNsKls8JmVfIuoXQ0Cm.KFk0-AQjsPAiMoa-.QqfUGG8pvw3VGE5W.7ElwsJrxPAmkgj3kZOi3Gg";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_ecdh_es_a256kw_aes256gcm_test() {
        let jwk_json = r#"{"kty":"EC","d":"AMdK5ZS6bqgebqm13k5_PbtuJ1mw5A-AwrQEmXstlFr67tl-UmzgM9zhWEBaum4Of7GkVL6DvxSf7lQqppGwbXMm","crv":"P-521","x":"AVsM5Q6v_wyaviAKDnwbQ2ZYKgH5BymwpT7xrkcOc9C58VemRCPe-Q9qR4_CM3LQaCul1SSj7fywaxX05iCyUXv2","y":"AZzP7cXNLR-EIycXgNfbq172WvPxNdpTktTfy54Qna4p2rlTNMGULN9hgQlkA3Lu8-gjfgrlePuX0WH8R-ekpm12"}"#;
        let compact_serialization = "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTUyMSIsIngiOiJBSUpZODkzdmJaMFRWRHY2N2JFbl9OZGhBTE03OFN6azBqamJMOGZkc2ZROUt4ckZWVUZPaTFKdEd5RlF0X3pIZGh2aHI3TDFMZ3FlTFFET2dLd1NJQ2dOIiwieSI6IkFiV21rUDdHMEJXZFhyeWNDV1VxQVJyTWU2RVRfMUw1YnRnVVFGei1XeGZIOHNiNm5QcnpTS2NOcWVwakFKbmVnczdlWlY3b2NYYWJKUWp1SEJxQmZHUUYifSwiZW5jIjoiQTI1NkdDTSIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0.Yw5Rwcy9MkZmrOy6dsc1saQs94hJwMrPAUU3AwYTr-X65O-s4Xvqqw.4kCCTwOC-M8OL3eI.ORPsZ236gU38qN6q.S_Ctuax5iG7oEw_B9XJcWA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_ecdh_es_a128kw_x25519_aes128gcm_test() {
        let jwk_json = r#"{"kty":"OKP","d":"VzIjaDnF1eeUzz3Nx9h4l_8Z5Eog97t3dtfHKebctKw","crv":"X25519","x":"qBgwQvrRjOFgawDnyIgCMie44CFy8rquQfQ_d9h5UiI"}"#;
        let compact_serialization = "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6ImhqREVhU2FRMi1uMXdndjVkWmJoNHdDTzNnN3owSTlTLW44MVNNQlJtZ1EifSwiZW5jIjoiWEMyMFAiLCJhbGciOiJFQ0RILUVTK0ExMjhLVyJ9.Qqv-pvkB1iFkvNphg7s4E2qyL_usnhgBoPyWpAGqEMbb9V3Z1_a0Ww.FuFdpNBOKAj7Uj5gJF2JN9Y_L9u5OzVM.AyQ2NhLV1M7U3OSl.amj_zKMXJjsS4Ste7n7iTA";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = b"Hello world!";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(*payload, *expected);
    }

    // Vector from the JOSE cookbook (also used in jose4j's JoseCookbookTest):
    // PBES2-HS256+A128KW key management with A128CBC-HS256 content encryption.
    #[test]
    fn decrypt_pbes2_hs256_a128kw_aes128cbc_hs256_test() {
        let jwk_json = r#"{"kty":"oct","k":"ZW50cmFwX29fcGV0ZXJfbG9uZ19jcmVkaXRfdHVu"}"#;
        let compact_serialization = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YKbKLsEoyw_JoNvhtuHo9aaeRNSEhhAW2OVHcuF_HLqS0n6hA_fgCA.VBiCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p.ALTKwxvAefeL-32NY7eTAQ";

        let constraints = AlgorithmConstraints::new(
            ConstraintType::Permit,
            [KeyManagementAlgorithm::Pbes2Hs256A128Kw],
        );
        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        let expected = "{\"keys\":[\
            {\"kty\":\"oct\",\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\",\"use\":\"enc\",\"alg\":\"A128GCM\",\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\"},\
            {\"kty\":\"oct\",\"kid\":\"81b20965-8332-43d9-a468-82160ad91ac8\",\"use\":\"enc\",\"alg\":\"A128KW\",\"k\":\"GZy6sIZ6wl9NJOKB-jnmVQ\"},\
            {\"kty\":\"oct\",\"kid\":\"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d\",\"use\":\"enc\",\"alg\":\"A256GCMKW\",\"k\":\"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8\"}]}";
        let payload = jwe.payload(&jwk).unwrap();
        assert_eq!(payload, expected.as_bytes());
    }

    // An excessive 'p2c' must be rejected to guard against the "billion hashes"
    // denial of service attack (same vector as jose4j's p2cTooBig test).
    #[test]
    fn decrypt_pbes2_iteration_count_too_large_test() {
        let jwk_json = r#"{"kty":"oct","k":"c3VwZXIgc2VjcmV0IHdvcmQ"}"#; // "super secret word"
        let compact_serialization = "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJjIjoyMTQ3NDgzNjQ3LCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.YKbKLsEoyw_JoNvhtuHo9aaeRNSEhhAW2OVHcuF_HLqS0n6hA_fgCA.VBiCzVHNoLiR3F4V82uoTQ.23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p.ALTKwxvAefeL-32NY7eTAQ";

        let constraints = AlgorithmConstraints::new(
            ConstraintType::Permit,
            [KeyManagementAlgorithm::Pbes2Hs512A256Kw],
        );
        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();

        assert!(jwe.payload(&jwk).is_err());
    }

    // Round-trip encrypt -> decrypt helpers and tests. Each exercises a
    // different key management family against a generated key.

    use crate::jwk::JsonWebKeyGenerator;

    fn round_trip(
        key_mgmt_alg: KeyManagementAlgorithm,
        content_enc_alg: ContentEncryptionAlgorithm,
        constraints: &AlgorithmConstraints<KeyManagementAlgorithm>,
    ) {
        let plaintext = b"Hello, JWE world!";
        let key = JsonWebKeyGenerator::for_encryption(key_mgmt_alg)
            .generate()
            .unwrap();

        // Encrypt.
        let mut enc = JsonWebEncryption::new();
        enc.set_algorithm_constraints(constraints);
        enc.set_algorithm_header_value(key_mgmt_alg.name());
        enc.set_header(HeaderParameter::EncryptionMethod, content_enc_alg.name());
        enc.set_payload(plaintext);
        enc.encrypt(&key).unwrap();
        let compact = enc.compact_serialization().unwrap();

        // Decrypt from the compact serialization.
        let mut dec = JsonWebEncryption::new();
        dec.set_algorithm_constraints(constraints);
        dec.set_compact_serialization(&compact).unwrap();
        let decrypted = dec.payload(&key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    fn permit(alg: KeyManagementAlgorithm) -> AlgorithmConstraints<KeyManagementAlgorithm> {
        AlgorithmConstraints::new(ConstraintType::Permit, [alg])
    }

    #[test]
    fn round_trip_direct() {
        round_trip(
            KeyManagementAlgorithm::Direct,
            ContentEncryptionAlgorithm::Aes256Gcm,
            &permit(KeyManagementAlgorithm::Direct),
        );
    }

    #[test]
    fn round_trip_aes_kw() {
        for (alg, enc) in [
            (
                KeyManagementAlgorithm::A128Kw,
                ContentEncryptionAlgorithm::Aes128Gcm,
            ),
            (
                KeyManagementAlgorithm::A192Kw,
                ContentEncryptionAlgorithm::Aes192Gcm,
            ),
            (
                KeyManagementAlgorithm::A256Kw,
                ContentEncryptionAlgorithm::Aes256Gcm,
            ),
            (
                KeyManagementAlgorithm::A256Kw,
                ContentEncryptionAlgorithm::Aes256CbcHmacSha512,
            ),
        ] {
            round_trip(alg, enc, &permit(alg));
        }
    }

    #[test]
    #[cfg(feature = "zip")]
    fn round_trip_zip_deflate() {
        // Highly compressible payload so the `zip: DEF` path is exercised
        // meaningfully; round-trips through both an AEAD and a CBC-HMAC enc.
        let plaintext = b"Hello, JWE world! Hello, JWE world! Hello, JWE world!";
        for enc_alg in [
            ContentEncryptionAlgorithm::Aes128Gcm,
            ContentEncryptionAlgorithm::Aes128CbcHmacSha256,
        ] {
            let key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
                .generate()
                .unwrap();
            let constraints = permit(KeyManagementAlgorithm::A128Kw);

            let mut enc = JsonWebEncryption::new();
            enc.set_algorithm_constraints(&constraints);
            enc.set_algorithm(KeyManagementAlgorithm::A128Kw);
            enc.set_encryption_method(enc_alg);
            enc.set_payload(plaintext);
            enc.enable_default_compression();
            enc.encrypt(&key).unwrap();
            // The zip header must be present in the emitted token.
            assert_eq!(enc.header(HeaderParameter::Zip), Some("DEF"));
            let compact = enc.compact_serialization().unwrap();

            let mut dec = JsonWebEncryption::new();
            dec.set_algorithm_constraints(&constraints);
            dec.set_compact_serialization(&compact).unwrap();
            let decrypted = dec.payload(&key).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    #[cfg(feature = "zip")]
    fn decrypt_zip_enforces_size_cap() {
        // Compress a large payload, then decrypt with a tiny cap and expect a
        // decompression-limit error rather than the expanded bytes.
        let plaintext = vec![0u8; 1 << 20];
        let key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
            .generate()
            .unwrap();
        let constraints = permit(KeyManagementAlgorithm::A128Kw);

        let mut enc = JsonWebEncryption::new();
        enc.set_algorithm_constraints(&constraints);
        enc.set_algorithm(KeyManagementAlgorithm::A128Kw);
        enc.set_encryption_method(ContentEncryptionAlgorithm::Aes128Gcm);
        enc.set_payload(&plaintext);
        enc.enable_default_compression();
        enc.encrypt(&key).unwrap();
        let compact = enc.compact_serialization().unwrap();

        let mut dec = JsonWebEncryption::new();
        dec.set_algorithm_constraints(&constraints);
        dec.set_compact_serialization(&compact).unwrap();
        dec.set_max_decompressed_size(1024);
        let err = dec.payload(&key).unwrap_err();
        assert!(err.to_string().contains("exceeds"));

        // With an adequate cap the same token decrypts fully.
        let mut dec2 = JsonWebEncryption::new();
        dec2.set_algorithm_constraints(&constraints);
        dec2.set_compact_serialization(&compact).unwrap();
        dec2.set_max_decompressed_size(1 << 20);
        assert_eq!(dec2.payload(&key).unwrap(), &plaintext[..]);
    }

    #[test]
    #[cfg(feature = "zip")]
    fn unsupported_zip_value_rejected_on_encrypt() {
        // Setting an unknown `zip` algorithm must fail at encrypt time rather
        // than emit a token that silently skips compression.
        let key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
            .generate()
            .unwrap();
        let constraints = permit(KeyManagementAlgorithm::A128Kw);

        let mut enc = JsonWebEncryption::new();
        enc.set_algorithm_constraints(&constraints);
        enc.set_algorithm(KeyManagementAlgorithm::A128Kw);
        enc.set_encryption_method(ContentEncryptionAlgorithm::Aes128Gcm);
        enc.set_payload(b"data");
        enc.set_header(HeaderParameter::Zip, "GZIP");
        assert!(enc.encrypt(&key).is_err());
    }

    #[test]
    fn round_trip_aes_gcm_kw() {
        for alg in [
            KeyManagementAlgorithm::A128GcmKw,
            KeyManagementAlgorithm::A192GcmKw,
            KeyManagementAlgorithm::A256GcmKw,
        ] {
            round_trip(alg, ContentEncryptionAlgorithm::Aes128Gcm, &permit(alg));
        }
    }

    #[test]
    fn round_trip_rsa() {
        for alg in [
            KeyManagementAlgorithm::Rsa15,
            KeyManagementAlgorithm::RsaOaep,
            KeyManagementAlgorithm::RsaOaep256,
            KeyManagementAlgorithm::RsaOaep384,
            KeyManagementAlgorithm::RsaOaep512,
        ] {
            round_trip(alg, ContentEncryptionAlgorithm::Aes128Gcm, &permit(alg));
        }
    }

    #[test]
    fn round_trip_ecdh_es() {
        round_trip(
            KeyManagementAlgorithm::EcdhEs,
            ContentEncryptionAlgorithm::Aes128Gcm,
            &permit(KeyManagementAlgorithm::EcdhEs),
        );
    }

    #[test]
    fn round_trip_ecdh_es_kw() {
        for alg in [
            KeyManagementAlgorithm::EcdhEsA128Kw,
            KeyManagementAlgorithm::EcdhEsA192Kw,
            KeyManagementAlgorithm::EcdhEsA256Kw,
        ] {
            round_trip(alg, ContentEncryptionAlgorithm::Aes128Gcm, &permit(alg));
        }
    }

    #[test]
    fn round_trip_pbes2() {
        for alg in [
            KeyManagementAlgorithm::Pbes2Hs256A128Kw,
            KeyManagementAlgorithm::Pbes2Hs384A192Kw,
            KeyManagementAlgorithm::Pbes2Hs512A256Kw,
        ] {
            round_trip(alg, ContentEncryptionAlgorithm::Aes128Gcm, &permit(alg));
        }
    }

    // -- wrong-key-type rejection ----------------------------------------

    #[test]
    fn encrypt_rsa_alg_rejects_ec_key() {
        let constraints = permit(KeyManagementAlgorithm::RsaOaep256);
        let ec_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEs)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_header_value(KeyManagementAlgorithm::RsaOaep256.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.set_algorithm_constraints(&constraints);
        assert!(jwe.encrypt(&ec_key).is_err());
    }

    #[test]
    fn encrypt_ecdh_alg_rejects_rsa_key() {
        let constraints = permit(KeyManagementAlgorithm::EcdhEs);
        let rsa_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::RsaOaep)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_header_value(KeyManagementAlgorithm::EcdhEs.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.set_algorithm_constraints(&constraints);
        assert!(jwe.encrypt(&rsa_key).is_err());
    }

    #[test]
    fn decrypt_rsa_alg_rejects_ec_key() {
        let constraints = permit(KeyManagementAlgorithm::RsaOaep256);
        let rsa_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::RsaOaep256)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_header_value(KeyManagementAlgorithm::RsaOaep256.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.set_algorithm_constraints(&constraints);
        jwe.encrypt(&rsa_key).unwrap();
        let compact = jwe.compact_serialization().unwrap();

        let ec_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::EcdhEs)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(&compact).unwrap();
        jwe.set_algorithm_constraints(&constraints);
        assert!(jwe.payload(&ec_key).is_err());
    }

    #[test]
    fn encrypt_aes_kw_rejects_rsa_key() {
        let constraints = permit(KeyManagementAlgorithm::A128Kw);
        let rsa_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::RsaOaep)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_header_value(KeyManagementAlgorithm::A128Kw.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.set_algorithm_constraints(&constraints);
        assert!(jwe.encrypt(&rsa_key).is_err());
    }

    // -- malformed key-management input rejection -------------------------
    //
    // These lock in the `manage_decrypt` guards that reject malformed
    // key-management material (wrong-size management keys, truncated or
    // non-block-aligned wrapped keys) before it reaches the AEAD/AES
    // primitives. Each builds a valid KW token, then corrupts the
    // `encrypted_key` segment or swaps in an undersized management key.

    /// Encrypts a minimal `alg`/A128GCM token with a generated key, returning
    /// the key and the compact serialization's segments.
    fn encrypt_kw_token(alg: KeyManagementAlgorithm) -> (crate::jwk::JsonWebKey, Vec<String>) {
        let constraints = permit(alg);
        let key = JsonWebKeyGenerator::for_encryption(alg).generate().unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_algorithm_header_value(alg.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.encrypt(&key).unwrap();
        let compact = jwe.compact_serialization().unwrap();
        let segments = compact.split('.').map(str::to_string).collect();
        (key, segments)
    }

    /// Reassembles `segments`, parses, and attempts decryption with `key`.
    fn try_decrypt(segments: &[String], key: &JsonWebKey, alg: KeyManagementAlgorithm) -> bool {
        let constraints = permit(alg);
        let compact = segments.join(".");
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(&compact).unwrap();
        jwe.payload(key).is_ok()
    }

    #[test]
    fn decrypt_aes_kw_rejects_undersized_management_key() {
        // A128KW requires a 16-byte key; a 24-byte A192KW key must be
        // rejected as an invalid length before unwrapping.
        let constraints = permit(KeyManagementAlgorithm::A128Kw);
        let good_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A128Kw)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_payload("payload");
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_algorithm_header_value(KeyManagementAlgorithm::A128Kw.name());
        jwe.set_header(
            HeaderParameter::EncryptionMethod,
            ContentEncryptionAlgorithm::Aes128Gcm.name(),
        );
        jwe.encrypt(&good_key).unwrap();
        let compact = jwe.compact_serialization().unwrap();

        let wrong_len_key = JsonWebKeyGenerator::for_encryption(KeyManagementAlgorithm::A192Kw)
            .generate()
            .unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_algorithm_constraints(&constraints);
        jwe.set_compact_serialization(&compact).unwrap();
        assert!(jwe.payload(&wrong_len_key).is_err());
    }

    #[test]
    fn decrypt_aes_kw_rejects_non_block_aligned_encrypted_key() {
        // Truncating the wrapped key so it is not a multiple of the 8-byte
        // AES-KW block must be rejected before unwrapping.
        let (key, mut segments) = encrypt_kw_token(KeyManagementAlgorithm::A128Kw);
        let mut encrypted_key = base64::url_decode(&segments[1]).unwrap().into_vec();
        encrypted_key.truncate(encrypted_key.len() - 4); // no longer % 8 == 0
        segments[1] = String::from_utf8(base64::url_encode(&encrypted_key).into_vec()).unwrap();
        assert!(!try_decrypt(
            &segments,
            &key,
            KeyManagementAlgorithm::A128Kw
        ));
    }

    #[test]
    fn decrypt_aes_kw_rejects_too_short_encrypted_key() {
        // Fewer than 16 bytes of wrapped key carries no integrity check.
        let (key, mut segments) = encrypt_kw_token(KeyManagementAlgorithm::A128Kw);
        let mut encrypted_key = base64::url_decode(&segments[1]).unwrap().into_vec();
        encrypted_key.truncate(8); // < 16, though still % 8 == 0
        segments[1] = String::from_utf8(base64::url_encode(&encrypted_key).into_vec()).unwrap();
        assert!(!try_decrypt(
            &segments,
            &key,
            KeyManagementAlgorithm::A128Kw
        ));
    }

    #[test]
    fn decrypt_aes_kw_rejects_corrupted_encrypted_key() {
        // Flipping bits in the wrapped key must fail the AES-KW integrity
        // check even when lengths are valid.
        let (key, mut segments) = encrypt_kw_token(KeyManagementAlgorithm::A128Kw);
        let mut encrypted_key = base64::url_decode(&segments[1]).unwrap().into_vec();
        encrypted_key[0] ^= 0x01;
        segments[1] = String::from_utf8(base64::url_encode(&encrypted_key).into_vec()).unwrap();
        assert!(!try_decrypt(
            &segments,
            &key,
            KeyManagementAlgorithm::A128Kw
        ));
    }
}
