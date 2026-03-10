use crate::crypto::hmac;
use crate::crypto::mem::crypto_memcmp;
use crate::crypto::CipherAlgorithm;
use crate::crypto::DigestAlgorithm;
use crate::crypto::EvpCipherCtx;
use crate::error::JoseError;

pub(super) struct AesHmacAeadCtx {
    algorithm: Algorithm,
    key: Box<[u8]>,
    evp_cipher_ctx: EvpCipherCtx,
}

impl AesHmacAeadCtx {
    pub(super) fn init(algorithm: Algorithm, key: &[u8]) -> Self {
        let key = Box::from(key);
        Self {
            algorithm,
            key,
            evp_cipher_ctx: EvpCipherCtx::init(),
        }
    }

    pub(super) fn encrypt<'a>(
        &mut self,
        iv: &[u8],
        aad: &[u8],
        in_out: &mut Vec<u8>,
        tag: &'a mut [u8],
    ) -> Result<&'a [u8], JoseError> {
        let alg_key_len = self.algorithm.key_len();
        if self.key.len() != alg_key_len {
            return Err(JoseError::new("key length mismatch"));
        }

        if tag.len() != self.algorithm.tag_length() {
            return Err(JoseError::new("tag length mismatch"));
        }

        // https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.2
        // Split the key into MAC and encryption keys
        let (mac_key, enc_key) = self.key.split_at(alg_key_len / 2);

        // Encrypt the plaintext
        // The plaintext is CBC encrypted using PKCS #7 padding using
        // ENC_KEY as the key and the IV.  We denote the ciphertext output
        // from this step as E.
        // key and IV length are checked by EvpCipherCtx
        let e =
            self.evp_cipher_ctx
                .encrypt(self.algorithm.cipher_algorithm(), enc_key, iv, in_out)?;

        // The octet string AL is equal to the number of bits in the
        // Additional Authenticated Data A expressed as a 64-bit unsigned
        // big-endian integer.
        let al = ((aad.len() as u64) * 8).to_be_bytes();

        // A message Authentication Tag T is computed by applying HMAC
        // [RFC2104] to the following data, in order:
        //
        //    the Additional Authenticated Data A,
        //    the Initialization Vector IV,
        //    the ciphertext E computed in the previous step, and
        //    the octet string AL defined above.
        //
        // The string MAC_KEY is used as the MAC key.  We denote the output
        // of the MAC computed in this step as M.  The first T_LEN octets of
        // M are used as T.
        let mac_input = [aad, iv, e, &al].concat();
        let m = hmac::hmac(self.algorithm.digest_algorithm(), mac_key, &mac_input)?;

        tag.copy_from_slice(&m[..tag.len()]);
        Ok(tag)
    }

    pub(super) fn decrypt<'a>(
        &mut self,
        iv: &[u8],
        aad: &[u8],
        in_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], JoseError> {
        if self.key.len() != self.algorithm.key_len() {
            return Err(JoseError::new("key length mismatch"));
        }

        // https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.2
        // Split the key into MAC and encryption keys
        let (mac_key, enc_key) = self.key.split_at(self.algorithm.key_len() / 2);

        // The integrity and authenticity of A and E are checked by
        // computing an HMAC with the inputs as in Step 5 of
        // Section 5.2.2.1.  The value T, from the previous step, is
        // compared to the first MAC_KEY length bits of the HMAC output.  If
        // those values are identical, then A and E are considered valid,
        // and processing is continued.  Otherwise, all of the data used in
        // the MAC validation are discarded, and the authenticated
        // decryption operation returns an indication that it failed, and
        // the operation halts.  (But see Section 11.5 of [JWE] for security
        // considerations on thwarting timing attacks.)
        let al = ((aad.len() as u64) * 8).to_be_bytes();
        let mac_input = [aad, iv, in_out, &al].concat();
        let m = hmac::hmac(self.algorithm.digest_algorithm(), mac_key, &mac_input)?;

        if tag.len() != self.algorithm.tag_length() {
            return Err(JoseError::new("tag length mismatch"));
        }

        if !crypto_memcmp(tag, &m[..tag.len()]) {
            return Err(JoseError::new("tag mismatch"));
        }

        // The value E is decrypted and the PKCS #7 padding is checked and
        // removed.  The value IV is used as the Initialization Vector.  The
        // value ENC_KEY is used as the decryption key.
        self.evp_cipher_ctx
            .decrypt(self.algorithm.cipher_algorithm(), enc_key, iv, in_out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Aes128CbcHmacSha256,
    Aes192CbcHmacSha384,
    Aes256CbcHmacSha512,
}

impl Algorithm {
    #[inline]
    fn cipher_algorithm(&self) -> CipherAlgorithm {
        match self {
            Algorithm::Aes128CbcHmacSha256 => CipherAlgorithm::Aes128Cbc,
            Algorithm::Aes192CbcHmacSha384 => CipherAlgorithm::Aes192Cbc,
            Algorithm::Aes256CbcHmacSha512 => CipherAlgorithm::Aes256Cbc,
        }
    }

    #[inline]
    fn digest_algorithm(&self) -> DigestAlgorithm {
        match self {
            Algorithm::Aes128CbcHmacSha256 => DigestAlgorithm::Sha256,
            Algorithm::Aes192CbcHmacSha384 => DigestAlgorithm::Sha384,
            Algorithm::Aes256CbcHmacSha512 => DigestAlgorithm::Sha512,
        }
    }

    #[inline]
    pub fn key_len(&self) -> usize {
        match self {
            Algorithm::Aes128CbcHmacSha256 => 32,
            Algorithm::Aes192CbcHmacSha384 => 48,
            Algorithm::Aes256CbcHmacSha512 => 64,
        }
    }

    #[inline]
    pub fn tag_length(&self) -> usize {
        match self {
            Algorithm::Aes128CbcHmacSha256 => 16,
            Algorithm::Aes192CbcHmacSha384 => 24,
            Algorithm::Aes256CbcHmacSha512 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_cbc_hmac_sha_256_rfc_case() {
        // Key (K)
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        // Initialization Vector (IV)
        let iv: [u8; 16] = [
            0x1a, 0xf3, 0x8c, 0x2d, 0xc2, 0xb9, 0x6f, 0xfd, 0xd8, 0x66, 0x94, 0x09, 0x23, 0x41,
            0xbc, 0x04,
        ];

        // Additional Authenticated Data (AAD)
        let aad: [u8; 42] = [
            0x54, 0x68, 0x65, 0x20, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x20, 0x70, 0x72, 0x69,
            0x6e, 0x63, 0x69, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20, 0x41, 0x75, 0x67, 0x75,
            0x73, 0x74, 0x65, 0x20, 0x4b, 0x65, 0x72, 0x63, 0x6b, 0x68, 0x6f, 0x66, 0x66, 0x73,
        ];

        // Plaintext (P)
        let plaintext: Vec<u8> = vec![
            0x41, 0x20, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65,
            0x6d, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20,
            0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65,
            0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
            0x74, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x61, 0x62, 0x6c, 0x65,
            0x20, 0x74, 0x6f, 0x20, 0x66, 0x61, 0x6c, 0x6c, 0x20, 0x69, 0x6e, 0x74, 0x6f, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x68, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x65, 0x6e, 0x65, 0x6d, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68, 0x6f,
            0x75, 0x74, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x6e, 0x69, 0x65, 0x6e,
            0x63, 0x65,
        ];

        // Expected Ciphertext (E)
        let expected_ciphertext: Vec<u8> = vec![
            0xc8, 0x0e, 0xdf, 0xa3, 0x2d, 0xdf, 0x39, 0xd5, 0xef, 0x00, 0xc0, 0xb4, 0x68, 0x83,
            0x42, 0x79, 0xa2, 0xe4, 0x6a, 0x1b, 0x80, 0x49, 0xf7, 0x92, 0xf7, 0x6b, 0xfe, 0x54,
            0xb9, 0x03, 0xa9, 0xc9, 0xa9, 0x4a, 0xc9, 0xb4, 0x7a, 0xd2, 0x65, 0x5c, 0x5f, 0x10,
            0xf9, 0xae, 0xf7, 0x14, 0x27, 0xe2, 0xfc, 0x6f, 0x9b, 0x3f, 0x39, 0x9a, 0x22, 0x14,
            0x89, 0xf1, 0x63, 0x62, 0xc7, 0x03, 0x23, 0x36, 0x09, 0xd4, 0x5a, 0xc6, 0x98, 0x64,
            0xe3, 0x32, 0x1c, 0xf8, 0x29, 0x35, 0xac, 0x40, 0x96, 0xc8, 0x6e, 0x13, 0x33, 0x14,
            0xc5, 0x40, 0x19, 0xe8, 0xca, 0x79, 0x80, 0xdf, 0xa4, 0xb9, 0xcf, 0x1b, 0x38, 0x4c,
            0x48, 0x6f, 0x3a, 0x54, 0xc5, 0x10, 0x78, 0x15, 0x8e, 0xe5, 0xd7, 0x9d, 0xe5, 0x9f,
            0xbd, 0x34, 0xd8, 0x48, 0xb3, 0xd6, 0x95, 0x50, 0xa6, 0x76, 0x46, 0x34, 0x44, 0x27,
            0xad, 0xe5, 0x4b, 0x88, 0x51, 0xff, 0xb5, 0x98, 0xf7, 0xf8, 0x00, 0x74, 0xb9, 0x47,
            0x3c, 0x82, 0xe2, 0xdb,
        ];

        // Expected Tag (T)
        let expected_tag: [u8; 16] = [
            0x65, 0x2c, 0x3f, 0xa3, 0x6b, 0x0a, 0x7c, 0x5b, 0x32, 0x19, 0xfa, 0xb3, 0xa3, 0x0b,
            0xc1, 0xc4,
        ];

        let mut in_out = plaintext.clone();
        let mut tag_buf = [0u8; 16];

        let mut ctx = AesHmacAeadCtx::init(Algorithm::Aes128CbcHmacSha256, &key);
        let t = ctx.encrypt(&iv, &aad, &mut in_out, &mut tag_buf).unwrap();

        assert_eq!(t, expected_tag);
        //assert_eq!(ciphertext, expected_tag);
        assert_eq!(in_out, expected_ciphertext);

        let p = ctx.decrypt(&iv, &aad, in_out.as_mut_slice(), t).unwrap();
        assert_eq!(p, plaintext);
    }
}
