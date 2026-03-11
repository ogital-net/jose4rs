mod aes_hmac;
mod content_enc_alg;
mod kdf;
mod key_mgmt_alg;

use std::sync::LazyLock;

pub use content_enc_alg::ContentEncryptionAlgorithm;
pub use key_mgmt_alg::KeyManagementAlgorithm;
use simd_json::{
    derived::{MutableObject, ValueObjectAccessAsScalar as _},
    ValueBuilder,
};

use crate::{
    base64,
    error::JoseError,
    jwa::{AlgorithmConstraints, ConstraintType},
    jwk::JsonWebKey,
    jwx::{HeaderParameter, JsonWebStructure, Memchr},
    BufferRef,
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

pub(super) struct ContentEncryptionParts {
    iv: Box<[u8]>,
    ciphertext: Vec<u8>,
    authentication_tag: Box<[u8]>,
}

pub struct JsonWebEncryption<'a> {
    buffer: Vec<u8>,
    key: Option<&'a JsonWebKey>,
    header: Option<simd_json::owned::Value>,
    encoded_header: Option<BufferRef>,
    encrypted_key: Option<BufferRef>,
    iv: Option<BufferRef>,
    ciphertext: Option<BufferRef>,
    auth_tag: Option<BufferRef>,
    plaintext: Option<BufferRef>,
    algorithm_constraints: &'a AlgorithmConstraints<KeyManagementAlgorithm>,
}

impl<'a> JsonWebEncryption<'a> {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            key: None,
            header: None,
            encoded_header: None,
            encrypted_key: None,
            iv: None,
            ciphertext: None,
            auth_tag: None,
            plaintext: None,
            algorithm_constraints: &DEFAULT_BLOCK,
        }
    }

    fn decrypt(&mut self) -> Result<&[u8], JoseError> {
        let key_mgmt_alg = self.get_key_mgmt_alg(true)?;
        let content_enc_alg = self.get_content_enc_alg()?;

        let ciphertext = self
            .ciphertext
            .as_ref()
            .ok_or(JoseError::new("missing ciphertext"))?
            .get(&self.buffer);
        let management_key = self.key.ok_or(JoseError::new("no decryption key"))?;
        let encrypted_key = self
            .encrypted_key
            .ok_or(JoseError::new("missing encrypted key"))?
            .get(&self.buffer);
        let headers = self
            .header
            .as_ref()
            .ok_or(JoseError::new("missing header"))?;

        let cek = key_mgmt_alg.manage_decrypt(management_key, encrypted_key, headers)?;
        let iv = self
            .iv
            .ok_or(JoseError::new("missing IV"))?
            .get(&self.buffer);
        let auth_tag = self
            .auth_tag
            .ok_or(JoseError::new("missing authentication tag"))?
            .get(&self.buffer);
        let aad = self
            .encoded_header
            .ok_or(JoseError::new("missing encoded header"))?
            .get(&self.buffer);

        let mut ciphertext = Box::from(ciphertext);
        let plain = content_enc_alg.decrypt(iv, &mut ciphertext, auth_tag, aad, &cek)?;
        let start_idx = self.buffer.len();
        self.buffer.extend_from_slice(plain);
        let plaintext = BufferRef::new(start_idx, self.buffer.len());
        self.plaintext = Some(plaintext);

        Ok(plaintext.get(&self.buffer))
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
        let header = simd_json::to_owned_value(json_buf.get_mut(&mut self.buffer))?;

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
        let alg =
            self.get_header(HeaderParameter::Algorithm)
                .ok_or(JoseError::InvalidAlgorithm(
                    "Encryption key management algorithm header not set.".into(),
                ))?;
        let alg = KeyManagementAlgorithm::try_from(alg)?;
        if check_constraints {
            self.algorithm_constraints.check_constraint(alg)?;
        }
        Ok(alg)
    }

    fn get_content_enc_alg(&self) -> Result<ContentEncryptionAlgorithm, JoseError> {
        let alg = self.get_header(HeaderParameter::EncryptionMethod).ok_or(
            JoseError::InvalidAlgorithm("Content encryption header not set.".into()),
        )?;
        ContentEncryptionAlgorithm::try_from(alg)
    }
}

impl<'a> JsonWebStructure<'a, KeyManagementAlgorithm> for JsonWebEncryption<'a> {
    fn set_compact_serialization(
        &mut self,
        compact_serialization: &'a (impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError> {
        let compact_serialization = compact_serialization.as_ref();

        let delimeter_indexes = {
            let mut iter = Memchr::new(b'.', compact_serialization);

            let mut indexes = [0usize; 4];
            for idx in &mut indexes {
                match iter.next() {
                    Some(i) => *idx = i,
                    None => return Err(JoseError::new("not enough parts")),
                }
            }
            if iter.next().is_some() {
                return Err(JoseError::new("too many parts"));
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

    fn get_compact_serialization(&self) -> Result<String, JoseError> {
        todo!()
    }

    fn set_payload(&mut self, payload: impl AsRef<[u8]>) {
        let start = self.buffer.len();
        self.buffer.extend_from_slice(payload.as_ref());
        self.plaintext = Some(BufferRef::new(start, self.buffer.len()));
    }

    fn get_payload(&mut self) -> Result<&[u8], JoseError> {
        if let Some(plain) = self.plaintext {
            return Ok(plain.get(&self.buffer));
        }

        self.decrypt()
    }

    fn set_header_name(&mut self, name: impl Into<String>, value: impl Into<String>) {
        match self.header {
            Some(ref mut header) => {
                header.insert(name.into(), value.into()).unwrap();
            }
            None => {
                let mut header = simd_json::owned::Value::object();
                header.insert(name.into(), value.into()).unwrap();
                self.header = Some(header);
            }
        };
    }

    fn get_header_name(&self, name: impl AsRef<str>) -> Option<&str> {
        match self.header {
            Some(ref header) => header.get_str(name.as_ref()),
            None => None,
        }
    }

    fn set_key(&mut self, key: &'a JsonWebKey) {
        self.key = Some(key);
    }

    fn get_key(&mut self) -> Option<&'a JsonWebKey> {
        self.key
    }

    fn set_algorithm_constraints(
        &mut self,
        algorithm_constraints: &'a AlgorithmConstraints<KeyManagementAlgorithm>,
    ) {
        self.algorithm_constraints = algorithm_constraints;
    }
}

pub(super) struct ContentEncryptionKeys {
    content_encryption_key: Box<[u8]>,
    encrypted_key: Option<Box<[u8]>>,
}

impl ContentEncryptionKeys {
    pub(super) fn new(
        content_encryption_key: impl Into<Box<[u8]>>,
        encrypted_key: impl Into<Box<[u8]>>,
    ) -> Self {
        Self {
            content_encryption_key: content_encryption_key.into(),
            encrypted_key: Some(encrypted_key.into()),
        }
    }

    pub(super) fn direct(content_encryption_key: impl Into<Box<[u8]>>) -> Self {
        Self {
            content_encryption_key: content_encryption_key.into(),
            encrypted_key: None,
        }
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
        assert_eq!(*payload, *expected);
    }

    #[test]
    fn decrypt_direct_xc20p_test() {
        let jwk_json = r#"{"kty":"oct","k":"Sr1D4Rnf31x2SYXdy8AtLDBAgx-cLJaXtAmGS-OVIg4"}"#;
        let compact_serialization = "eyJlbmMiOiJYQzIwUCIsImFsZyI6ImRpciJ9..nTYOzMHBUV3ZFTU3HouBBUUHOZqTQZQt.30val_-t-HDPAORH.-PXYFmoBz38m1FvhWDU7wQ";

        let jwk = JsonWebKey::from_json(jwk_json).unwrap();
        let mut jwe = JsonWebEncryption::new();
        jwe.set_compact_serialization(compact_serialization)
            .unwrap();
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
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
        jwe.set_key(&jwk);

        let expected = b"Hello world!";
        let payload = jwe.get_payload().unwrap();
        assert_eq!(*payload, *expected);
    }
}
