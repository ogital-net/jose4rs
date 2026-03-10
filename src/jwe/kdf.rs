use crate::crypto::{mem, DigestAlgorithm, MessageDigest};

pub(super) struct ConcatKDF {
    md_alg: DigestAlgorithm,
}

impl ConcatKDF {
    pub(super) fn init(md_alg: DigestAlgorithm) -> Self {
        Self { md_alg }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn kdf(
        &self,
        shared_secret: &[u8],
        key_data_len_bits: usize,
        algorithm_id: impl AsRef<[u8]>,
        party_u_info: impl AsRef<[u8]>,
        party_v_info: impl AsRef<[u8]>,
    ) -> Vec<u8> {
        let algorithm_id = Self::prepend_len(algorithm_id);
        let party_u_info = Self::prepend_len(party_u_info);
        let party_v_info = Self::prepend_len(party_v_info);
        let supp_pub_info = (key_data_len_bits as u32).to_be_bytes();

        self.kdf_internal(
            shared_secret,
            key_data_len_bits,
            &algorithm_id,
            &party_u_info,
            &party_v_info,
            &supp_pub_info,
        )
    }

    fn kdf_internal(
        &self,
        shared_secret: &[u8],
        key_data_len_bits: usize,
        algorithm_id: &[u8],
        party_u_info: &[u8],
        party_v_info: &[u8],
        supp_pub_info: &[u8],
    ) -> Vec<u8> {
        let hash_len_bytes = self.md_alg.output_len();
        let hash_len_bits = hash_len_bytes * 8;

        let reps = key_data_len_bits.div_ceil(hash_len_bits);
        let mut md = MessageDigest::init(self.md_alg);

        let mut derived_key_material = Vec::with_capacity(reps * hash_len_bytes);
        for i in 0..reps {
            md.update(((i + 1) as u32).to_be_bytes());
            md.update(shared_secret);
            md.update(algorithm_id);
            md.update(party_u_info);
            md.update(party_v_info);
            md.update(supp_pub_info);
            let digest = md.finish();
            derived_key_material.extend_from_slice(&digest);
        }

        let key_data_len_bytes = key_data_len_bits / 8;
        if derived_key_material.len() > key_data_len_bytes {
            derived_key_material.truncate(key_data_len_bytes);
        }
        derived_key_material
    }

    fn prepend_len(src: impl AsRef<[u8]>) -> Box<[u8]> {
        let src = src.as_ref();
        if src.is_empty() {
            return Box::new([0, 0, 0, 0]);
        }
        let src_len = src.len();
        let mut out = mem::new_boxed_slice(src_len + 4);
        let len_bytes = (src_len as u32).to_be_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), out.as_mut_ptr(), len_bytes.len());
            std::ptr::copy_nonoverlapping(src.as_ptr(), out.as_mut_ptr().add(4), src_len);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::base64;

    use super::*;

    #[test]
    fn test_prepend_len() {
        let src: [u8; 5] = [65, 108, 105, 99, 101];
        let expected: [u8; 9] = [0, 0, 0, 5, 65, 108, 105, 99, 101];
        let res = ConcatKDF::prepend_len(src);
        assert_eq!(*res, expected);
    }

    // test values produced from implementation found at http://stackoverflow.com/questions/10879658
    #[test]
    fn test_concat_kdf1() {
        let expected_derived_key_b64 = "pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA";
        let shared_secret =
            base64::url_decode("Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0").unwrap();
        let key_data_len_bits = 512;
        let algorithm_id = "A256CBC-HS512";

        let kdf = ConcatKDF::init(DigestAlgorithm::Sha256);
        let derived_key = kdf.kdf(&shared_secret, key_data_len_bits, algorithm_id, [], []);

        assert_eq!(
            *base64::url_decode(expected_derived_key_b64).unwrap(),
            *derived_key
        );
    }

    #[test]
    fn test_concat_kdf2() {
        let expected_derived_key_b64 = "yRbmmZJpxv3H1aq3FgzESa453frljIaeMz6pt5rQZ4Q5Hs-4RYoFRXFh_qBsbTjlsj8JxIYTWj-cp5LKtgi1fBRsf_5yTEcLDv4pKH2fNxjbEOKuVVDWA1_Qv2IkEC0_QSi3lSSELcJaNX-hDG8occ7oQv-w8lg6lLJjg58kOes";
        let shared_secret =
            base64::url_decode("KSDnQpf2iurUsAbcuI4YH-FKfk2gecN6cWHTYlBzrd8").unwrap();
        let key_data_len_bits = 1024;
        let algorithm_id = "meh";
        let party_u_info = "Alice";
        let party_v_info = "Bob";

        let kdf = ConcatKDF::init(DigestAlgorithm::Sha256);
        let derived_key = kdf.kdf(
            &shared_secret,
            key_data_len_bits,
            algorithm_id,
            party_u_info,
            party_v_info,
        );

        assert_eq!(
            *base64::url_decode(expected_derived_key_b64).unwrap(),
            *derived_key
        );
    }
}
