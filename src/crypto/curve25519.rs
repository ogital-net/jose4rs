#[cfg(feature = "aws-lc")]
use aws_lc_sys::{ED25519_keypair, ED25519_keypair_from_seed, X25519_keypair};

#[cfg(feature = "boring")]
use boring_sys::{ED25519_keypair, ED25519_keypair_from_seed, X25519_keypair};

pub(crate) fn x25519_keypair(out_public_value: &mut [u8; 32], out_private_key: &mut [u8; 32]) {
    unsafe {
        X25519_keypair(out_public_value.as_mut_ptr(), out_private_key.as_mut_ptr());
    }
}

pub(crate) fn ed25519_keypair(out_public_key: &mut [u8; 32], out_private_key: &mut [u8; 64]) {
    unsafe {
        ED25519_keypair(out_public_key.as_mut_ptr(), out_private_key.as_mut_ptr());
    }
}

pub(crate) fn ed25519_keypair_from_seed(
    out_public_key: &mut [u8; 32],
    out_private_key: &mut [u8; 64],
    seed: &[u8; 32],
) {
    unsafe {
        ED25519_keypair_from_seed(
            out_public_key.as_mut_ptr(),
            out_private_key.as_mut_ptr(),
            seed.as_ptr(),
        );
    }
}

pub(crate) fn ed25519_pubkey_is_valid_for_private_key(
    private_key: &[u8],
    public_key: &[u8],
) -> bool {
    if public_key.len() != 32 {
        return false;
    }

    let tmp = private_key[0..32].try_into();
    let seed: &[u8; 32] = match &tmp {
        Ok(seed) => seed,
        Err(_) => return false,
    };

    let mut out_pub = [0u8; 32];
    let mut out_private = [0u8; 64];
    ed25519_keypair_from_seed(&mut out_pub, &mut out_private, seed);
    public_key == out_pub
}

#[cfg(test)]
mod tests {
    use crate::{base64, crypto::rand};

    use super::*;

    #[test]
    fn test_ed25519_pubkey_is_valid_for_private_key() {
        let private_key =
            base64::url_decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
        let public_key = base64::url_decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
        assert!(ed25519_pubkey_is_valid_for_private_key(
            &private_key,
            &public_key
        ));

        let private_key =
            base64::url_decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
        let public_key = rand::rand_bytes(32);
        assert!(!ed25519_pubkey_is_valid_for_private_key(
            &private_key,
            &public_key
        ));
    }
}
