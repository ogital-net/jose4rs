#[cfg(feature = "aws-lc")]
use aws_lc_sys::{ED25519_keypair, X25519_keypair};

#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{ED25519_keypair, X25519_keypair};

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
