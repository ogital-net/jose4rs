use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "aws-lc")]
use aws_lc_sys::{CRYPTO_memcmp, OPENSSL_cleanse};
#[cfg(all(feature = "boring", not(feature = "aws-lc")))]
use boring_sys::{CRYPTO_memcmp, OPENSSL_cleanse};

pub(crate) fn crypto_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

pub(crate) fn cleanse(data: &mut [u8]) {
    unsafe {
        OPENSSL_cleanse(data.as_mut_ptr().cast(), data.len());
    }
}

#[derive(Clone)]
pub(crate) struct Zeroizing<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn as_inner_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> AsRef<[u8]> for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> Deref for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<T> DerefMut for Zeroizing<T>
where
    T: AsMut<[u8]> + AsRef<[u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        cleanse(self.0.as_mut());
    }
}

pub(crate) struct ZeroizingUninit<T: AsMut<[MaybeUninit<u8>]>>(T);

impl<T: AsMut<[MaybeUninit<u8>]>> ZeroizingUninit<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        self.0.as_mut()
    }
}

impl ZeroizingUninit<Box<[MaybeUninit<u8>]>> {
    /// # Safety
    /// Every byte in the boxed slice must be initialized.
    pub(crate) unsafe fn assume_init(mut self) -> Zeroizing<Box<[u8]>> {
        let bytes = std::mem::take(&mut self.0);
        Zeroizing::new(unsafe { bytes.assume_init() })
    }
}

impl<T: AsMut<[MaybeUninit<u8>]>> Drop for ZeroizingUninit<T> {
    fn drop(&mut self) {
        let bytes = self.as_mut_slice();
        if !bytes.is_empty() {
            unsafe { OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
        }
    }
}

pub(crate) struct ZeroizingVec(Vec<u8>);

// No `DerefMut` to `Vec`: growing through `Vec` would free the old allocation
// without cleansing it. All growth goes through `reserve`.
impl ZeroizingVec {
    pub(crate) fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Ensures room for `additional` bytes, cleansing the old allocation if
    /// the buffer has to move.
    pub(crate) fn reserve(&mut self, additional: usize) {
        if self.0.capacity() - self.0.len() >= additional {
            return;
        }
        let required = self
            .0
            .len()
            .checked_add(additional)
            .expect("capacity overflow");
        let mut grown = Vec::with_capacity(required.max(self.0.capacity() * 2));
        grown.extend_from_slice(&self.0);
        drop(Self(std::mem::replace(&mut self.0, grown)));
    }

    pub(crate) fn extend_from_slice(&mut self, data: &[u8]) {
        self.reserve(data.len());
        self.0.extend_from_slice(data);
    }

    pub(crate) fn extend_from_within(&mut self, range: std::ops::Range<usize>) {
        self.reserve(range.len());
        self.0.extend_from_within(range);
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    /// Runs `append` on the inner `Vec` after reserving `max_additional`
    /// bytes; `append` must not write more than that.
    pub(crate) fn append_with<R>(
        &mut self,
        max_additional: usize,
        append: impl FnOnce(&mut Vec<u8>) -> R,
    ) -> R {
        self.reserve(max_additional);
        let capacity = self.0.capacity();
        let result = append(&mut self.0);
        debug_assert_eq!(capacity, self.0.capacity(), "ZeroizingVec reallocated");
        result
    }
}

impl Deref for ZeroizingVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        // SAFETY: `as_mut_ptr()` addresses an allocation of `capacity()` bytes.
        // OPENSSL_cleanse writes each byte without requiring it to be initialized.
        unsafe {
            OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.capacity());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroizing_cleanses_on_drop() {
        let mut bytes = [0x5a; 32];
        {
            let _secret = Zeroizing::new(bytes.as_mut_slice());
        }
        assert_eq!(bytes, [0; 32]);
    }

    #[test]
    fn zeroizing_uninit_cleanses_on_drop() {
        let mut bytes = [MaybeUninit::uninit(); 3];
        {
            let mut secret = ZeroizingUninit::new(bytes.as_mut_slice());
            secret.as_mut_slice()[0].write(0x5a);
            secret.as_mut_slice()[2].write(0xa5);
        }
        assert_eq!(unsafe { bytes[0].assume_init() }, 0);
        assert_eq!(unsafe { bytes[2].assume_init() }, 0);
    }

    #[test]
    fn zeroizing_uninit_transfers_box() {
        let mut secret = ZeroizingUninit::new(Box::<[u8]>::new_uninit_slice(2));
        let bytes = secret.as_mut_slice();
        bytes[0].write(0x5a);
        bytes[1].write(0xa5);
        let original_ptr = bytes.as_ptr().cast::<u8>();
        let initialized = unsafe { secret.assume_init() };
        assert_eq!(initialized.as_ptr(), original_ptr);
        assert_eq!(*initialized, [0x5a, 0xa5]);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn zeroizing_vec_growth_preserves_contents() {
        let mut buffer = ZeroizingVec::new(Vec::new());
        for chunk in 0u8..64 {
            buffer.extend_from_slice(&[chunk; 7]);
        }
        buffer.extend_from_within(0..7);
        buffer.truncate(64 * 7 + 3);
        assert_eq!(buffer.len(), 64 * 7 + 3);
        assert!(
            buffer
                .chunks(7)
                .enumerate()
                .all(|(i, c)| c.iter().all(|&b| b == (i % 64) as u8))
        );
    }
}
