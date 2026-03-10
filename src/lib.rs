use std::{ops::Range, slice::SliceIndex};

mod base64;
mod crypto;
pub mod error;
pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod jwx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BufferRef {
    start_idx: usize,
    end_idx: usize,
}

impl BufferRef {
    pub fn new(start_idx: usize, end_idx: usize) -> Self {
        BufferRef { start_idx, end_idx }
    }

    pub fn is_empty(&self) -> bool {
        self.end_idx == 0 || self.end_idx - self.start_idx == 0
    }

    pub fn len(&self) -> usize {
        self.end_idx - self.start_idx
    }

    pub fn as_range(&self) -> Range<usize> {
        self.start_idx..self.end_idx
    }

    pub fn get<'a>(&self, s: &'a [u8]) -> &'a [u8] {
        unsafe { s.get_unchecked(self.start_idx..self.end_idx) }
    }

    pub fn get_mut<'a>(&self, s: &'a mut [u8]) -> &'a mut [u8] {
        unsafe { s.get_unchecked_mut(self.start_idx..self.end_idx) }
    }
}
