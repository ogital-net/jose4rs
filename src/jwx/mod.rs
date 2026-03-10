use crate::{error::JoseError, jwa::AlgorithmConstraints, jwk::JsonWebKey};

mod header_param;

pub use header_param::HeaderParameter;

pub trait JsonWebStructure<'a, A> {
    fn set_compact_serialization(
        &mut self,
        compact_serialization: &'a (impl AsRef<[u8]> + ?Sized),
    ) -> Result<(), JoseError>;

    fn get_compact_serialization(&self) -> Result<String, JoseError>;

    fn set_payload(&mut self, payload: impl AsRef<[u8]>);

    fn get_payload(&mut self) -> Result<&[u8], JoseError>;

    fn set_header(&mut self, param: HeaderParameter, value: impl Into<String>) {
        self.set_header_name(param.name(), value);
    }

    fn get_header(&self, param: HeaderParameter) -> Option<&str> {
        self.get_header_name(param.name())
    }

    fn set_header_name(&mut self, name: impl Into<String>, value: impl Into<String>);

    fn get_header_name(&self, name: impl AsRef<str>) -> Option<&str>;

    fn set_algorithm_header_value(&mut self, alg: impl Into<String>) {
        self.set_header(HeaderParameter::Algorithm, alg);
    }

    fn get_algorithm_header_value(&self) -> Option<&str> {
        self.get_header(HeaderParameter::Algorithm)
    }

    fn set_content_type_header_value(&mut self, cty: impl Into<String>) {
        self.set_header(HeaderParameter::ContentType, cty);
    }

    fn get_content_type_header_value(&self) -> Option<&str> {
        self.get_header(HeaderParameter::ContentType)
    }

    fn set_key_id_header_value(&mut self, kid: impl Into<String>) {
        self.set_header(HeaderParameter::KeyId, kid);
    }

    fn get_key_id_header_value(&self) -> Option<&str> {
        self.get_header(HeaderParameter::KeyId)
    }

    fn set_key(&mut self, key: &'a JsonWebKey);

    fn get_key(&mut self) -> Option<&'a JsonWebKey>;

    fn set_algorithm_constraints(&mut self, algorithm_constraints: &'a AlgorithmConstraints<A>);
}

pub struct Header {}

pub(crate) struct Memchr<'h> {
    haystack: &'h [u8],
    needle: u8,
    remaining: usize,
}

impl<'h> Memchr<'h> {
    pub(crate) fn new(needle: u8, haystack: &'h [u8]) -> Self {
        Self {
            haystack,
            needle,
            remaining: haystack.len(),
        }
    }
}

impl Iterator for Memchr<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            if self.remaining == 0 {
                return None;
            }
            let start_ptr = self
                .haystack
                .as_ptr()
                .add(self.haystack.len() - self.remaining);
            let end_ptr = memchr(start_ptr, self.needle.into(), self.remaining);
            if end_ptr.is_null() {
                None
            } else {
                let idx = end_ptr.offset_from(self.haystack.as_ptr()) as usize;
                self.remaining = self.haystack.len() - (idx + 1);
                Some(idx)
            }
        }
    }

    fn count(self) -> usize {
        self.size_hint().0
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        unsafe {
            let mut remaining = self.remaining;
            let mut start_ptr = self.haystack.as_ptr();
            let mut end_ptr;
            let mut count = 0;

            while remaining > 0 {
                end_ptr = memchr(start_ptr, self.needle.into(), remaining);
                if end_ptr.is_null() {
                    break;
                }
                count += 1;
                remaining -= end_ptr.offset_from(start_ptr) as usize + 1;
                start_ptr = end_ptr.add(1);
            }
            (count, Some(count))
        }
    }
}

unsafe extern "C" {
    unsafe fn memchr(s: *const u8, c: core::ffi::c_int, n: usize) -> *mut u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memchr_iterator() {
        for (cs, expected) in [
            ("01", 0),
            (".", 1),
            ("01.23.45", 2),
            ("01.23.45.", 3),
            ("01.23.45.67.89", 4),
            (".01.23.45.67.89.", 6),
        ] {
            assert_eq!(Memchr::new(b'.', cs.as_bytes()).size_hint().0, expected);
        }

        let cs = ".01.23.45.67.89.";

        let indicies: Vec<usize> = Memchr::new(b'.', cs.as_bytes()).collect();
        assert_eq!(indicies.len(), 6);
        for (idx, expected) in [0, 3, 6, 9, 12, 15].iter().enumerate() {
            assert_eq!(indicies[idx], *expected);
        }
    }
}
