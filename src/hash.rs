//! Hash traits
use std::c_str::CString;
use std::io::{IoResult, Writer};

use common::sbuf::{Allocator, SBuf};
use curve41417::bytes::{Bytes, B416, B512, B832, Scalar, MontPoint, EdPoint};


/// Trait for hashable types
pub trait Hash<S> {
    fn hash(&self, state: &mut S) -> IoResult<()>;
}

impl<'a, S: Writer> Hash<S> for &'a [u8] {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        state.write(*self)
    }
}

impl<S: Writer> Hash<S> for String {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        state.write(self.as_bytes())
    }
}

impl<'a, S: Writer> Hash<S> for &'a str {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        state.write(self.as_bytes())
    }
}

impl<S: Writer> Hash<S> for Vec<u8> {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        state.write(self.as_slice())
    }
}

impl<S: Writer> Hash<S> for CString {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        state.write(self.as_bytes_no_nul())
    }
}

impl<A: Allocator, S, T: Hash<S>> Hash<S> for SBuf<A, T> {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        for it in self.iter() {
            try!(it.hash(state));
        }
        Ok(())
    }
}

macro_rules! bytes_hash(($name:ident) => (
impl<A: Allocator, S: Writer> Hash<S> for $name<A> {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        self.as_bytes().hash(state)
    }
}
))

bytes_hash!(B416)
bytes_hash!(B512)
bytes_hash!(B832)

macro_rules! bytes_wrapper_hash(($name:ident) => (
impl<A: Allocator, S: Writer> Hash<S> for $name<A> {
    fn hash(&self, state: &mut S) -> IoResult<()> {
        self.get().hash(state)
    }
}
))

bytes_wrapper_hash!(Scalar)
bytes_wrapper_hash!(MontPoint)
bytes_wrapper_hash!(EdPoint)


/// Hasher
pub trait Hasher<S> {
    /// Hash `input` and put the result in `output`. Return the number of bytes
    /// written to `output`.
    fn hash<T: Hash<S>>(&self, value: &T, output: &mut [u8]) -> IoResult<uint>;
}


/// Authenticator
pub trait Authenticator<S> {
    /// Authenticate `input` with `key` and put the result in `output`.
    /// Return the number of bytes written to `output`.
    fn authenticate<T: Hash<S>>(&self, key: &[u8], value: &T,
                                output: &mut [u8]) -> IoResult<uint>;
}
