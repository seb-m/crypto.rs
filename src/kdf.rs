//! Key Derivation Function

use std::io::{Reader, IoResult, IoError, EndOfFile};
use std::num::Int;
use std::slice;
use std::u32;

use common::sbuf::{Allocator, SBuf};
use common::utils;

use hash::Hash;
use sha3::{Sha3, Sha3Mode};


fn key_pack<A: Allocator>(key: &[u8], l: uint) -> Result<SBuf<A, u8>, ()> {
    if key.len() > 253 || l % 8 != 0 ||
        l < ((key.len() + 2) << 3) || l > (255 << 3) {
        return Err(());
    }

    let mut kp: SBuf<A, u8> = SBuf::new_zero(l / 8);
    kp[0] = (l / 8) as u8;
    slice::bytes::copy_memory(kp[mut 1..], key);
    kp[key.len() + 1] = 0x01;
    Ok(kp)
}


/// [XKdf](http://csrc.nist.gov/groups/ST/hash/sha-3/Aug2014/documents/perlner_kmac.pdf)
/// key derivation function based on SHA3-SHAKE and
/// [NIST-SP800-108](http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf)
pub struct XKdf<A> {
    shake: Sha3<A>,
    size: uint,
    pos: uint
}

impl<A: Allocator> XKdf<A> {
    /// `mode` is the SHAKE mode, `key` a key used as input, `label` identifies
    /// the purpose for the derived keying material, `context` contains
    /// information related to the derived keying material and `size` specifies
    /// the length in bytes of the derived keying material.
    pub fn new(mode: Sha3Mode, key: &[u8], label: &[u8], context: Option<&[u8]>,
           size: uint) -> Result<XKdf<A>, ()> {
        if !Sha3Mode::is_shake(mode) {
            return Err(());
        }

        if key.len() > 253 {
            return Err(());
        }

        // XMac
        let mut shake = Sha3::<A>::new(mode);

        // Key pack
        let l = (key.len() + 2) << 3;
        try_ok_unit!(try!(key_pack::<A>(key, l))[].hash(&mut shake));

        // Label || 0x00 || Context || size
        try_ok_unit!(label.hash(&mut shake));
        try_ok_unit!([0u8].hash(&mut shake));
        if context.is_some() {
            try_ok_unit!(context.unwrap().hash(&mut shake));
        }
        let size_bits = try_some_err!(size.checked_mul(8));
        let mut size_bytes = SBuf::<A, u8>::new_zero(u32::BYTES);
        utils::u32to8_le(size_bytes[mut],
                         &(try_some_err!(size_bits.to_u32())));
        try_ok_unit!(size_bytes[].hash(&mut shake));

        Ok(XKdf {
            shake: shake,
            size: size,
            pos: 0
        })
    }

    /// Read and discard the next `n` key derived bytes. Return the
    /// number of bytes discarded.
    pub fn skip(&mut self, n: uint) -> IoResult<uint> {
        let mut s: SBuf<A, u8> = SBuf::new_zero(n);
        self.read(s[mut])
    }

    /// Return the derived key all-in-one read.
    pub fn derived_key(&mut self) -> Result<SBuf<A, u8>, IoError> {
        let mut dk = SBuf::<A, u8>::new_zero(self.size - self.pos);
        try!(self.read(dk[mut]));
        Ok(dk)
    }
}

impl<A: Allocator> Reader for XKdf<A> {
    /// Read key derived bytes to `buf` and return the number of bytes
    /// read.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        if self.pos >= self.size {
            return Err(IoError {
                kind: EndOfFile,
                desc: "No key derived bytes left to consumme.",
                detail: None
            });
        }

        let mut nread = try!(self.shake.read(buf));
        let left = self.size - self.pos;
        if nread > left {
            utils::zero_memory(buf[mut left..]);
            nread = left;
        }

        self.pos += nread;
        Ok(nread)
    }
}

impl<A: Allocator> Clone for XKdf<A> {
    fn clone(&self) -> XKdf<A> {
        XKdf {
            shake: self.shake.clone(),
            size: self.size,
            pos: self.pos
        }
    }
}
