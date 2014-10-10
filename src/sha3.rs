//! SHA-3 hash as specified in the
//! [FIPS 202 draft](http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf)
use std::cmp;
use std::io::{Reader, Writer, IoResult, IoError, EndOfFile, OtherIoError};
use std::iter;

use common::sbuf::{Allocator, DefaultAllocator, SBuf};
use common::utils;

use hash::{Hash, Hasher};


const B: uint = 200;
const NROUNDS: uint = 24;
const RC: [u64, ..24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008
];
const ROTC: [uint, ..24] = [
    1, 3, 6, 10, 15, 21, 28, 36,
    45, 55, 2, 14, 27, 41, 56, 8,
    25, 43, 62, 18, 39, 61, 20, 44
];
const PIL: [uint, ..24] = [
    10, 7, 11, 17, 18, 3, 5, 16,
    8, 21, 24, 4, 15, 23, 19, 13,
    12, 2, 20, 14, 22, 9, 6, 1
];
const M5: [uint, ..10] = [
    0, 1, 2, 3, 4, 0, 1, 2, 3, 4
];


macro_rules! rotl64(($v:expr, $n:expr) => (
    (($v as u64 << ($n % 64)) as u64 & 0xffffffffffffffff) ^
        ($v as u64 >> (64 - ($n % 64)))
))

// Code based on Keccak-compact64.c from ref implementation.
fn keccak_f<A: Allocator>(state: &mut SBuf<A, u8>) {
    assert!(state.len() == B);

    let mut s: SBuf<A, u64> = SBuf::new_zero(25);
    let mut t: SBuf<A, u64> = SBuf::new_zero(1);
    let mut c: SBuf<A, u64> = SBuf::new_zero(5);

    for i in iter::range_step(0u, state.len(), 8) {
        utils::u8to64_le(s.get_mut(i / 8), state[mut i..i + 8]);
    }

    for round in range(0u, NROUNDS) {
        // Theta
        for x in range(0u, 5) {
            c[x] = s[x] ^ s[5 + x] ^ s[10 + x] ^ s[15 + x] ^ s[20 + x];
        }
        for x in range(0u, 5) {
            t[0] = c[M5[x + 4]] ^ rotl64!(c[M5[x + 1]], 1);
            for y in iter::range_step(0u, 25, 5) {
                s[y + x] = s[y + x] ^ t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in range(0u, 24) {
            c[0] = s[PIL[x]];
            s[PIL[x]] = rotl64!(t[0], ROTC[x]);
            t[0] = c[0];
        }

        // Chi
        for y in iter::range_step(0u, 25, 5) {
            for x in range(0u, 5) {
                c[x] = s[y + x];
            }
            for x in range(0u, 5) {
                s[y + x] = c[x] ^ (!c[M5[x + 1]] & c[M5[x + 2]]);
            }
        }

        // Iota
        s[0] = s[0] ^ RC[round];
    }

    for i in range(0u, s.len()) {
        utils::u64to8_le(state[mut i * 8..(i + 1) * 8], s.get(i));
    }
}


/// SHA-3 Modes.
#[allow(non_camel_case_types)]
pub enum Sha3Mode {
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256
}

impl Sha3Mode {
    /// Return the expected hash size in bytes specified for `mode`, or 0
    /// for modes with variable output as for shake functions.
    pub fn digest_length(mode: Sha3Mode) -> uint {
        match mode {
            Sha3_224 => 28,
            Sha3_256 => 32,
            Sha3_384 => 48,
            Sha3_512 => 64,
            Shake128 => 0,
            Shake256 => 0
        }
    }

    /// Return `true` if `mode` is a SHAKE mode.
    pub fn is_shake(mode: Sha3Mode) -> bool {
        match mode {
            Shake128|Shake256 => true,
            _ => false
        }
    }

    /// Return the capacity in bytes.
    fn capacity(mode: Sha3Mode) -> uint {
        match mode {
            Sha3_224 => 56,
            Sha3_256 => 64,
            Sha3_384 => 96,
            Sha3_512 => 128,
            Shake128 => 32,
            Shake256 => 64
        }
    }
}


/// SHA-3 State.
///
/// Use the `io::Writer` trait implementation to hash data and the
/// `io::Reader` trait implementation to read the its result either
/// a fixed digest or a variable output depending on the `mode` used.
pub struct Sha3<A> {
    state: SBuf<A, u8>,  // B bytes
    mode: Sha3Mode,
    can_absorb: bool,  // Can absorb
    can_squeeze: bool,  // Can squeeze
    offset: uint  // Enqueued bytes in state for absorb phase
                  // Squeeze offset for squeeze phase
}

impl<A: Allocator> Sha3<A> {
    /// New SHA-3 instanciated from specified SHA-3 `mode`.
    pub fn new(mode: Sha3Mode) -> Sha3<A> {
        Sha3 {
            state: SBuf::new_zero(B),
            mode: mode,
            can_absorb: true,
            can_squeeze: true,
            offset: 0
        }
    }

    /// New SHA3-224 instance.
    pub fn sha3_224() -> Sha3<A> {
        Sha3::new(Sha3_224)
    }

    /// New SHA3-256 instance.
    pub fn sha3_256() -> Sha3<A> {
        Sha3::new(Sha3_256)
    }

    /// New SHA3-384 instance.
    pub fn sha3_384() -> Sha3<A> {
        Sha3::new(Sha3_384)
    }

    /// New SHA3-512 instance.
    pub fn sha3_512() -> Sha3<A> {
        Sha3::new(Sha3_512)
    }

    /// New SHAKE-128 instance.
    pub fn shake_128() -> Sha3<A> {
        Sha3::new(Shake128)
    }

    /// New SHAKE-256 instance.
    pub fn shake_256() -> Sha3<A> {
        Sha3::new(Shake256)
    }

    /// Return the expected hash size in bytes specified for `mode`, or 0
    /// for modes with variable output as for shake functions.
    pub fn digest_length(&self) -> uint {
        Sha3Mode::digest_length(self.mode)
    }

    fn finalize(&mut self) -> IoResult<()> {
        assert!(self.can_absorb);

        fn domain_sep_len(out_len: uint) -> uint {
            if out_len != 0 {
                2
            } else {
                4
            }
        }

        fn set_domain_sep(out_len: uint, buf: &mut [u8]) {
            assert!(buf.len() > 0);
            if out_len != 0 {
                // 01...
                buf[0] &= 0xfe;
                buf[0] |= 0x2;
            } else {
                // 1111...
                buf[0] |= 0xf;
            }
        }

        // All parameters are expected to be in bits.
        fn pad_len(ds_len: uint, offset: uint, rate: uint) -> uint {
            assert!(rate % 8 == 0 && offset % 8 == 0);
            let r: int = rate as int;
            let m: int = (offset + ds_len) as int;
            let zeros = (((-m - 2) + 2 * r) % r) as uint;
            assert!((m as uint + zeros + 2) % 8 == 0);
            (ds_len as uint + zeros + 2) / 8
        }

        fn set_pad(offset: uint, buf: &mut [u8]) {
            assert!(buf.len() as f32 >= ((offset + 2) as f32 / 8.0).ceil());
            let s = offset / 8;
            buf[s] |= 1 << (offset % 8);
            for i in range((offset % 8) + 1, 8) {
                buf[s] &= !(1 << i);
            }
            for i in range(s + 1, buf.len()) {
                buf[i] = 0;
            }
            buf[buf.len() - 1] |= 0x80;
        }

        let ds_len = domain_sep_len(self.digest_length());
        let p_len = pad_len(ds_len, self.offset * 8, self.rate() * 8);

        let mut p: Vec<u8> = Vec::from_elem(p_len, 0);
        set_domain_sep(self.digest_length(), p[mut]);
        set_pad(ds_len, p[mut]);

        try!(self.write(p[]));
        self.can_absorb = false;
        Ok(())
    }

    fn rate(&self) -> uint {
        B - Sha3Mode::capacity(self.mode)
    }

    /// Read and discard the next `n` squeezed bytes. Return the
    /// number of bytes discarded.
    pub fn skip(&mut self, n: uint) -> IoResult<uint> {
        let mut s: SBuf<A, u8> = SBuf::new_zero(n);
        self.read(s[mut])
    }
}

/// Hash data.
impl<A: Allocator> Writer for Sha3<A> {
    fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        if !self.can_absorb {
            return Err(IoError {
                kind: OtherIoError,
                desc: "Invalid state, absorb phase already finalized.",
                detail: None
            });
        }

        let r = self.rate();
        assert!(self.offset < r);

        let in_len = buf.len();
        let mut in_pos: uint = 0;

        // Absorb
        while in_pos < in_len {
            let offset = self.offset;
            let nread = cmp::min(r - offset, in_len - in_pos);
            for i in range(0u, nread) {
                self.state[offset + i] = self.state[offset + i] ^
                    buf[in_pos + i];
            }
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            self.offset = 0;
            keccak_f(&mut self.state);
        }

        Ok(())
    }
}

/// Read digest result.
impl<A: Allocator> Reader for Sha3<A> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        if !self.can_squeeze {
            return Err(IoError {
                kind: EndOfFile,
                desc: "Nothing left to squeeze.",
                detail: None
            });
        }

        if self.can_absorb {
            try!(self.finalize());
        }

        let r = self.rate();
        let out_len = self.digest_length();
        if out_len != 0 {
            assert!(self.offset < out_len);
        } else {
            assert!(self.offset < r);
        }

        let in_len = buf.len();
        let mut in_pos: uint = 0;

        // Squeeze
        while in_pos < in_len {
            let offset = self.offset % r;
            let mut nread = cmp::min(r - offset, in_len - in_pos);
            if out_len != 0 {
                nread = cmp::min(nread, out_len - self.offset);
            }

            for i in range(0u, nread) {
                *buf.get_mut(in_pos + i).unwrap() = self.state[offset + i];
            }
            in_pos += nread;

            if offset + nread != r {
                self.offset += nread;
                break;
            }

            if out_len == 0 {
                self.offset = 0;
            } else {
                self.offset += nread;
            }

            keccak_f(&mut self.state);
        }

        if out_len != 0 && out_len == self.offset {
            self.can_squeeze = false;
        }

        Ok(in_pos)
    }
}

impl<A: Allocator> Clone for Sha3<A> {
    fn clone(&self) -> Sha3<A> {
        Sha3 {
            state: self.state.clone(),
            mode: self.mode,
            can_absorb: self.can_absorb,
            can_squeeze: self.can_squeeze,
            offset: self.offset
        }
    }
}


/// SHA-3 Hasher.
///
/// Allocator `A` is used for all internal allocations.
pub struct Sha3Hasher<A = DefaultAllocator> {
    mode: Sha3Mode
}

impl<A: Allocator> Sha3Hasher<A> {
    /// New `Sha3Hasher` instance initialized from SHA-3 function defined by
    /// `mode`.
    pub fn new(mode: Sha3Mode) -> Sha3Hasher<A> {
        Sha3Hasher {
            mode: mode
        }
    }
}

impl<A: Allocator> Hasher<Sha3<A>> for Sha3Hasher<A> {
    // Call this method with an `output` buffer of the expected size in the
    // case of `Sha3_*` digest functions and with a buffer of the wanted size
    // in the case of `Shake*` functions.
    fn hash<T: Hash<Sha3<A>>>(&self, value: &T, output: &mut [u8])
                              -> IoResult<uint> {
        let mut state = Sha3::new(self.mode);
        try!(value.hash(&mut state));
        state.read(output)
    }
}


/// All-in-one SHA-3 hash function
///
/// Instanciate SHA-3 from `mode` to hash `input` and put the result in
/// `output` which must be a buffer of the appropriate size. Return the
/// number of bytes written to `output`.
pub fn hash<A: Allocator = DefaultAllocator>(mode: Sha3Mode, input: &[u8],
                                             output: &mut [u8])
                                             -> IoResult<uint> {
    let mut state: Sha3<A> = Sha3::new(mode);
    try!(state.write(input));
    state.read(output)
}


#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;
    use std::io::{BufferedReader, File};
    use std::io::fs::PathExtensions;
    use std::os;
    use std::rand::{task_rng, Rng};
    use test::Bencher;

    use common::sbuf::DefaultAllocator;

    use hash::{Hash, Hasher};
    use sha3::{Sha3Mode, Sha3_224, Sha3_256, Sha3_384, Sha3_512,
               Shake128, Shake256, Sha3Hasher, Sha3, hash};


    #[test]
    fn test_ref() {
      let vectors = [(Sha3_224, "sha3_224_test_vectors.txt"),
                     (Sha3_256, "sha3_256_test_vectors.txt"),
                     (Sha3_384, "sha3_384_test_vectors.txt"),
                     (Sha3_512, "sha3_512_test_vectors.txt"),
                     (Shake128, "shake128_test_vectors.txt"),
                     (Shake256, "shake256_test_vectors.txt")];

        let mut count: uint = 0;
        let mut vectors_dir = os::getcwd();
        loop {
            let cargo_file = vectors_dir.join("Cargo.toml");
            if cargo_file.exists() {
                break;
            }

            vectors_dir.pop();
            assert!(vectors_dir != Path::new("/"));
        }
        vectors_dir = vectors_dir.join("src/sha3_vectors");

        for i in vectors.iter() {
            let (mode, filename) = *i;

            let path = vectors_dir.join(filename);
            assert!(path.exists());
            let mut file = BufferedReader::new(File::open(&path));
            let mut lines = file.lines();
            let mut msg: Vec<u8> = Vec::with_capacity(1);

            loop {
                match lines.next() {
                    Some(Ok(ref msg_line))
                        if msg_line[].starts_with("Msg =") => {

                        let msg_hex = msg_line[][6..];
                        msg = msg_hex.from_hex().unwrap();
                    },
                    Some(Ok(ref hash_line))
                        if hash_line[].starts_with("MD =") => {
                        count += 1;

                        let hash_hex = hash_line[][5..];
                        let hasher: Sha3Hasher<DefaultAllocator> =
                            Sha3Hasher::new(mode);
                        let mut out: Vec<u8> =
                            Vec::from_elem(Sha3Mode::digest_length(mode), 0);
                        let r = hasher.hash(&msg, out[mut]);
                        assert!(r.ok().unwrap() == out.len());
                        assert!(hash_hex.from_hex().unwrap() == out);
                    },
                    Some(Ok(ref hash_line))
                        if hash_line[].starts_with("Squeezed =") => {
                        count += 1;

                        let hash_hex = hash_line[][11..];
                        let hasher: Sha3Hasher<DefaultAllocator> =
                            Sha3Hasher::new(mode);
                        let mut out: Vec<u8> =
                            Vec::from_elem(hash_hex.len() / 2, 0);
                        let r = hasher.hash(&msg, out[mut]);
                        assert!(r.ok().unwrap() == out.len());
                        assert!(hash_hex.from_hex().unwrap() == out);
                    },
                    Some(Ok(_)) => continue,
                    _ => break
                }
            }
        }

        assert!(count == 1536);
    }

    #[test]
    fn test_write_chunks() {
        let size = 8192u;
        let mode = Sha3_256;

        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input[mut]);

        // One chunk
        let hasher1: Sha3Hasher<DefaultAllocator> = Sha3Hasher::new(mode);
        let mut out1: Vec<u8> =
            Vec::from_elem(Sha3Mode::digest_length(mode), 0);
        let ret1 = hasher1.hash(&input, out1[mut]);
        assert!(ret1.ok().unwrap() == out1.len());

        // Multiple chunks
        let mut old_pos = 0u;
        let mut pos = 0u;
        let mut state: Sha3<DefaultAllocator> = Sha3::new(mode);
        while pos < size {
            pos = task_rng().gen_range(pos, size + 1);
            assert!(state.write(input[old_pos..pos]).is_ok());
            old_pos = pos;
        }
        let mut out2: Vec<u8> =
            Vec::from_elem(Sha3Mode::digest_length(mode), 0);
        let ret2 = state.read(out2[mut]);
        assert!(ret2.ok().unwrap() == out2.len());

        // Compare digests
        assert!(out1 == out2);
    }

    #[test]
    fn test_read_chunks() {
        let size = 8192u;
        let mode = Shake128;

        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input[mut]);

        // One chunk
        let hasher1: Sha3Hasher<DefaultAllocator> = Sha3Hasher::new(mode);
        let mut out1: Vec<u8> = Vec::from_elem(size, 0);
        let ret1 = hasher1.hash(&input, out1[mut]);
        assert!(ret1.ok().unwrap() == out1.len());

        // Multiple chunks
        let mut old_pos = 0u;
        let mut pos = 0u;
        let mut state: Sha3<DefaultAllocator> = Sha3::new(mode);
        assert!(state.write(input[]).is_ok());
        let mut out2: Vec<u8> = Vec::from_elem(size, 0);
        while pos < size {
            pos = task_rng().gen_range(pos, size + 1);
            assert!(state.read(out2[mut old_pos..pos]).is_ok());
            old_pos = pos;
        }

        // Compare digests
        assert!(out1 == out2);
    }

    #[test]
    fn test_hash() {
        let size = 8192u;
        let mode = Shake128;

        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input[mut]);

        let hasher: Sha3Hasher<DefaultAllocator> = Sha3Hasher::new(mode);
        let mut out1: Vec<u8> = Vec::from_elem(size, 0);
        let mut ret = hasher.hash(&input, out1[mut]);
        assert!(ret.ok().unwrap() == out1.len());

        let mut out2: Vec<u8> = Vec::from_elem(size, 0);
        ret = hash::<DefaultAllocator>(mode, input[], out2[mut]);
        assert!(ret.ok().unwrap() == out2.len());

        assert!(out1 == out2);
    }

    #[bench]
    #[allow(unused_must_use)]
    fn bench_sha3_512(b: &mut Bencher) {
        let size = 8192u;
        let mode = Sha3_512;

        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input[mut]);
        let mut state: Sha3<DefaultAllocator> = Sha3::new(mode);
        let mut out: Vec<u8> =
            Vec::from_elem(Sha3Mode::digest_length(mode), 0);

        b.iter(|| {
            input.hash(&mut state);
            state.read(out[mut]);
        })
    }
}
