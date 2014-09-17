//! [Poly1305](http://cr.yp.to/mac.html) one-time authenticator
use std::io::{IoResult, IoError, OtherIoError};
use std::iter;
use std::slice;

use common::sbuf::{Allocator, DefaultAllocator, SBuf};

use hash::{Hash, Authenticator};


pub static KEY_SIZE: uint = 32;
pub static TAG_SIZE: uint = 16;

static trail: [u8, ..17] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];


fn add<A: Allocator>(s: &mut SBuf<A, u32>, c: &[u8]) {
    assert!(s.len() == 17 && c.len() <= 17);
    let mut u: u32 = 0;

    for (its, itc) in s.iter_mut().zip(c.iter().chain(trail.iter())) {
        u += *its + *itc as u32;
        *its = u & 0xff;
        u >>= 8;
    }
}

fn squeeze<A: Allocator>(s: &mut SBuf<A, u32>) {
    assert!(s.len() == 17);
    let mut u: u32 = 0;

    for i in range(0u, 16) {
        u += (*s)[i];
        s[i] = u & 0xff;
        u >>= 8;
    }
    u += (*s)[16];
    s[16] = u & 3;
    u = 5 * (u >> 2);
    for i in range(0u, 16) {
        u += (*s)[i];
        s[i] = u & 0xff;
        u >>= 8;
    }
    u += (*s)[16];
    s[16] = u;
}

static minusp: [u8, ..17] = [
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];

#[allow(unsigned_negate)]
fn freeze<A: Allocator>(s: &mut SBuf<A, u32>) {
    assert!(s.len() == 17);
    let sorig = s.clone();
    let mut negative: u32;

    add(s, minusp);
    negative = -((*s)[16] >> 7);
    for i in range(0u, 17) {
        s[i] ^= negative & (sorig[i] ^ (*s)[i]);
    }
}

fn mulmod<A: Allocator>(s: &mut SBuf<A, u32>, r: &[u8]) {
    assert!(s.len() == 17 && r.len() == 17);
    let mut sr: SBuf<A, u32> = SBuf::new_zero(17);
    let mut u: u32;

    for i in range(0u, 17) {
        u = 0;
        for j in iter::range_inclusive(0u, i) {
            u += (*s)[j] * r[i - j] as u32;
        }
        for j in range(i + 1, 17) {
            u += 320 * (*s)[j] * r[i + 17 - j] as u32;
        }
        sr[i] = u;
    }

    for i in range(0u, 17) {
        s[i] = sr[i];
    }

    squeeze(s);
}

fn write_block<A: Allocator>(state: &mut SBuf<A, u32>,
                             block: &[u8], key: &[u8]) {
    assert!(block.len() <= 16);

    add(state, block);
    mulmod(state, key);
}


/// Poly1305 one-time authenticator
pub struct Poly1305<A = DefaultAllocator> {
    key: SBuf<A, u8>,
    state: SBuf<A, u32>,
    partial: SBuf<A, u8>,
    pos: uint,  // Current pos in partial
    done: bool
}

impl<A: Allocator> Poly1305<A> {
    pub fn new(key: &SBuf<A, u8>) -> Result<Poly1305<A>, ()> {
        if key.len() != KEY_SIZE {
            return Err(());
        }

        let mut dkey: SBuf<A, u8> = SBuf::new_zero(33);
        dkey[0] = key[0];
        dkey[1] = key[1];
        dkey[2] = key[2];
        dkey[3] = key[3] & 15;
        dkey[4] = key[4] & 252;
        dkey[5] = key[5];
        dkey[6] = key[6];
        dkey[7] = key[7] & 15;
        dkey[8] = key[8] & 252;
        dkey[9] = key[9];
        dkey[10] = key[10];
        dkey[11] = key[11] & 15;
        dkey[12] = key[12] & 252;
        dkey[13] = key[13];
        dkey[14] = key[14];
        dkey[15] = key[15] & 15;

        slice::bytes::copy_memory(dkey.slice_from_mut(17), key.slice_from(16));

        Ok(Poly1305 {
            key: dkey,
            state: SBuf::<A, u32>::new_zero(17),
            partial: SBuf::<A, u8>::new_zero(16),
            pos: 0,
            done: false
        })
    }

    /// Write the authenticator value to `output`which must be of size
    /// `TAG_SIZE`. Return `TAG_SIZE`.
    pub fn tag(&mut self, output: &mut [u8]) -> IoResult<uint> {
        if output.len() < TAG_SIZE || self.done {
            let desc = if self.done {
                "Tag already returned."
            } else {
                "Tag destination size too short."
            };
            return Err(IoError {
                kind: OtherIoError,
                desc: desc,
                detail: None
            });
        }

        if self.pos > 0 {
            write_block(&mut self.state, self.partial.slice_to(self.pos),
                        self.key.slice_to(17));
        }

        freeze(&mut self.state);
        add(&mut self.state, self.key.slice_from(17));
        for i in range(0u, TAG_SIZE) {
            *output.get_mut(i).unwrap() = self.state[i] as u8;
        }

        self.done = true;
        Ok(TAG_SIZE)
    }

    // FIXME: find better name.
    /// Convenience method returning the authenticator value in a `SBuf`
    /// buffer.
    pub fn tag_to_sbuf(&mut self) -> IoResult<SBuf<A, u8>> {
        let mut s: SBuf<A, u8> = SBuf::new_zero(TAG_SIZE);
        try!(self.tag(s.as_mut_slice()));
        Ok(s)
    }
}

/// Authenticate data.
impl<A: Allocator> Writer for Poly1305<A> {
    fn write(&mut self, buf: &[u8]) -> IoResult<()> {
        if self.done {
            return Err(IoError {
                kind: OtherIoError,
                desc: "Invalid state, mac-ing already completed.",
                detail: None
            });
        }

        assert!(self.pos < 16);

        let n = 16 - self.pos;
        let in_len = buf.len();
        let mut in_pos: uint = 0;

        // Complete existing partial chunk.
        if self.pos > 0 && in_len >= n {
            slice::bytes::copy_memory(self.partial.slice_from_mut(self.pos),
                                      buf.slice_to(n));
            write_block(&mut self.state, self.partial.as_slice(),
                        self.key.slice_to(17));
            self.pos = 0;
            in_pos += n;
        }

        // Process full chunks.
        while in_pos + 16 <= in_len {
            write_block(&mut self.state, buf.slice(in_pos, in_pos + 16),
                        self.key.slice_to(17));
            in_pos += 16;
        }

        // Store partial remaining chunk.
        if in_pos != in_len {
            slice::bytes::copy_memory(self.partial.slice_from_mut(self.pos),
                                      buf.slice_from(in_pos));
            self.pos += in_len - in_pos;
        }

        Ok(())
    }
}

impl<A: Allocator> Clone for Poly1305<A> {
    fn clone(&self) -> Poly1305<A> {
        Poly1305 {
            key: self.key.clone(),
            state: self.state.clone(),
            partial: self.partial.clone(),
            pos: self.pos,
            done: self.done
        }
    }
}


/// Poly1305 Authenticator
///
/// Allocator `A` is used for all internal allocations.
pub struct Poly1305Authenticator<A = DefaultAllocator>;

impl<A: Allocator> Poly1305Authenticator<A> {
}

impl<A: Allocator> Authenticator<Poly1305<A>> for Poly1305Authenticator<A> {
    fn authenticate<T: Hash<Poly1305<A>>>(&self, key: &[u8], value: &T,
                                          output: &mut [u8]) -> IoResult<uint> {
        let skey: SBuf<A, u8> = SBuf::from_slice(key);
        let mut poly: Poly1305<A> = match Poly1305::new(&skey) {
            Ok(p) => p,
            Err(()) => {
                return Err(IoError {
                    kind: OtherIoError,
                    desc: "Instanciation failed",
                    detail: None
                });
            }
        };
        try!(value.hash(&mut poly));
        poly.tag(output)
    }
}


/// All-in-one Poly1305 one-time mac function
///
/// Authenticate `input` using key `key` and put the result in `output`
/// which is expected to be of size `TAG_SIZE`.
pub fn authenticate<A: Allocator = DefaultAllocator>(key: &SBuf<A, u8>,
                                                     input: &[u8],
                                                     output: &mut [u8])
                                                     -> Result<uint, ()> {
    let mut poly: Poly1305<A> = try!(Poly1305::new(key));
    try_ok_unit!(poly.write(input));
    Ok(try_ok_unit!(poly.tag(output)))
}


#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;
    use std::iter;
    use std::rand::{task_rng, Rng};
    use test::Bencher;

    use common::sbuf::{DefaultAllocator, SBuf};

    use poly1305::{Poly1305, KEY_SIZE, TAG_SIZE};


    #[test]
    fn test_ref() {
        let vectors = [
            // Key
            "c8afaac331ee372cd6082de134943b174710130e9f6fea8d72293850a667d86c",
            // Input
            "",
            // Tag
            "4710130e9f6fea8d72293850a667d86c",

            "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
            "48656c6c6f20776f726c6421",
            "a6f745008f81c916a20dcc74eef2b2f0",

            "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "49ec78090e481ec6c26b33b91ccc0307",

            "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff",
            "50515253c0c1c2c3c4c5c6c70c00000000000000d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61167200000000000000",
            "18fb11a5031ad13a7e3b03d46ee3a6a7",

            "746869732069732033322d62797465206b657920666f7220506f6c7931333035",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "da84bcab02676c38cdb015604274c2aa",
            ];

        for i in iter::range_step(0, vectors.len(), 3) {
            let key: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i].from_hex().unwrap().as_slice());
            assert!(key.len() == KEY_SIZE);

            let v1 = vectors[i + 1].from_hex().unwrap();
            let input = v1.as_slice();

            let v2 = vectors[i + 2].from_hex().unwrap();
            let tag1 = v2.as_slice();
            assert!(tag1.len() == TAG_SIZE);
            let mut tag2: Vec<u8> = Vec::from_elem(TAG_SIZE, 0);

            let mut p: Poly1305<DefaultAllocator> =
                Poly1305::new(&key).unwrap();
            assert!(p.write(input).is_ok());

            assert!(p.tag(tag2.as_mut_slice()).ok().unwrap() == TAG_SIZE);
            assert!(tag1 == tag2.as_slice());
        }
    }

    #[test]
    fn test_write_chunks() {
        let size = 8192u;

        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input.as_mut_slice());

        // One chunk
        let mut poly1: Poly1305<DefaultAllocator> =
            Poly1305::new(&key).unwrap();
        let mut out1: Vec<u8> = Vec::from_elem(TAG_SIZE, 0);
        assert!(poly1.write(input.as_slice()).is_ok());
        let ret1 = poly1.tag(out1.as_mut_slice());
        assert!(ret1.ok().unwrap() == out1.len());

        // Multiple chunks
        let mut old_pos = 0u;
        let mut pos = 0u;
        let mut poly2: Poly1305<DefaultAllocator> =
            Poly1305::new(&key).unwrap();
        while pos < size {
            pos = task_rng().gen_range(pos, size + 1);
            assert!(poly2.write(input.slice(old_pos, pos)).is_ok());
            old_pos = pos;
        }
        let mut out2: Vec<u8> = Vec::from_elem(TAG_SIZE, 0);
        let ret2 = poly2.tag(out2.as_mut_slice());
        assert!(ret2.ok().unwrap() == out2.len());

        // Compare tags
        assert!(out1 == out2);
    }

    #[bench]
    #[allow(unused_must_use)]
    fn bench_poly1305(b: &mut Bencher) {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input.as_mut_slice());
        let mut tag: Vec<u8> = Vec::from_elem(TAG_SIZE, 0);

        b.iter(|| {
            let mut poly = Poly1305::new(&key).unwrap();
            poly.write(input.as_slice());
            poly.tag(tag.as_mut_slice());
        })
    }
}
