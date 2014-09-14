//! [Chacha20](http://cr.yp.to/chacha.html) stream cipher
use std::cmp;
use std::io::{Reader, IoResult, IoError, EndOfFile, InvalidInput};
use std::slice;
use std::{u32, u64};

use common::sbuf::{Allocator, DefaultAllocator, SBuf};
use common::utils;

use encrypt::{Encrypt, Encrypter, CipherEncrypt};
use hash::Hash;
use poly1305;


pub static KEY_SIZE: uint = 32;
pub static NONCE_SIZE: uint = 8;
pub static NONCE_AEAD_SIZE: uint = 12;
pub static BLOCK_SIZE: uint = 64;

static BUFFER_SIZE: uint = BLOCK_SIZE * 16;  // FIXME: maybe too short.
static SIGMA: &'static [u8] = b"expand 32-byte k";


macro_rules! rotl32(($v:expr, $n:expr) => (
    (($v << $n) as u32 & 0xffffffff) | ($v >> (32 - $n))
))

fn quarter_round<A: Allocator>(x: &mut SBuf<A, u32>,
                               a: uint, b: uint, c: uint, d: uint) {
    x[a] = (*x)[a] + (*x)[b];
    x[d] = rotl32!((*x)[d] ^ (*x)[a], 16);
    x[c] = (*x)[c] + (*x)[d];
    x[b] = rotl32!((*x)[b] ^ (*x)[c], 12);
    x[a] = (*x)[a] + (*x)[b];
    x[d] = rotl32!((*x)[d] ^ (*x)[a], 8);
    x[c] = (*x)[c] + (*x)[d];
    x[b] = rotl32!((*x)[b] ^ (*x)[c], 7);
}

// Code based on supercop-20140529 chacha20/e/ref/
fn salsa20_word_to_byte<A: Allocator>(buf: &mut [u8],
                                      input: &SBuf<A, u32>) {
    assert!(input.len() == 16);
    assert!(buf.len() >= BLOCK_SIZE);
    let mut x = input.clone();

    for _ in range(0u, 10) {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    for i in range(0u, x.len()) {
        x[i] = x[i] + input[i];
        utils::u32to8_le(buf.mut_slice(i * 4, (i + 1) * 4), &x[i]);
    }
}


struct ChachaRaw<A = DefaultAllocator> {
    input: SBuf<A, u32>,
    ctr_words: uint,
    eos: bool  // End-of-stream
}

impl<A: Allocator> ChachaRaw<A> {
    fn new(key: &SBuf<A, u8>, nonce: &[u8]) -> Result<ChachaRaw<A>, ()> {
        if key.len() != KEY_SIZE {
            return Err(());
        }
        let nonce_len = nonce.len();
        if (nonce_len != NONCE_SIZE && nonce_len != NONCE_AEAD_SIZE) ||
            (nonce_len % 4 != 0 || nonce_len >= 16) {
            return Err(());
        }

        let mut s = ChachaRaw {
            input: SBuf::<A, u32>::new_zero(16),
            ctr_words: (16 - nonce_len) >> 2,
            eos: false
        };

        // Input setup
        {
            let input = &mut s.input;

            // Constant
            for i in range(0u, 4) {
                utils::u8to32_le(input.get_mut(i),
                                 SIGMA.slice(i * 4, (i + 1) * 4));
            }

            // Key
            for i in range(0u, 8) {
                utils::u8to32_le(input.get_mut(4 + i),
                                 key.slice(i * 4, (i + 1) * 4));
            }

            // IV
            for i in range(0u, s.ctr_words) {
                input[12 + i] = 0;
            }
            for i in range(0u, nonce_len >> 2) {
                utils::u8to32_le(input.get_mut(12 + s.ctr_words + i),
                                 nonce.slice(i * 4, (i + 1) * 4));
            }
        }

        Ok(s)
    }

    fn counter_inc(&mut self) {
        let input = &mut self.input;

        if self.eos {
            return;
        }

        let mut eos = true;
        for i in range(0u, self.ctr_words) {
            if (*input)[12 + i] != u32::MAX {
                eos = false;
                break;
            }
        }
        if eos {
            self.eos = true;
            return;
        }

        input[12] = (*input)[12] + 1;
        for i in range(0u, self.ctr_words - 1) {
            if (*input)[12 + i] == 0 {
                input[12 + i + 1] = (*input)[12 + i + 1] + 1;
            } else {
                break;
            }
        }
    }
}

impl<A: Allocator> Reader for ChachaRaw<A> {
    // Only read multiples of `BLOCK_SIZE` bytes. `0` is returned if the
    // size of `buf` is less than `BLOCK_SIZE`. Don't use it directly,
    // use a `ChachaStream` instead, which bufferize this method.
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let mut len = buf.len();

        if len < BLOCK_SIZE {
            return Ok(0);
        }

        let mut pos: uint = 0;

        while len >= BLOCK_SIZE {
            if self.eos {
                return Err(IoError {
                    kind: EndOfFile,
                    desc: "Counter limit reached for this nonce.",
                    detail: None
                });
            }

            let bufr = buf.mut_slice(pos, pos + BLOCK_SIZE);
            salsa20_word_to_byte(bufr, &self.input);

            len -= BLOCK_SIZE;
            pos += BLOCK_SIZE;

            self.counter_inc();
        }

        Ok(pos)
    }
}

impl<A: Allocator> Clone for ChachaRaw<A> {
    fn clone(&self) -> ChachaRaw<A> {
        ChachaRaw {
            input: self.input.clone(),
            ctr_words: self.ctr_words,
            eos: self.eos
        }
    }
}


/// Chacha20 key stream generator
pub struct ChachaStream<A = DefaultAllocator> {
    inner: ChachaRaw<A>,
    buf: SBuf<A, u8>,  // Buffer of size BUFFER_SIZE
    pos: uint,  // Current pos in buf
    cap: uint,  // Effective size of buf
}

impl<A: Allocator> ChachaStream<A> {
    /// Return a new `ChachaStream` instance. `key` is the secret key of
    /// size `KEY_SIZE` and `nonce` is the nonce of size `NONCE_SIZE`.
    pub fn new(key: &SBuf<A, u8>, nonce: &[u8]) -> Result<ChachaStream<A>, ()> {
        assert!(BUFFER_SIZE > 0);
        Ok(ChachaStream {
            inner: try!(ChachaRaw::new(key, nonce)),
            buf: SBuf::new_zero(BUFFER_SIZE),
            pos: 0,
            cap: 0,
        })
    }

    /// Read by reference up to count bytes. Return `Err` on end-of-stream.
    pub fn read_bytes_ref(&mut self, count: uint) -> IoResult<&[u8]> {
        let nread = {
            let available = try!(self.fill_buf());
            let nread = cmp::min(available.len(), count);
            nread
        };
        let pos = self.pos;
        self.consume(nread);
        Ok(self.buf.slice(pos, nread))
    }

    /// Read by reference a single byte. Return `Err` on end-of-stream.
    pub fn read_byte_ref(&mut self) -> IoResult<&u8> {
        try!(self.fill_buf());
        let pos = self.pos;
        self.consume(1);
        Ok(self.buf.get(pos))
    }

    // FIXME: find better name.
    /// Convenience method directly returning the encrypted data as a
    /// `SBuf`buffer.
    pub fn encrypt_to_sbuf(&mut self, input: &[u8]) -> IoResult<SBuf<A, u8>> {
        let mut s: SBuf<A, u8> = SBuf::new_zero(input.len());
        try!(self.encrypt(input, s.as_mut_slice()));
        Ok(s)
    }

    pub fn decrypt_to_sbuf(&mut self, input: &[u8]) -> IoResult<SBuf<A, u8>> {
        self.encrypt_to_sbuf(input)
    }

    /// Read and discard the next `n` keystream bytes. Return the
    /// number of bytes discarded.
    pub fn skip(&mut self, n: uint) -> IoResult<uint> {
        let mut s: SBuf<A, u8> = SBuf::new_zero(n);
        self.read(s.as_mut_slice())
    }
}

impl<A: Allocator> CipherEncrypt for ChachaStream<A> {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> IoResult<uint> {
        if output.len() < input.len() {
            return Err(IoError {
                kind: InvalidInput,
                desc: "Destination buffer must be larger than source buffer",
                detail: None
            });
        }
        for (i, o) in input.iter().zip(output.mut_iter()) {
            *o = *i ^ *try!(self.read_byte_ref());
        }
        Ok(input.len())
    }
}

impl<A: Allocator> Buffer for ChachaStream<A> {
    fn fill_buf(&mut self) -> IoResult<&[u8]> {
        if self.pos == self.cap {
            self.cap = try!(self.inner.read(self.buf.as_mut_slice()));
            self.pos = 0;
        }
        Ok(self.buf.slice(self.pos, self.cap))
    }

    fn consume(&mut self, amt: uint) {
        self.pos += amt;
        assert!(self.pos <= self.cap);
    }
}

impl<A: Allocator> Reader for ChachaStream<A> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
        let mut pos = 0u;

        while pos < buf.len() {
            let nread = {
                let available = try!(self.fill_buf());
                let nread = cmp::min(available.len(), buf.len() - pos);
                slice::bytes::copy_memory(buf.mut_slice_from(pos),
                                          available.slice_to(nread));
                nread
            };
            self.consume(nread);
            pos += nread;
        }

        Ok(pos)
    }
}

impl<A: Allocator> Clone for ChachaStream<A> {
    fn clone(&self) -> ChachaStream<A> {
        ChachaStream {
            inner: self.inner.clone(),
            buf: self.buf.clone(),
            pos: self.pos,
            cap: self.cap
        }
    }
}


/// Chacha20 Encrypter
pub struct ChachaEncrypter<A> {
    stream: ChachaStream<A>
}

impl<A: Allocator> ChachaEncrypter<A> {
    /// New encrypter instance from `key` and `nonce`.
    pub fn new(key: &SBuf<A, u8>,
               nonce: &[u8]) -> Result<ChachaEncrypter<A>, ()> {
        Ok(ChachaEncrypter::new_with_stream(try!(ChachaStream::new(key,
                                                                   nonce))))
    }

    /// New encrypter instance from already instanciated Chacha20 key stream.
    pub fn new_with_stream(stream: ChachaStream<A>) -> ChachaEncrypter<A> {
        ChachaEncrypter {
            stream: stream
        }
    }
}

impl<A: Allocator> Encrypter<ChachaStream<A>> for ChachaEncrypter<A> {
    /// Encrypt `value`. Internally for a same instance, the encryption
    /// state is maintained between repeated calls to this method or to the
    /// decrypt method.
    fn encrypt<T: Encrypt<ChachaStream<A>>>(&mut self, value: &T,
                                            output: &mut [u8])
                                            -> IoResult<uint> {
        value.encrypt(&mut self.stream, output)
    }
}


/// Encrypt bytes
pub fn encrypt<A: Allocator>(key: &SBuf<A, u8>, nonce: &[u8],
                             input: &[u8], output: &mut [u8])
                             -> Result<uint, ()> {
    let mut s: ChachaStream<A> = try!(ChachaStream::new(key, nonce));
    Ok(try_ok_unit!(s.encrypt(input, output)))
}

/// Decrypt bytes
pub fn decrypt<A: Allocator>(key: &SBuf<A, u8>, nonce: &[u8],
                             input: &[u8], output: &mut [u8])
                             -> Result<uint, ()> {
    encrypt(key, nonce, input, output)
}


/// [Chacha20 AEAD](http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01)
pub struct ChachaAead<A = DefaultAllocator> {
    key: SBuf<A, u8>
}

impl<A: Allocator> ChachaAead<A> {
    /// Return a new `ChachaAead` instance. `key` is the secret key of
    /// size `KEY_SIZE`.
    pub fn new(key: &SBuf<A, u8>) -> Result<ChachaAead<A>, ()> {
        if key.len() != KEY_SIZE {
            return Err(());
        }

        Ok(ChachaAead {
            key: key.clone()
        })
    }

    fn authenticator(&self, mac_key: &SBuf<A, u8>, aad: Option<&[u8]>,
                     ciphertext: &[u8], tag: &mut [u8]) -> Result<(), ()> {
        if mac_key.len() != poly1305::KEY_SIZE ||
            tag.len() != poly1305::TAG_SIZE {
            return Err(());
        }

        let mut poly = try!(poly1305::Poly1305::new(mac_key));
        let mut lens_enc = SBuf::<A, u8>::new_zero(u64::BYTES * 2);
        match aad {
            Some(data) => {
                try_ok_unit!(data.hash(&mut poly));
                try_ok_unit!(utils::pad16(data.len()).hash(&mut poly));
                utils::u64to8_le(lens_enc.mut_slice_to(u64::BYTES),
                                 &(data.len() as u64));
            },
            None => ()
        }
        try_ok_unit!(ciphertext.hash(&mut poly));
        try_ok_unit!(utils::pad16(ciphertext.len()).hash(&mut poly));
        utils::u64to8_le(lens_enc.mut_slice_from(u64::BYTES),
                         &(ciphertext.len() as u64));
        try_ok_unit!(lens_enc.as_slice().hash(&mut poly));
        try_ok_unit!(poly.tag(tag));
        Ok(())
    }

    /// `nonce` is a unique nonce of size `NONCE_AEAD_SIZE`, `plaintext`
    /// is the data to encrypt and authenticate. `aad` is some optional
    /// additional data to authenticate. The authenticated ciphertext
    /// is returned on output.
    pub fn seal(&self, nonce: &[u8], plaintext: &[u8],
                aad: Option<&[u8]>) -> Result<SBuf<A, u8>, ()> {
        if nonce.len() != NONCE_AEAD_SIZE {
            return Err(());
        }

        let mut chacha = try!(ChachaStream::new(&self.key, nonce));

        let mut mac_key = SBuf::<A, u8>::new_zero(poly1305::KEY_SIZE);
        try_ok_unit!(chacha.read(mac_key.as_mut_slice()));

        // Discard remaining bytes of the first block.
        assert!(poly1305::KEY_SIZE <= BLOCK_SIZE);
        try_ok_unit!(chacha.skip(BLOCK_SIZE - poly1305::KEY_SIZE));

        // Prepare output buffer.
        let mut out = SBuf::<A, u8>::new_zero(poly1305::TAG_SIZE +
                                              plaintext.len());

        // Encrypt plaintext.
        try_ok_unit!(plaintext.encrypt(&mut chacha,
                                       out.mut_slice_from(poly1305::TAG_SIZE)));

        // Compute one-time authenticator.
        {
            let (tag, cyphertext) = out.mut_split_at(poly1305::TAG_SIZE);
            try!(self.authenticator(&mac_key, aad, cyphertext, tag));
        }

        Ok(out)
    }

    /// `nonce` is a unique nonce of size `NONCE_AEAD_SIZE`, `ciphertext`
    /// is the authenticated and encypted data to decrypt. `aad` is some
    /// optional additional data authenticated with the ciphertext. This
    /// method returns the plaintext on output.
    pub fn open(&self, nonce: &[u8], ciphertext: &[u8],
                aad: Option<&[u8]>) -> Result<SBuf<A, u8>, ()> {
        if nonce.len() != NONCE_AEAD_SIZE ||
            ciphertext.len() < poly1305::TAG_SIZE {
            return Err(());
        }

        let mut chacha = try!(ChachaStream::new(&self.key, nonce));

        let mut mac_key = SBuf::<A, u8>::new_zero(poly1305::KEY_SIZE);
        try_ok_unit!(chacha.read(mac_key.as_mut_slice()));

        // Discard remaining bytes of the first block.
        assert!(poly1305::KEY_SIZE <= BLOCK_SIZE);
        try_ok_unit!(chacha.skip(BLOCK_SIZE - poly1305::KEY_SIZE));

        // Authenticate data.
        let mut tag = SBuf::<A, u8>::new_zero(poly1305::TAG_SIZE);
        try!(self.authenticator(&mac_key, aad,
                                ciphertext.slice_from(poly1305::TAG_SIZE),
                                tag.as_mut_slice()));

        // Check provided authenticator is valid.
        if !utils::bytes_eq(ciphertext.slice_to(poly1305::TAG_SIZE),
                            tag.as_slice()) {
            return Err(());
        }

        // Decrypt data.
        let mut plaintext = SBuf::<A, u8>::new_zero(ciphertext.len() -
                                                    poly1305::TAG_SIZE);
        try_ok_unit!(ciphertext.slice_from(poly1305::TAG_SIZE).decrypt(
            &mut chacha, plaintext.as_mut_slice()));

        Ok(plaintext)
    }
}

impl<A: Allocator> Clone for ChachaAead<A> {
    fn clone(&self) -> ChachaAead<A> {
        ChachaAead {
            key: self.key.clone()
        }
    }
}


#[cfg(test)]
mod tests {
    use serialize::hex::FromHex;
    use std::num;
    use std::rand::{task_rng, Rng};
    use test::Bencher;

    use common::sbuf::{DefaultAllocator, SBuf};

    use chacha20::{ChachaStream, ChachaEncrypter, ChachaAead, NONCE_SIZE,
                   NONCE_AEAD_SIZE, KEY_SIZE, BLOCK_SIZE, encrypt, decrypt};
    use encrypt::{Encrypt, Encrypter, CipherEncrypt};
    use poly1305;


    #[test]
    fn test_chacha_ref() {
        let vectors = [
            [
                // Key
                "0000000000000000000000000000000000000000000000000000000000000000",
                // Nonce
                "0000000000000000",
                // Keystream
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
                    ],
            [
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000",
                "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae5469633aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"
                    ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000002",
                "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d"
                ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000001",
                "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757"
                    ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0100000000000000",
                "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b"
                    ],
            [
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "0001020304050607",
                "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb"
                    ]
            ];
        let zeros: [u8, ..512] = [0, ..512];

        for i in range(0, vectors.len()) {
            let k: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][0].from_hex().unwrap().as_slice());
            let v1 = vectors[i][1].from_hex().unwrap();
            let n = v1.as_slice();
            let v2 = vectors[i][2].from_hex().unwrap();
            let o = v2.as_slice();
            let mut c: Vec<u8> = Vec::from_elem(o.len(), 0);

            let mut s: ChachaStream<DefaultAllocator> =
                ChachaStream::new(&k, n).unwrap();
            let res = zeros.slice(0, o.len()).encrypt(&mut s, c.as_mut_slice());

            assert!(res.is_ok() && res.ok().unwrap() == o.len());
            assert!(o.as_slice() == c.as_slice());
        }
    }

    #[test]
    fn test_encrypter() {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let nonce: [u8, ..NONCE_SIZE] = [0, ..NONCE_SIZE];
        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input.as_mut_slice());
        let mut out1: Vec<u8> = Vec::from_elem(size, 0);
        let mut out2: Vec<u8> = Vec::from_elem(size, 0);

        let mut encrypter =
            ChachaEncrypter::new(&key, nonce.as_slice()).unwrap();
        let mut ret = encrypter.encrypt(&input, out1.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        encrypter =
            ChachaEncrypter::new(&key, nonce.as_slice()).unwrap();
        ret = encrypter.decrypt(&out1, out2.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        assert!(input == out2);
    }

    #[test]
    fn test_encrypt() {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let nonce: [u8, ..NONCE_SIZE] = [0, ..NONCE_SIZE];
        let mut input: Vec<u8> = Vec::from_elem(size, 0);
        task_rng().fill_bytes(input.as_mut_slice());
        let mut out1: Vec<u8> = Vec::from_elem(size, 0);
        let mut out2: Vec<u8> = Vec::from_elem(size, 0);

        let mut ret = encrypt(&key, nonce.as_slice(), input.as_slice(),
                              out1.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        ret = decrypt(&key, nonce.as_slice(), out1.as_slice(),
                      out2.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        assert!(input == out2);
    }

    #[test]
    fn test_encrypt_ref() {
        let vectors = [
            [
                // Key
                "0000000000000000000000000000000000000000000000000000000000000000",
                // Nonce
                "0000000000000000",
                // Plaintext
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                // Ciphertext
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
                // Initial block counter
                "0"
                    ],
            [
                "0000000000000000000000000000000000000000000000000000000000000001",
                "000000000000000000000002",
                "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
                "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
                "1"
                    ],
            [
                "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                "000000000000000000000002",
                "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
                "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
                "42"
                    ]
                ];

        for i in range(0, vectors.len()) {
            let k: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][0].from_hex().unwrap().as_slice());
            let n: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][1].from_hex().unwrap().as_slice());
            let p1: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][2].from_hex().unwrap().as_slice());
            let c1: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][3].from_hex().unwrap().as_slice());
            let b: uint = num::from_str_radix(vectors[i][4], 10).unwrap();

            // Encrypt.
            let mut chacha = ChachaStream::new(&k, n.as_slice()).unwrap();
            chacha.skip(b * BLOCK_SIZE).unwrap();
            let mut c2: SBuf<DefaultAllocator, u8> = SBuf::new_zero(p1.len());
            chacha.encrypt(p1.as_slice(), c2.as_mut_slice()).unwrap();
            assert!(c1 == c2);

            // Decrypt.
            let mut chacha = ChachaStream::new(&k, n.as_slice()).unwrap();
            chacha.skip(b * BLOCK_SIZE).unwrap();
            let mut p2: SBuf<DefaultAllocator, u8> = SBuf::new_zero(p1.len());
            chacha.decrypt(c2.as_slice(), p2.as_mut_slice()).unwrap();
            assert!(p1 == p2);
        }
    }

    #[test]
    fn test_read_chunks() {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let nonce: [u8, ..NONCE_SIZE] = [0, ..NONCE_SIZE];
        let mut ks1: Vec<u8> = Vec::from_elem(size, 0);

        // One chunk
        let mut stream = ChachaStream::new(&key, nonce.as_slice()).unwrap();
        let ret = stream.read(ks1.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        // Multiple chunks
        let mut old_pos = 0u;
        let mut pos = 0u;
        stream = ChachaStream::new(&key, nonce.as_slice()).unwrap();
        let mut ks2: Vec<u8> = Vec::from_elem(size, 0);
        while pos < size {
            pos = task_rng().gen_range(pos, size + 1);
            assert!(stream.read(ks2.mut_slice(old_pos, pos)).is_ok());
            old_pos = pos;
        }

        // Compare keystreams
        assert!(ks1 == ks2);
    }

    #[test]
    fn test_nonces() {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let mut ks1: Vec<u8> = Vec::from_elem(size, 0);
        let mut ks2: Vec<u8> = Vec::from_elem(size, 0);

        let n1: [u8, ..NONCE_SIZE] = [0, ..NONCE_SIZE];
        let mut s1 = ChachaStream::new(&key, n1.as_slice()).unwrap();
        let mut ret = s1.read(ks1.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        let n2: [u8, ..NONCE_AEAD_SIZE] = [0, ..NONCE_AEAD_SIZE];
        let mut s2 = ChachaStream::new(&key, n2.as_slice()).unwrap();
        ret = s2.read(ks2.as_mut_slice());
        assert!(ret.ok().unwrap() == size);

        assert!(ks1 == ks2);
    }

    #[test]
    fn test_aead() {
        let key = SBuf::<DefaultAllocator, u8>::new_rand(KEY_SIZE);
        let nonce = SBuf::<DefaultAllocator, u8>::new_rand(NONCE_AEAD_SIZE);

        // Plaintext data.
        let pt_len = task_rng().gen_range(0, 32768);
        let pt = SBuf::<DefaultAllocator, u8>::new_rand(pt_len);

        // Authenticated additional data.
        let aad_len = task_rng().gen_range(0, 32768);
        let aad = SBuf::<DefaultAllocator, u8>::new_rand(aad_len);

        let aead = ChachaAead::new(&key).unwrap();

        // Encrypt.
        let ct = aead.seal(nonce.as_slice(), pt.as_slice(),
                           Some(aad.as_slice())).unwrap();
        assert!(ct.len() == pt.len() + poly1305::TAG_SIZE);

        // Decrypt.
        let pt_dec = aead.open(nonce.as_slice(), ct.as_slice(),
                               Some(aad.as_slice())).unwrap();
        assert!(pt == pt_dec);
    }

    #[test]
    fn test_aead_ref() {
        // Test vectors from:
        // http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
        let vectors = [
            [
                // key
                "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
                // nonce
                "000000000102030405060708",
                // aad
                "f33388860000000000004e91",
                // plaintext
                "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
                // tag || ciphertext
                "eead9d67890cbb22392336fea1851f3864a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b"
                    ],
            [
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "070000004041424344454647",
                "50515253c0c1c2c3c4c5c6c7",
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
                "1ae10b594f09e26a7e902ecbd0600691d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
                    ]
                ];

        for i in range(0, vectors.len()) {
            let k: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][0].from_hex().unwrap().as_slice());
            let n: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][1].from_hex().unwrap().as_slice());
            let a: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][2].from_hex().unwrap().as_slice());
            let p1: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][3].from_hex().unwrap().as_slice());
            let c1: SBuf<DefaultAllocator, u8> = SBuf::from_bytes(
                vectors[i][4].from_hex().unwrap().as_slice());

            let aead = ChachaAead::new(&k).unwrap();

            // Encrypt.
            let c2 = aead.seal(n.as_slice(), p1.as_slice(),
                               Some(a.as_slice())).unwrap();
            assert!(c2.len() == p1.len() + poly1305::TAG_SIZE);
            assert!(c1 == c2);

            // Decrypt.
            let p2 = aead.open(n.as_slice(), c2.as_slice(),
                               Some(a.as_slice())).unwrap();
            assert!(p1 == p2);
        }
    }

    #[bench]
    #[allow(unused_must_use)]
    fn bench_chacha20(b: &mut Bencher) {
        let size = 8192u;
        let key: SBuf<DefaultAllocator, u8> = SBuf::new_rand(KEY_SIZE);
        let nonce: [u8, ..NONCE_SIZE] = [0, ..NONCE_SIZE];
        let mut ks: Vec<u8> = Vec::from_elem(size, 0);
        let mut stream = ChachaStream::new(&key, nonce.as_slice()).unwrap();

        b.iter(|| {
            stream.read(ks.as_mut_slice());
        })
    }
}
