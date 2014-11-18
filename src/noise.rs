//! [Noise](https://github.com/trevp/noise/blob/master/noise.md) crypto
//! protocols
//!
//! __/!\ EXPERIMENTAL /!\__
use std::io::Reader;
use std::rand::Rng;
use std::slice;
use std::{u32, u64};

use common::sbuf::{Allocator, DefaultAllocator, SBuf};
use common::utils;
use curve41417::bytes::{Bytes, Scalar, MontPoint};
use curve41417::{mod, mont};

use chacha20::{mod, ChachaStream};
use encrypt::{Encrypt, CipherEncrypt};
use hash::Hash;
use kdf::XKdf;
use poly1305::{mod, Poly1305};
use sha3::Sha3Mode::Shake256;


// Cipher suite name.
const NOISE414: &'static [u8] = b"Curv41417-Chacha20-Shake";


/// Noise cipher suite
pub trait NoiseSuite<A> : Clone {
    /// Return a new instance of this cipher suite.
    fn new() -> Self;

    /// Cipher suite's name.
    fn name(&self) -> &[u8];

    /// Generate and return a new pair of keys (pubkey, privkey).
    fn keypair(&self) -> (SBuf<A, u8>, SBuf<A, u8>);

    /// Return the point resulting from the DH computation.
    fn dh(&self, privkey: &[u8], pubkey: &[u8]) -> Result<SBuf<A, u8>, ()>;

    /// Derive a secret key from `secret`, `extra_secret`, `info` and
    /// write it in `output`, use all its length.
    fn kdf(&self, secret: &[u8], extra_secret: &[u8], info: &[u8],
           output: &mut [u8]) -> Result<uint, ()>;

    // FIXME: remove optional padding, force mandatory padding (even if 0-length).
    /// Encrypt `plaintext`, authenticate its result along with `authtext`.
    /// Update its context `key` and `nonce` and eventually return the
    /// ciphertext. When `None` is returned `key` and `nonce` are not updated.
    /// `pad_len` should be `None` when no padding should be appended.
    fn encrypt(&self, key: &mut [u8], nonce: &mut [u8],
               plaintext: &[u8], pad_len: Option<uint>,
               authtext: Option<&[u8]>) -> Result<SBuf<A, u8>, ()>;

    /// Authenticate `authtext` and the encrypted data `cyphertext`, then
    /// decrypt `ciphertext`, update `key` and `nonce` and eventually
    /// return its plaintext. When `None` is returned `key` and `nonce`
    /// are not updated. `pad` is `true` when some padding was appended
    /// to the plaintext and must be removed, the plaintext is returned
    /// without padding. If the authentication failed `None` is returned.
    fn decrypt(&self, key: &mut [u8], nonce: &mut [u8], ciphertext: &[u8],
               pad: bool, authtext: Option<&[u8]>) -> Result<SBuf<A, u8>, ()>;

    /// Chaining variable's size.
    fn cv_size(&self) -> uint;

    /// Cipher context's size (key + mac).
    fn cc_size(&self) -> uint;

    /// Cipher key's size.
    fn key_size(&self) -> uint;

    /// Cipher nonce's size.
    fn nonce_size(&self) -> uint;

    /// DH keys size.
    fn dh_size(&self) -> uint;

    /// MAC tag's size.
    fn mac_size(&self) -> uint;
}


/// Noise414 cipher suite
///
/// Use the following primitives:
///
///   * Curve41417 (DH)
///   * Chacha20-Poly1305 (Authenticated Encryption)
///   * Shake256 (Key-Derivation)
///
/// Note: this cipher suite is different than the suites officially
/// [supported](https://github.com/trevp/noise/wiki/Ciphersuites). It uses
/// a `DH` function with a different primitive, the same `ENCRYPT`
/// function than the one specified in `Noise255` and a different `KDF`
/// function with a different primitive.
pub struct Noise414<A = DefaultAllocator> {
    name: &'static [u8]
}

impl<A: Allocator> NoiseSuite<A> for Noise414<A> {
    fn new() -> Noise414<A> {
        Noise414 {
            name: NOISE414,
        }
    }

    fn name(&self) -> &[u8] {
        self.name
    }

    fn keypair(&self) -> (SBuf<A, u8>, SBuf<A, u8>) {
        let (MontPoint(pk), Scalar(sk)) = mont::keypair::<A>();
        (pk.unwrap(), sk.unwrap())
    }

    fn dh(&self, privkey: &[u8], pubkey: &[u8]) -> Result<SBuf<A, u8>, ()> {
        let privk = Scalar(try_some_err!(Bytes::from_bytes(privkey)));
        let pubk = MontPoint(try_some_err!(Bytes::from_bytes(pubkey)));
        let MontPoint(shared) = mont::scalar_mult(&privk, &pubk);
        Ok(shared.unwrap())
    }

    fn kdf(&self, secret: &[u8], extra_secret: &[u8], info: &[u8],
           output: &mut [u8]) -> Result<uint, ()> {
        // fixme: separate kdf_num to context?
        let key = SBuf::<A, u8>::from_slices(&[secret, extra_secret]);
        let mut xkdf = try!(XKdf::<A>::new(Shake256, key[], info,
                                           None, output.len()));
        Ok(try_ok_unit!(xkdf.read(output)))
    }

    fn encrypt(&self, key: &mut [u8], nonce: &mut [u8],
               plaintext: &[u8], pad_len: Option<uint>,
               authtext: Option<&[u8]>) -> Result<SBuf<A, u8>, ()> {
        if key.len() != self.key_size() || nonce.len() != self.nonce_size() {
            return Err(());
        }

        let enc_len = if pad_len.is_some() {
            plaintext.len() + *pad_len.as_ref().unwrap() + u32::BYTES
        } else {
            plaintext.len()
        };
        let mut output = SBuf::<A, u8>::new_zero(enc_len + self.mac_size());

        // Encryption state.
        let mut chacha = try!(ChachaStream::new(&SBuf::<A, u8>::from_slice(key),
                                                nonce));

        // Generate mac key.
        let mut mac_key = SBuf::<A, u8>::new_zero(poly1305::KEY_SIZE);
        try_ok_unit!(chacha.read(mac_key[mut]));

        // Discard first block's remaining bytes.
        assert!(chacha20::BLOCK_SIZE >= poly1305::KEY_SIZE);
        try_ok_unit!(chacha.skip(chacha20::BLOCK_SIZE - poly1305::KEY_SIZE));

        // Encrypt plaintext.
        try_ok_unit!(plaintext.encrypt(&mut chacha, output[mut]));

        // Optionally encrypt random padding.
        if pad_len.is_some() {
            let padlen = *pad_len.as_ref().unwrap();
            let mut pad = SBuf::<A, u8>::new_zero(padlen + u32::BYTES);
            if padlen > 0 {
                let rng = &mut utils::urandom_rng();
                rng.fill_bytes(pad[mut ..padlen]);
            }
            utils::u32to8_le(pad[mut padlen..], &(try_some_err!(padlen.to_u32())));
            try_ok_unit!(pad[].encrypt(&mut chacha,
                                       output[mut plaintext.len()..]));
        }

        // Authenticate fields.
        {
            let (ciphertext, tag) = output.split_at_mut(enc_len);
            try_ok_unit!(self.authenticate(ciphertext, authtext,
                                           &mac_key, tag));
        }

        // Update context.
        try_ok_unit!(self.update_context(key, nonce));

        Ok(output)
    }

    fn decrypt(&self, key: &mut [u8], nonce: &mut [u8], ciphertext: &[u8],
               pad: bool, authtext: Option<&[u8]>) -> Result<SBuf<A, u8>, ()> {
        if key.len() != self.key_size() || nonce.len() != self.nonce_size() {
            return Err(());
        }

        let min_size = if pad {
            self.mac_size() + u32::BYTES
        } else {
            self.mac_size()
        };
        if ciphertext.len() < min_size {
            return Err(());
        }

        let out_len = ciphertext.len() - self.mac_size();
        let mut output = SBuf::<A, u8>::new_zero(out_len);

        // Encryption state.
        let mut chacha = try!(ChachaStream::new(&SBuf::<A, u8>::from_slice(key),
                                                nonce));

        // Generate mac key.
        let mut mac_key = SBuf::<A, u8>::new_zero(poly1305::KEY_SIZE);
        try_ok_unit!(chacha.read(mac_key[mut]));

        // Authenticate fields.
        let mut tag = SBuf::<A, u8>::new_zero(self.mac_size());
        try_ok_unit!(self.authenticate(ciphertext[..out_len], authtext,
                                       &mac_key, tag[mut]));

        // Validate tag.
        if !utils::bytes_eq(ciphertext[out_len..], tag[]) {
            return Err(());
        }

        // Discard first block's remaining bytes.
        assert!(chacha20::BLOCK_SIZE >= poly1305::KEY_SIZE);
        try_ok_unit!(chacha.skip(chacha20::BLOCK_SIZE - poly1305::KEY_SIZE));

        // Decrypt ciphertext.
        try_ok_unit!(ciphertext[..out_len].decrypt(&mut chacha, output[mut]));
        if pad {
            let mut pad_len: u32 = 0;
            utils::u8to32_le(&mut pad_len,
                             output[out_len - u32::BYTES..out_len]);
            if (pad_len + 4) as uint > out_len {
                return Err(());
            }
            output = SBuf::from_slice(output[..out_len - pad_len as uint -
                                             u32::BYTES]);
        }

        // Update context.
        try_ok_unit!(self.update_context(key, nonce));

        Ok(output)
    }

    fn cv_size(&self) -> uint {
        48
    }

    fn cc_size(&self) -> uint {
        self.key_size() + self.nonce_size()
    }

    fn key_size(&self) -> uint {
        chacha20::KEY_SIZE
    }

    fn nonce_size(&self) -> uint {
        chacha20::NONCE_SIZE
    }

    fn dh_size(&self) -> uint {
        curve41417::POINT_SIZE
    }

    fn mac_size(&self) -> uint {
        poly1305::TAG_SIZE
    }
}

// Helpers
impl<A: Allocator> Noise414<A> {
    fn authenticate(&self, ciphertext: &[u8], authtext: Option<&[u8]>,
                    key: &SBuf<A, u8>, tag: &mut [u8]) -> Result<uint, ()> {
        // Authenticate fields.
        let mut poly = try!(Poly1305::new(key));

        let mut authtext_len = 0;
        if authtext.is_some() {
            try_ok_unit!(authtext.as_ref().unwrap().hash(&mut poly));
            authtext_len = authtext.as_ref().unwrap().len();
            try_ok_unit!(utils::pad16(authtext_len).hash(&mut poly));
        }

        try_ok_unit!(ciphertext.hash(&mut poly));
        try_ok_unit!(utils::pad16(ciphertext.len()).hash(&mut poly));

        let mut le_buf = SBuf::<A, u8>::new_zero(u64::BYTES * 2);
        utils::u64to8_le(le_buf[mut ..u64::BYTES], &(authtext_len as u64));
        utils::u64to8_le(le_buf[mut u64::BYTES..], &(ciphertext.len() as u64));
        try_ok_unit!(le_buf[].hash(&mut poly));

        assert!(tag.len() == self.mac_size());
        Ok(try_ok_unit!(poly.tag(tag)))
    }

    fn update_context(&self, key: &mut [u8],
                      nonce: &mut [u8]) -> Result<(), ()> {
        assert!(nonce.len() == self.nonce_size());
        let n = SBuf::<A, u8>::from_fn(self.nonce_size(), |idx| {
            nonce[idx] ^ 0xff
        });

        let mut chacha = try!(ChachaStream::new(&SBuf::<A, u8>::from_slice(key),
                                                n[]));

        // Discard first block.
        try_ok_unit!(chacha.skip(chacha20::BLOCK_SIZE));

        // Replace key and nonce.
        try_ok_unit!(chacha.read(key));
        try_ok_unit!(chacha.read(nonce));

        Ok(())
    }
}

impl<A: Allocator> Clone for Noise414<A> {
    fn clone(&self) -> Noise414<A> {
        Noise414 {
            name: self.name
        }
    }
}


/// Noise Blob
///
/// As specified [here](https://github.com/trevp/noise/blob/master/noise.md).
pub struct Blob<T, A = DefaultAllocator> {
    suite: T,
    key: Option<SBuf<A, u8>>,
    nonce: Option<SBuf<A, u8>>,
}

impl<A: Allocator, T: NoiseSuite<A>> Blob<T, A> {
    /// After instanciating a new instance `set_context()` must be called.
    pub fn new() -> Blob<T, A> {
        Blob {
            suite: NoiseSuite::new(),
            key: None,
            nonce: None
        }
    }

    /// Return the underlying cipher suite used for crypto operations.
    pub fn cipher_suite(&self) -> &T {
        &self.suite
    }

    /// Set crypto context, must be called before calling `seal()` or
    /// `open()`.
    pub fn set_context(&mut self, key: &[u8], nonce: &[u8]) {
        self.key = Some(SBuf::from_slice(key));
        self.nonce = Some(SBuf::from_slice(nonce));
    }

    /// Return current's crypto context `(key, nonce)`.
    pub fn get_context(&self) -> (Option<&SBuf<A, u8>>, Option<&SBuf<A, u8>>) {
        (self.key.as_ref(), self.nonce.as_ref())
    }

    pub fn seal(&mut self, pad_len: uint, contents: &[u8],
                authtext: Option<&[u8]>) -> Result<SBuf<A, u8>, ()> {
        match (&self.key, &self.nonce) {
            (&Some(_), &Some(_)) => (),
            (_, _) => return Err(())
        }
        self.suite.encrypt(self.key.as_mut().unwrap()[mut],
                           self.nonce.as_mut().unwrap()[mut],
                           contents, Some(pad_len), authtext)
    }

    pub fn open(&mut self, ciphertext: &[u8], authtext: Option<&[u8]>)
                -> Result<SBuf<A, u8>, ()> {
        match (&self.key, &self.nonce) {
            (&Some(_), &Some(_)) => (),
            (_, _) => return Err(())
        }
        self.suite.decrypt(self.key.as_mut().unwrap()[mut],
                           self.nonce.as_mut().unwrap()[mut],
                           ciphertext, true, authtext)
    }
}

impl<A: Allocator, T: NoiseSuite<A>> Clone for Blob<T, A> {
    fn clone(&self) -> Blob<T, A> {
        Blob {
            suite: self.suite.clone(),
            key: self.key.clone(),
            nonce: self.nonce.clone()
        }
    }
}


/// Noise Box
///
/// As specified [here](https://github.com/trevp/noise/blob/master/noise.md).
pub struct Box<T, A = DefaultAllocator> {
    suite: T
}

impl<A: Allocator, T: NoiseSuite<A>> Box<T, A> {
    pub fn new() -> Box<T, A> {
        Box {
            suite: NoiseSuite::new()
        }
    }

    /// Return the underlying cipher suite used for crypto operations.
    pub fn cipher_suite(&self) -> &T {
        &self.suite
    }

    /// Generate a new key pair.
    pub fn keypair(&self) -> (SBuf<A, u8>, SBuf<A, u8>) {
        self.suite.keypair()
    }

    /// Box `contents` and return the tuple `(boxed_data, cv)` where
    /// `cv` is the resulting chaining variable.
    pub fn seal(&self, eph_privkey: &[u8],
                sender_pubkey: &[u8], sender_privkey: &[u8],
                target_pubkey: &[u8],
                header_pad_len: uint, body_pad_len: uint,
                contents: &[u8], authtext: Option<&[u8]>,
                kdf_num: Option<u8>, cv: Option<&[u8]>)
                -> Result<(SBuf<A, u8>, SBuf<A, u8>), ()> {
        let kdf_val = if kdf_num.is_none() {
            0
        } else {
            *kdf_num.as_ref().unwrap()
        };
        if kdf_val == 255 {
            return Err(());
        }

        let suite = &self.suite;

        let chain: SBuf<A, u8> = if cv.is_none() {
            SBuf::new_zero(suite.cv_size())
        } else {
            SBuf::from_slice(*cv.as_ref().unwrap())
        };
        if chain.len() != suite.cv_size() {
            return Err(());
        }

        // DHs
        let dh1 = try_ok_unit!(suite.dh(eph_privkey, target_pubkey));
        let dh2 = try_ok_unit!(suite.dh(sender_privkey, target_pubkey));

        // Info data.
        let mut info = SBuf::<A, u8>::new_zero(suite.name().len() + 1);
        slice::bytes::copy_memory(info[mut], suite.name()[]);
        let kdf_num_idx = info.len() - 1;
        info[kdf_num_idx] = kdf_val;

        // KDF1
        let mut kdf1 = SBuf::<A, u8>::new_zero(suite.cc_size() +
                                               suite.cv_size());
        try_ok_unit!(self.suite.kdf(dh1[], chain[], info[], kdf1[mut]));

        // KDF2
        let cv_idx = suite.cc_size();
        info[kdf_num_idx] += 1;
        let mut kdf2 = SBuf::<A, u8>::new_zero(suite.cc_size() +
                                               suite.cv_size());
        try_ok_unit!(self.suite.kdf(dh2[], kdf1[cv_idx..], info[], kdf2[mut]));

        // Encrypt header.
        let nonce_idx = suite.key_size();
        let hdr_enc = {
            let (hdr_key, hdr_nonce) = kdf1.split_at_mut(nonce_idx);
            let mut hdr: Blob<T, A> = Blob::new();
            hdr.set_context(hdr_key, hdr_nonce[mut ..suite.nonce_size()]);
            try_ok_unit!(hdr.seal(header_pad_len, sender_pubkey, authtext))
        };

        // Encrypt body.
        let bdy_enc = {
            let (bdy_key, bdy_nonce) = kdf2.split_at_mut(nonce_idx);
            let bdy_add: SBuf<A, u8> = if authtext.is_some() {
                SBuf::from_slices(&[*authtext.as_ref().unwrap(), hdr_enc[]])
            } else {
                SBuf::from_slice(hdr_enc[])
            };
            let mut body: Blob<T, A> = Blob::new();
            body.set_context(bdy_key, bdy_nonce[mut ..suite.nonce_size()]);
            try_ok_unit!(body.seal(body_pad_len, contents, Some(bdy_add[])))
        };

        // Assemble final result.
        let boxed = SBuf::from_slices(&[hdr_enc[], bdy_enc[]]);
        let cv2 = SBuf::from_slice(kdf2[cv_idx..]);
        Ok((boxed, cv2))
    }

    /// Unbox `box_data` and return the tuple `(sender_pubkey, contents, cv)`.
    /// Where `sender_pubkey` is the non-ephemeral sender's public key to
    /// which `box_data` was encrypted to. `contents` is the decrypted data
    /// and `cv` is the resulting chaining variable. `recvr_privkey` is
    /// usually an ephemeral key.
    pub fn open(&self, recvr_privkey: &[u8], sender_eph_pubkey: &[u8],
                box_data: &[u8], authtext: Option<&[u8]>,
                kdf_num: Option<u8>, cv: Option<&[u8]>)
                -> Result<(SBuf<A, u8>, SBuf<A, u8>, SBuf<A, u8>), ()> {
        let suite = &self.suite;

        if box_data.len() < suite.dh_size() +
                        2 * (suite.mac_size() + u32::BYTES) {
            return Err(());
        }

        let kdf_val = if kdf_num.is_none() {
            0
        } else {
            *kdf_num.as_ref().unwrap()
        };
        if kdf_val == 255 {
            return Err(());
        }

        let chain: SBuf<A, u8> = if cv.is_none() {
            SBuf::new_zero(suite.cv_size())
        } else {
            SBuf::from_slice(*cv.as_ref().unwrap())
        };
        if chain.len() != suite.cv_size() {
            return Err(());
        }

        // Split input box.
        // FIXME: handle cases where header_pad_len is different than 0, thus
        //        bdy_idx may be variable.
        let bdy_idx = suite.dh_size() + suite.mac_size() + u32::BYTES;
        let hdr_enc = box_data[..bdy_idx];
        let bdy_enc = box_data[bdy_idx..];

        // DH1
        let dh1 = try_ok_unit!(self.suite.dh(recvr_privkey, sender_eph_pubkey));

        // Info data.
        let mut info = SBuf::<A, u8>::new_zero(suite.name().len() + 1);
        slice::bytes::copy_memory(info[mut], suite.name()[]);
        let kdf_num_idx = info.len() - 1;
        info[kdf_num_idx] = kdf_val;

        // KDF1
        let mut kdf1 = SBuf::<A, u8>::new_zero(suite.cc_size() +
                                               suite.cv_size());
        try_ok_unit!(self.suite.kdf(dh1[], chain[], info[], kdf1[mut]));

        // Decrypt header
        let nonce_idx = suite.key_size();
        let cv_idx = suite.cc_size();
        let sender_pubkey = {
            let (hdr_key, hdr_nonce) = kdf1.split_at_mut(nonce_idx);
            let mut hdr: Blob<T, A> = Blob::new();
            hdr.set_context(hdr_key, hdr_nonce[mut ..suite.nonce_size()]);
            try_ok_unit!(hdr.open(hdr_enc, authtext))
        };

        // DH2
        let dh2 = try_ok_unit!(self.suite.dh(recvr_privkey, sender_pubkey[]));

        // KDF2
        info[kdf_num_idx] += 1;
        let mut kdf2 = SBuf::<A, u8>::new_zero(suite.cc_size() +
                                               suite.cv_size());
        try_ok_unit!(self.suite.kdf(dh2[], kdf1[cv_idx..], info[], kdf2[mut]));

        // Decrypt data.
        let bdy_dec = {
            let (bdy_key, bdy_nonce) = kdf2.split_at_mut(nonce_idx);
            let bdy_add: SBuf<A, u8> = if authtext.is_some() {
                SBuf::from_slices(&[*authtext.as_ref().unwrap(), hdr_enc])
            } else {
                SBuf::from_slice(hdr_enc)
            };
            let mut body: Blob<T, A> = Blob::new();
            body.set_context(bdy_key, bdy_nonce[mut ..suite.nonce_size()]);
            try_ok_unit!(body.open(bdy_enc, Some(bdy_add[])))
        };

        // Assemble final result.
        let cv2 = SBuf::from_slice(kdf2[cv_idx..]);
        Ok((sender_pubkey, bdy_dec, cv2))
    }
}

impl<A: Allocator, T: NoiseSuite<A>> Clone for Box<T, A> {
    fn clone(&self) -> Box<T, A> {
        Box {
            suite: self.suite.clone()
        }
    }
}


#[cfg(test)]
mod tests {
    use std::rand::{task_rng, Rng};

    use common::sbuf::{DefaultAllocator, SBuf};

    use noise::{mod, NoiseSuite, Noise414, Blob};


    #[test]
    fn test_blob() {
        let input_len = 8192u;
        let authtext_len_max = 512u;
        let authtext_len = task_rng().gen_range(0, authtext_len_max);
        let pad_len_max = 1024u;
        let pad_len = task_rng().gen_range(0, pad_len_max);

        // Generate keys.
        let noise414: Noise414<DefaultAllocator> = NoiseSuite::new();
        let key_size = noise414.key_size();
        let key = SBuf::<DefaultAllocator, u8>::new_rand(key_size);
        let nonce_size = noise414.nonce_size();
        let nonce = SBuf::<DefaultAllocator, u8>::new_rand(nonce_size);

        let mut blob_enc: Blob<Noise414<DefaultAllocator>, DefaultAllocator> =
            Blob::new();
        blob_enc.set_context(key[], nonce[]);

        let mut blob_dec: Blob<Noise414<DefaultAllocator>, DefaultAllocator> =
            Blob::new();
        blob_dec.set_context(key[], nonce[]);

        // Input data.
        let mut input: Vec<u8> = Vec::from_elem(input_len, 0);
        task_rng().fill_bytes(input[mut]);

        // Authtext data.
        let mut authtext: Vec<u8> = Vec::from_elem(authtext_len, 0);
        task_rng().fill_bytes(authtext[mut]);

        let enc_data = blob_enc.seal(pad_len,
                                     input[],
                                     Some(authtext[])).unwrap();

        let dec_data = blob_dec.open(enc_data[],
                                     Some(authtext[])).unwrap();

        assert!(input[] == dec_data[]);
        assert!(blob_enc.key == blob_dec.key);
        assert!(blob_enc.nonce == blob_dec.nonce);
    }

    #[test]
    fn test_box() {
        let input_len = task_rng().gen_range(0, 32768);;
        let authtext_len = task_rng().gen_range(0, 32768);;
        let pad_len = task_rng().gen_range(0, 1024);

        let nbox: noise::Box<Noise414<DefaultAllocator>, DefaultAllocator> =
            noise::Box::new();

        // Generate keys.
        let (eph_pubkey, eph_privkey) = nbox.keypair();
        let (sender_pubkey, sender_privkey) = nbox.keypair();
        let (recvr_pubkey, recvr_privkey) = nbox.keypair();

        // Input data.
        let mut input: Vec<u8> = Vec::from_elem(input_len, 0);
        task_rng().fill_bytes(input[mut]);

        // Authenticated additional data.
        let mut authtext: Vec<u8> = Vec::from_elem(authtext_len, 0);
        task_rng().fill_bytes(authtext[mut]);

        let (box_data, cv1) = nbox.seal(eph_privkey[],
                                        sender_pubkey[],
                                        sender_privkey[],
                                        recvr_pubkey[],
                                        0, pad_len, // fixme: s/0/pad_len/
                                        input[],
                                        Some(authtext[]),
                                        None,
                                        None).unwrap();

        let (sender_pubkey2, plaintext, cv2) =
            nbox.open(recvr_privkey[],
                      eph_pubkey[],
                      box_data[],
                      Some(authtext[]),
                      None,
                      None).unwrap();

        assert!(sender_pubkey[] == sender_pubkey2[]);
        assert!(input[] == plaintext[]);
        assert!(cv1[] == cv2[]);
    }
}
