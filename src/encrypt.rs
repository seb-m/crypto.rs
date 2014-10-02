//! Encrypt traits
use std::c_str::CString;
use std::io::IoResult;


/// Trait for encryptable types
pub trait Encrypt<S> {
    /// Use the current key stream state provided by `stream` to encrypt the
    /// value of `Self` and put the result in `output`. `output` must be equal
    /// or larger in size to the size of the value submitted for encryption
    /// by `Self`.
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint>;

    /// Decrypt operation. See encrypt.
    fn decrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        self.encrypt(stream, output)
    }
}

impl<'a, S: CipherEncrypt> Encrypt<S> for &'a [u8] {
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        stream.encrypt(*self, output)
    }
}

impl<S: CipherEncrypt> Encrypt<S> for String {
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        stream.encrypt(self.as_bytes(), output)
    }
}

impl<'a, S: CipherEncrypt> Encrypt<S> for &'a str {
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        stream.encrypt(self.as_bytes(), output)
    }
}

impl<S: CipherEncrypt> Encrypt<S> for Vec<u8> {
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        stream.encrypt(self[], output)
    }
}

impl<S: CipherEncrypt> Encrypt<S> for CString {
    fn encrypt(&self, stream: &mut S, output: &mut [u8]) -> IoResult<uint> {
        stream.encrypt(self.as_bytes_no_nul(), output)
    }
}


/// Trait for ciphers implementing encrypt/decrypt operations
pub trait CipherEncrypt {
    /// Encrypt `input` and put the result in `output`. The size of
    /// `output` must at least be of the size of `input` or more
    /// depending on the underlying mode of operations used. Return the
    /// number of encrypted bytes written in `output` or `Err` on error.
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> IoResult<uint>;

    /// Decrypt `input` and put the result in `output`. The size of
    /// `output` must at least be of the size of `input`. Return the
    /// number of decrypted bytes written in `output` or `Err` on error.
    fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> IoResult<uint> {
        self.encrypt(input, output)
    }
}


/// Encrypter
pub trait Encrypter<S> {
    /// Encrypt the encryptable `value` and put the result in `output`.
    /// The size of `output` must at least be of the size of `input`.
    /// Return the number of encrypted bytes written to `output`.
    fn encrypt<T: Encrypt<S>>(&mut self,
                              value: &T, output: &mut [u8]) -> IoResult<uint>;

    /// Decrypt `value` in `output`. See encrypt operation.
    fn decrypt<T: Encrypt<S>>(&mut self,
                              value: &T, output: &mut [u8]) -> IoResult<uint> {
        self.encrypt(value, output)
    }
}
