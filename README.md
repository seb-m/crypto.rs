# Rust Crypto Primitives

## Update 12/17/2014

Code is currently broken, it should be updated and refactored to use [TARS](https://github.com/seb-m/tars) and the latest Rust awesomeness.

## Description

A selection of crypto primitives implemented in pure-[Rust](http://www.rust-lang.org/). This code is experimental, don't use it for anything real.


## Crypto primitives

Currently implemented:

* [Curve41417](http://safecurves.cr.yp.to/)
* [Chacha20](http://cr.yp.to/chacha.html)
* [Poly1305](http://cr.yp.to/mac.html)
* [Chacha20-Poly1305 AEAD](http://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01)
* [Sha3](http://csrc.nist.gov/groups/ST/hash/sha-3/sha-3_standardization.html) (Draft FIPS 202) and [XKdf](http://csrc.nist.gov/groups/ST/hash/sha-3/Aug2014/documents/perlner_kmac.pdf)


## Building from source

Install Rust package manager [Cargo](https://github.com/rust-lang/cargo).

* Build as library:

```
$ cargo build
```

* Run tests and build documentation:

```
$ cargo test
$ cargo doc   # Build documentation under target/doc/
```


## Documentation

The generated documentation is also available [here](http://www.rust-ci.org/seb-m/crypto.rs/doc/crypto/).


## License

This code is distributed under the terms of both the MIT license and the Apache License (Version 2.0).
