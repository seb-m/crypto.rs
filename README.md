# Rust Crypto Primitives

## Description

A selection of crypto primitives implemented in pure-[Rust](http://www.rust-lang.org/).


## Crypto primitives

Currently implemented:

* [Curve41417](http://safecurves.cr.yp.to/)
* [Chacha20](http://cr.yp.to/chacha.html)
* [Poly1305](http://cr.yp.to/mac.html)
* [Sha3](http://csrc.nist.gov/groups/ST/hash/sha-3/sha-3_standardization.html) (draft fips 202)


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

The generated documentation is also available [here](http://seb.dbzteam.org/crypto.rs/crypto/).


## License

This code is distributed under the terms of both the MIT license and the Apache License (Version 2.0).
