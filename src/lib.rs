//! Selection of crypto primitives in pure-Rust
#![crate_name = "crypto"]
#![comment = "A selection of pure-Rust crypto primitives"]
#![license = "MIT/ASL2"]
#![experimental]  // Stability
#![doc(html_logo_url = "http://www.rust-lang.org/logos/rust-logo-128x128-blk.png",
       html_favicon_url = "http://www.rust-lang.org/favicon.ico",
       html_root_url = "http://doc.rust-lang.org/")]

#![feature(macro_rules)]
#![feature(unsafe_destructor)]
#![feature(default_type_params)]
#![feature(slicing_syntax)]
#![feature(phase)]

#[cfg(test)] extern crate test;
#[cfg(test)] #[phase(plugin, link)] extern crate log;

extern crate serialize;

#[phase(plugin, link)]
extern crate common;
extern crate "curve41417" as crv_curve41417;

// Reexport modules
pub use common::sbuf;
pub use common::utils;

/// [Curve41417](http://safecurves.cr.yp.to/) elliptic curve
pub mod curve41417 {
    pub use crv_curve41417::{POINT_SIZE, SCALAR_SIZE};
    pub use crv_curve41417::bytes;
    pub use crv_curve41417::ed;
    pub use crv_curve41417::mont;
    pub use crv_curve41417::sc;
}

// Common traits
pub mod encrypt;
pub mod hash;

// Crypto modules
pub mod chacha20;
pub mod poly1305;
pub mod sha3;
pub mod kdf;
pub mod noise;
pub mod eke;
