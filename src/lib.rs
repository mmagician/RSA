#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

#[cfg(not(feature = "alloc"))]
compile_error!("This crate does not yet support environments without liballoc. See https://github.com/RustCrypto/RSA/issues/51.");

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
pub use num_bigint::BigUint;

/// Useful algorithms.
#[cfg(feature = "alloc")]
pub mod algorithms;

/// Error types.
#[cfg(feature = "alloc")]
pub mod errors;

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
mod key;
mod rabin;

#[cfg(feature = "alloc")]
// pub use self::key::{PrivateKey, PublicKey, Sign, Verify};
pub use self::key::{PrivateKey, PublicKey};
pub use self::rabin::*;

#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
