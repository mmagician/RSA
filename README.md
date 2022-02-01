# Rabin-Williams signatures

<!-- [![crates.io][crate-image]][crate-link]
[![Documentation][doc-image]][doc-link]
[![Build Status][build-image]][build-link]
![minimum rustc 1.56][msrv-image]
[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link] -->

A portable Rabin-Williams signature scheme implementation in pure Rust.

⚠️ **WARNING:** This crate has NOT been audited by a 3rd party and is a work-in-progress. Use at your own risk.

## Example

```rust
use rsa::{VerifyRabin, PrivateKey, SignRabin, KeyType, generate_multi_prime_key_with_exp};
use sha2::Sha256;
use rand::rngs::OsRng;

let mut rng = OsRng;
let bits = 1024;
let private_key = generate_multi_prime_key_with_exp(&mut rng, bits, KeyType::Rabin).expect("failed to generate a key");
let public_key = private_key.to_public_key();

// Signature
let message = String::from("fast verification scheme");
let signature = SignRabin::<Sha256>::sign(&private_key, message.as_bytes());

// Verification
assert!(VerifyRabin::<Sha256>::verify(
    &public_key,
    message.as_bytes(),
    signature.unwrap()
));
```
<!-- 
> **Note:** If you encounter unusually slow key generation time while using `RWPrivateKey::new` you can try to compile in release mode or add the following to your `Cargo.toml`. Key generation is much faster when building with higher optimization levels, but this will increase the compile time a bit.
> ```toml
> [profile.debug]
> opt-level = 3
> ```
> If you don't want to turn on optimizations for all dependencies,
> you can only optimize the `num-bigint-dig` dependency. This should
> give most of the speedups.
> ```toml
> [profile.dev.package.num-bigint-dig]
> opt-level = 3
> ``` -->

## Status

Currently at Phase 1 (v) 🚧

There will be three phases before `1.0` 🚢 can be released.

1. 🚧  Make it work
    - [x] Prime generation: Rabin ✅
    - [ ] Prime generation: Rabin-Williams scheme ✅
    - [x] Key generation ✅
    - [x] Rabin: Sign & Verify
    - [ ] Rabin-Williams: Sign & Verify
    - [ ] Key import & export
2. 🚀 Make it fast
    - [ ] Benchmarks ✅
    - [ ] compare to other implementations 🚧
    - [ ] optimize 🚧
3. 🔐 Make it secure
    - [ ] Fuzz testing
    - [ ] Security Audits

## Minimum Supported Rust Version (MSRV)

All crates in this repository support Rust 1.56 or higher. In future
minimally supported version of Rust can be changed, but it will be done with
a minor version bump.

## License

Licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

<!-- [//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rsa.svg
[crate-link]: https://crates.io/crates/rsa
[doc-image]: https://docs.rs/rsa/badge.svg
[doc-link]: https://docs.rs/rsa
[build-image]: https://github.com/rustcrypto/RSA/workflows/CI/badge.svg
[build-link]: https://github.com/RustCrypto/RSA/actions?query=workflow%3ACI+branch%3Amaster
[msrv-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260047-RSA
[deps-image]: https://deps.rs/repo/github/RustCrypto/RSA/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/RSA -->
