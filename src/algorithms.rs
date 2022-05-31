use alloc::vec;
use alloc::vec::Vec;

use digest::DynDigest;
use num_bigint::{BigUint, RandPrime};
#[allow(unused_imports)]
use num_traits::Float;
use num_traits::{One, Zero};
use rand::Rng;
use sha2::Sha512;

use crate::errors::{Error, Result};
use crate::key::{DigestResult, HmacSecret, PrivateKey};
use crate::PublicKey;

const N_PRIMES: usize = 2;

/// Generates a 2-prime Rabin-Williams PrivateKey of the given bit size
/// and the given random source.
///
/// This method was inspired by the RSA
/// implementation of `generate_multi_prime_key_with_exp` in [1].
///
/// [1]: https://github.com/RustCrypto/RSA/blob/4b8fa4fb679fbf83a4ef0c19e62ef5d5b7b47715/src/algorithms.rs#L51
pub fn generate_private_key<R: Rng>(rng: &mut R, bit_size: usize) -> Result<PrivateKey> {
    if bit_size < 64 {
        let prime_limit = (1u64 << (bit_size / N_PRIMES) as u64) as f64;

        // pi aproximates the number of primes less than prime_limit
        let mut pi = prime_limit / (prime_limit.ln() - 1f64);
        // Generated primes start with 0b11, so we can only use a quarter of them.
        pi /= 4f64;
        // Use a factor of two to ensure taht key generation terminates in a
        // reasonable amount of time.
        pi /= 2f64;

        if pi < N_PRIMES as f64 {
            return Err(Error::TooSmallBitSize);
        }
    }
    let mut primes = vec![BigUint::zero(); N_PRIMES as usize];
    let n_final: BigUint;
    let three: BigUint = BigUint::from(3u8);
    let seven: BigUint = BigUint::from(7u8);
    let eight: BigUint = BigUint::from(8u8);

    'next: loop {
        let mut todo = bit_size;
        // `gen_prime` should set the top two bits in each prime.
        // Thus each prime has the form
        //   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
        // And the product is:
        //   P = 2^todo × α
        // where α is the product of nprimes numbers of the form 0.11...
        //
        // If α < 1/2 (which can happen for nprimes > 2), we need to
        // shift todo to compensate for lost bits: the mean value of 0.11...
        // is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
        // will give good results.
        for (i, prime) in primes.iter_mut().enumerate() {
            let mut tmp;
            loop {
                tmp = rng.gen_prime(todo / (N_PRIMES - i));
                // first prime should be 3 mod 8
                if i == 0 {
                    if &tmp % &eight == three {
                        break;
                    }
                }
                // second prime should be 7 mod 8
                else if &tmp % &eight == seven {
                    break;
                }
            }
            *prime = tmp;
            todo -= prime.bits();
        }

        // Makes sure that primes are unequal.
        if primes[0] == primes[1] {
            continue 'next;
        }

        let mut n = BigUint::one();
        for prime in &primes {
            n *= prime;
        }

        if n.bits() != bit_size {
            // This should never happen for nprimes == 2 because
            // gen_prime should set the top two bits in each prime.
            continue 'next;
        } else {
            n_final = n;
            break;
        }
    }
    let hmac_secret: HmacSecret = rng.gen();

    Ok(PrivateKey::from_components(n_final, primes, hmac_secret))
}

pub(crate) fn calculate_tweak_factors(mut a: bool, b: bool) -> (i8, u8) {
    let mut e: i8 = 1;
    let mut f: u8 = 1;

    if a ^ b {
        f = 2;
        a ^= true;
    }
    if !a {
        e = -1
    }
    (e, f)
}

struct ExpanderXmd<T: DynDigest + Clone> {
    pub(super) hasher: T,
}

impl<T: DynDigest + Clone> ExpanderXmd<T> {
    fn expand(&self, msg: &[u8], output_size: usize) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        // output size of the hash function, e.g. 64 bytes = 512 bits for sha2::512
        let b_len = hasher.output_size();
        // number of iterations that we need to fill the output_size with hashed bytes,
        // e.g. for output_size = 1024 and sha512, we'd need 2 iterations, while for
        // 1025 we need a 3rd one (which later gets truncated from 1536 to 1025)
        let ell = (output_size + (b_len - 1)) / b_len;
        assert!(
            ell <= 255,
            "The ratio of desired output to the output size of hash function is too large!"
        );

        // The program should abort if integer that we're trying to convert is too
        // large.
        assert!(
            output_size < (1 << 16),
            "Length should be smaller than 2^16"
        );

        let mut uniform_bytes: Vec<u8> = Vec::new();

        hasher.update(msg);
        hasher.update(&[0u8]);
        let h_0 = hasher.finalize_reset();
        uniform_bytes.extend_from_slice(&h_0);

        let mut h_i = h_0;

        for i in 1..=ell {
            // update the hasher with xor of b_0 and b_i elements
            hasher.update(&h_i);
            hasher.update(&[i as u8]);
            h_i = hasher.finalize_reset();
            uniform_bytes.extend_from_slice(&h_i);
        }
        uniform_bytes[0..output_size].to_vec()
    }
}

pub(crate) fn hash(msg: &[u8]) -> Vec<u8> {
    let expander = ExpanderXmd {
        hasher: Sha512::default(),
    };
    expander.expand(msg, 1024)
}

pub(crate) fn compress_signature(
    uncompressed_signature: BigUint,
    pk: &PublicKey,
) -> BigUint {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use crate::algorithms::calculate_tweak_factors;

    #[test]
    fn test_e_f() {
        assert_eq!(calculate_tweak_factors(true, true), (1, 1));
        assert_eq!(calculate_tweak_factors(false, false), (-1, 1));
        assert_eq!(calculate_tweak_factors(false, true), (1, 2));
        assert_eq!(calculate_tweak_factors(true, false), (-1, 2));
    }
}
