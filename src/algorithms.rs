use alloc::vec;

use num_bigint::{BigUint, RandPrime};
#[allow(unused_imports)]
use num_traits::Float;
use num_traits::{One, Zero};
use rand::Rng;

use crate::errors::{Error, Result};
use crate::key::RsaPrivateKey;

/// Default exponent for RSA keys.
const EXP: u64 = 2;
const N_PRIMES: usize = 2;

/// Generates a multi-prime RSA keypair of the given bit size, public exponent,
/// and the given random source, as suggested in [1]. Although the public
/// keys are compatible (actually, indistinguishable) from the 2-prime case,
/// the private keys are not. Thus it may not be possible to export multi-prime
/// private keys in certain formats or to subsequently import them into other
/// code.
///
/// Table 1 in [2] suggests maximum numbers of primes for a given size.
///
/// [1] US patent 4405829 (1972, expired)
/// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub fn generate_multi_prime_key_with_exp<R: Rng>(
    rng: &mut R,
    bit_size: usize,
) -> Result<RsaPrivateKey> {
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
            *prime = rng.gen_prime(todo / (N_PRIMES - i));
            todo -= prime.bits();
        }

        // Makes sure that primes is pairwise unequal.
        for (i, prime1) in primes.iter().enumerate() {
            for prime2 in primes.iter().take(i) {
                if prime1 == prime2 {
                    continue 'next;
                }
            }
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

    Ok(RsaPrivateKey::from_components(n_final, primes))
}
