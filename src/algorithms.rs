use alloc::vec;
use alloc::vec::Vec;

use digest::DynDigest;
use num_bigint::{BigUint, RandPrime};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;
use sha2::Sha512;

use crate::errors::{Error, Result};
use crate::key::{HmacSecret, PrivateKey};

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

#[must_use]
pub(crate) fn compress_signature(s: BigUint, n: &BigUint) -> BigUint {
    // assert that n, s are co-prime
    assert!(n.gcd(&s).is_one(), "n and s are not co-prime!");

    // we'll return the largest denominator of principal convergent of s/n that is
    // less than sqrt(n)
    let root_n = n.clone().sqrt();

    let mut v_previous: BigUint = BigUint::from(0u8);
    let mut v_current: BigUint = BigUint::from(1u8);
    let mut v_next: BigUint;
    let mut s_current: BigUint = s;
    let mut n_current: BigUint = n.clone();
    let mut alpha: BigUint;
    let mut tmp: BigUint;
    loop {
        (alpha, tmp) = n_current.div_mod_floor(&s_current);
        // tmp = n_current % &s_current;
        // compute the next denominator
        v_next = &v_current * &alpha + &v_previous;
        // break when v_next is larger than root_n
        if v_next > root_n {
            return v_current;
        }
        v_previous = v_current;
        v_current = v_next;
        n_current = s_current;
        s_current = tmp;
    }
}

/// Verify whether the passed compressed signature `v` is valid
pub fn verify_compressed_signature(v: &BigUint, h: &BigUint, n: &BigUint) -> bool {
    decompress_signature(v, h, n).is_ok()
}

/// Decompress a signature and return sqrt(t), if found
fn decompress_signature(v: &BigUint, h: &BigUint, n: &BigUint) -> Result<BigUint> {
    let t = (h * v * v).mod_floor(n);
    // assert that t mod n is not zero
    if t.is_zero() {
        return Err(Error::Verification);
    }
    let t_sqrt = t.sqrt();
    // assert that t is a perfect square
    if &t_sqrt * &t_sqrt != t {
        return Err(Error::Verification);
    }
    // likely only going to use the output for sanity checks
    Ok(t_sqrt)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_bigint::ModInverse;
    use num_integer::Integer;
    use num_traits::FromPrimitive;

    use crate::algorithms::calculate_tweak_factors;
    use crate::algorithms::compress_signature;
    use crate::algorithms::decompress_signature;
    use crate::errors::Error;

    #[test]
    fn test_e_f() {
        assert_eq!(calculate_tweak_factors(true, true), (1, 1));
        assert_eq!(calculate_tweak_factors(false, false), (-1, 1));
        assert_eq!(calculate_tweak_factors(false, true), (1, 2));
        assert_eq!(calculate_tweak_factors(true, false), (-1, 2));
    }

    #[test]
    fn test_compress_signature() {
        let n = BigUint::from_u8(77u8).unwrap();
        let s = BigUint::from_u8(25u8).unwrap();

        assert_eq!(compress_signature(s, &n), BigUint::from_u8(3u8).unwrap());
    }

    #[test]
    #[allow(unused)]
    #[should_panic(expected = "")]
    fn test_compress_signature_zero_should_fail() {
        let n = BigUint::from_u8(77u8).unwrap();
        let s = BigUint::from_u8(0u8).unwrap();

        compress_signature(s, &n);
    }

    #[test]
    #[allow(unused)]
    #[should_panic(expected = "n and s are not co-prime!")]
    fn test_compress_signature_coprime_should_fail() {
        let n = BigUint::from_u8(77u8).unwrap();
        let s = BigUint::from_u8(7u8).unwrap();

        compress_signature(s, &n);
    }

    #[test]
    fn test_decompress_signature() {
        let n = BigUint::from_u8(77u8).unwrap();
        let h = BigUint::from_u8(9u8).unwrap();
        let v = BigUint::from_u8(3u8).unwrap();

        let expected_signature = BigUint::from_u8(25u8).unwrap();
        let sqrt_t = decompress_signature(&v, &h, &n).unwrap();
        // sanity check
        let computed_signature = (&sqrt_t
            * (&v
                .mod_inverse(&n)
                .expect("no multiplicative inverse for sqrt(t)")
                .to_biguint()
                .expect("Failed to cast back to BigUint")))
            .mod_floor(&n);
        // it only makes sense to compare squares
        assert_eq!(
            (&computed_signature * &computed_signature).mod_floor(&n),
            (&expected_signature * &expected_signature).mod_floor(&n)
        );
    }

    #[test]
    #[allow(unused)]
    fn test_decompress_signature_zero_should_fail() {
        let n = BigUint::from_u8(77u8).unwrap();
        let h = BigUint::from_u8(9u8).unwrap();
        let v = BigUint::from_u8(0u8).unwrap();

        assert_eq!(decompress_signature(&v, &h, &n), Err(Error::Verification));
    }
}
