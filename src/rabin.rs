use alloc::vec::Vec;
use digest::{Digest, FixedOutput, FixedOutputReset};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::FromPrimitive;
use rand::{thread_rng, Rng};
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

use crate::errors::Result;
use crate::*;

const RANDOMIZER_BYTES: usize = 1;
/// Default exponent for RSA keys.
const EXP: u8 = 2;
type DigestResult = Vec<u8>;
type Randomiser = [u8; RANDOMIZER_BYTES];
pub struct Signature {
    s: DigestResult,
    u: Randomiser,
}
pub trait SignRabin<H: Digest + FixedOutputReset> {
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}

pub trait VerifyRabin<H: Digest + FixedOutput> {
    /// Verify a signed message.
    /// `message` must be the original, unhashed message.
    /// If the message is valid, `Ok(())` is returned, otherwiese an `Err` indicating failure.
    fn verify(&self, message: &[u8], sig: Signature) -> bool;
}

impl<H: Digest + FixedOutput> VerifyRabin<H> for PublicKey {
    fn verify(&self, message: &[u8], signature: Signature) -> bool {
        let mut hasher = H::new();
        Digest::update(&mut hasher, message);
        Digest::update(&mut hasher, signature.u);
        // if the same hash function is used, then the digest `c` should match whatever the signer produced
        let c = BigUint::from_bytes_le(&hasher.finalize()).mod_floor(&self.n);
        let x = BigUint::from_bytes_le(&signature.s);
        c == x.modpow(&BigUint::from_u8(EXP).unwrap(), &self.n)
    }
}

impl<H: Digest + FixedOutputReset> SignRabin<H> for PrivateKey {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let mut rng = thread_rng();
        let mut digest;
        let mut hasher = H::new();
        let mut u: [u8; RANDOMIZER_BYTES];
        // try different randomisers `u` until we find one that satisifes
        // H(m, u) == x^2
        // for some x
        let s;
        loop {
            u = rng.gen();
            Digest::update(&mut hasher, message);
            Digest::update(&mut hasher, &u);
            digest = hasher.finalize_reset().to_vec();
            // if the current digest is a valid Quadratic Residue
            // return the sqrt
            // Otherwise, try another u
            let c = BigUint::from_bytes_le(&digest).mod_floor(&self.n);
            match self.sqrt_mod_n(&c) {
                Ok(sqrt) => {
                    s = sqrt;
                    break;
                }
                _ => continue,
            }
        }
        Ok(Signature {
            s: s.to_bytes_le(),
            u,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::algorithms::generate_multi_prime_key_with_exp;
    use num_traits::{FromPrimitive, ToPrimitive};
    use rand::{rngs::StdRng, SeedableRng};
    use sha2::Sha256;

    use std::time::SystemTime;

    #[test]
    fn test_from_into() {
        let private_key = PrivateKey {
            pubkey_components: PublicKey {
                n: BigUint::from_u64(100).unwrap(),
            },
            primes: vec![],
        };
        let public_key: PublicKey = private_key.to_public_key();

        assert_eq!(public_key.n.to_u64(), Some(100));
    }

    fn test_key_basics(private_key: &PrivateKey) {
        private_key.validate().expect("invalid private key");

        let _pub_key: PublicKey = private_key.to_public_key();
        let _m = vec![42];
        // let signature = private_key.sign(&m).unwrap();
        // assert!(pub_key.verify(&m, &signature).is_err());
        // assert!(pub_key.verify(&m, &signature).is_ok());
    }

    #[test]
    fn test_signing() {
        // Alice computes her private key
        let p = BigUint::from_u8(7u8).unwrap();
        let q = BigUint::from_u8(11u8).unwrap();
        let n = p.clone() * q.clone();
        let private_key = PrivateKey {
            pubkey_components: PublicKey { n },
            primes: vec![p, q],
        };
        // And a public key for Bob
        let public_key: PublicKey = private_key.to_public_key();
        // Sign the message
        let message = String::from("fast verification scheme");
        let signature = SignRabin::<Sha256>::sign(&private_key, message.as_bytes());
        assert!(VerifyRabin::<Sha256>::verify(
            &public_key,
            message.as_bytes(),
            signature.unwrap()
        ));
    }

    macro_rules! key_generation {
        ($name:ident,  $size:expr) => {
            #[test]
            fn $name() {
                let seed = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                let mut rng = StdRng::seed_from_u64(seed.as_secs());

                for _ in 0..10 {
                    let private_key = generate_multi_prime_key_with_exp(&mut rng, $size).unwrap();
                    assert_eq!(private_key.n.bits(), $size);

                    test_key_basics(&private_key);
                }
            }
        };
    }

    key_generation!(key_generation_128, 128);
    // key_generation!(key_generation_1024, 1024);

    // key_generation!(key_generation_multi_3_256, 256);

    key_generation!(key_generation_multi_4_64, 64);

    key_generation!(key_generation_multi_5_64, 64);
    // key_generation!(key_generation_multi_8_576, 576);
    // key_generation!(key_generation_multi_16_1024, 1024);

    #[test]
    fn test_impossible_keys() {
        // make sure not infinite loops are hit here.
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let mut rng = StdRng::seed_from_u64(seed.as_secs());
        for i in 0..12 {
            assert!(PrivateKey::new(&mut rng, i).is_err());
        }
        assert!(PrivateKey::new(&mut rng, 13).is_ok());
    }

    #[test]
    #[cfg(feature = "serde1")]
    fn test_serde() {
        use rand::SeedableRng;
        use rand_xorshift::XorShiftRng;
        use serde_test::{assert_tokens, Token};

        let mut rng = XorShiftRng::from_seed([1; 16]);
        let priv_key = PrivateKey::new(&mut rng, 64).expect("failed to generate key");

        let priv_tokens = [
            Token::Struct {
                name: "RsaPrivateKey",
                len: 3,
            },
            Token::Str("pubkey_components"),
            Token::Struct {
                name: "RsaPublicKey",
                len: 2,
            },
            Token::Str("n"),
            Token::Seq { len: Some(2) },
            Token::U32(1296829443),
            Token::U32(2444363981),
            Token::SeqEnd,
            Token::Str("e"),
            Token::Seq { len: Some(1) },
            Token::U32(65537),
            Token::SeqEnd,
            Token::StructEnd,
            Token::Str("d"),
            Token::Seq { len: Some(2) },
            Token::U32(298985985),
            Token::U32(2349628418),
            Token::SeqEnd,
            Token::Str("primes"),
            Token::Seq { len: Some(2) },
            Token::Seq { len: Some(1) },
            Token::U32(3238068481),
            Token::SeqEnd,
            Token::Seq { len: Some(1) },
            Token::U32(3242199299),
            Token::SeqEnd,
            Token::SeqEnd,
            Token::StructEnd,
        ];
        assert_tokens(&priv_key, &priv_tokens);

        let priv_tokens = [
            Token::Struct {
                name: "RsaPublicKey",
                len: 2,
            },
            Token::Str("n"),
            Token::Seq { len: Some(2) },
            Token::U32(1296829443),
            Token::U32(2444363981),
            Token::SeqEnd,
            Token::Str("e"),
            Token::Seq { len: Some(1) },
            Token::U32(65537),
            Token::SeqEnd,
            Token::StructEnd,
        ];
        assert_tokens(&PublicKey::from(priv_key), &priv_tokens);
    }

    #[test]
    fn invalid_coeff_private_key_regression() {
        let n = base64::decode("wC8GyQvTCZOK+iiBR5fGQCmzRCTWX9TQ3aRG5gGFk0wB6EFoLMAyEEqeG3gS8xhAm2rSWYx9kKufvNat3iWlbSRVqkcbpVAYlj2vTrpqDpJl+6u+zxFYoUEBevlJJkAhl8EuCccOA30fVpcfRvXPTtvRd3yFT9E9EwZljtgSI02w7gZwg7VIxaGeajh5Euz6ZVQZ+qNRKgXrRC7gPRqVyI6Dt0Jc+Su5KBGNn0QcPDzOahWha1ieaeMkFisZ9mdpsJoZ4tw5eicLaUomKzALHXQVt+/rcZSrCd6/7uUo11B/CYBM4UfSpwXaL88J9AE6A5++no9hmJzaF2LLp+Qwx4yY3j9TDutxSAjsraxxJOGZ3XyA9nG++Ybt3cxZ5fP7ROjxCfROBmVv5dYn0O9OBIqYeCH6QraNpZMadlLNIhyMv8Y+P3r5l/PaK4VJaEi5pPosnEPawp0W0yZDzmjk2z1LthaRx0aZVrAjlH0Rb/6goLUQ9qu1xsDtQVVpN4A89ZUmtTWORnnJr0+595eHHxssd2gpzqf4bPjNITdAEuOCCtpvyi4ls23zwuzryUYjcUOEnsXNQ+DrZpLKxdtsD/qNV/j1hfeyBoPllC3cV+6bcGOFcVGbjYqb+Kw1b0+jL69RSKQqgmS+qYqr8c48nDRxyq3QXhR8qtzUwBFSLVk=").unwrap();
        let primes = vec![
            base64::decode("9kQWEAzsbzOcdPa+s5wFfw4XDd7bB1q9foZ31b1+TNjGNxbSBCFlDF1q98vwpV6nM8bWDh/wtbNoETSQDgpEnYOQ26LWEw6YY1+q1Q2GGEFceYUf+Myk8/vTc8TN6Zw0bKZBWy10Qo8h7xk4JpzuI7NcxvjJYTkS9aErFxi3vVH0aiZC0tmfaCqr8a2rJxyVwqreRpOjwAWrotMsf2wGsF4ofx5ScoFy5GB5fJkkdOrW1LyTvZAUCX3cstPr19+TNC5zZOk7WzZatnCkN5H5WzalWtZuu0oVL205KPOa3R8V2yv5e6fm0v5fTmqSuvjmaMJLXCN4QJkmIzojO99ckQ==").unwrap(),
            base64::decode("x8exdMjVA2CiI+Thx7loHtVcevoeE2sZ7btRVAvmBqo+lkHwxb7FHRnWvuj6eJSlD2f0T50EewIhhiW3R9BmktCk7hXjbSCnC1u9Oxc1IAUm/7azRqyfCMx43XhLxpD+xkBCpWkKDLxGczsRwTuaP3lKS3bSdBrNlGmdblubvVBIq4YZ2vXVlnYtza0cS+dgCK7BGTqUsrCUd/ZbIvwcwZkZtpkhj1KQfto9X/0OMurBzAqbkeq1cyRHXHkOfN/qbUIIRqr9Ii7Eswf9Vk8xp2O1Nt8nzcYS9PFD12M5eyaeFEkEYfpNMNGuTzp/31oqVjbpoCxS6vuWAZyADxhISQ==").unwrap(),
            base64::decode("is7d0LY4HoXszlC2NO7gejkq7XqL4p1W6hZJPYTNx+r37t1CC2n3Vvzg6kNdpRixDhIpXVTLjN9O7UO/XuqSumYKJIKoP52eb4Tg+a3hw5Iz2Zsb5lUTNSLgkQSBPAf71LHxbL82JL4g1nBUog8ae60BwnVArThKY4EwlJguGNw09BAU4lwf6csDl/nX2vfVwiAloYpeZkHL+L8m+bueGZM5KE2jEz+7ztZCI+T+E5i69rZEYDjx0lfLKlEhQlCW3HbCPELqXgNJJkRfi6MP9kXa9lSfnZmoT081RMvqonB/FUa4HOcKyCrw9XZEtnbNCIdbitfDVEX+pSSD7596wQ==").unwrap(),
            base64::decode("GPs0injugfycacaeIP5jMa/WX55VEnKLDHom4k6WlfDF4L4gIGoJdekcPEUfxOI5faKvHyFwRP1wObkPoRBDM0qZxRfBl4zEtpvjHrd5MibSyJkM8+J0BIKk/nSjbRIGeb3hV5O56PvGB3S0dKhCUnuVObiC+ne7izplsD4OTG70l1Yud33UFntyoMxrxGYLUSqhBMmZfHquJg4NOWOzKNY/K+EcHDLj1Kjvkcgv9Vf7ocsVxvpFdD9uGPceQ6kwRDdEl6mb+6FDgWuXVyqR9+904oanEIkbJ7vfkthagLbEf57dyG6nJlqh5FBZWxGIR72YGypPuAh7qnnqXXjY2Q==").unwrap(),
            base64::decode("CUWC+hRWOT421kwRllgVjy6FYv6jQUcgDNHeAiYZnf5HjS9iK2ki7v8G5dL/0f+Yf+NhE/4q8w4m8go51hACrVpP1p8GJDjiT09+RsOzITsHwl+ceEKoe56ZW6iDHBLlrNw5/MtcYhKpjNU9KJ2udm5J/c9iislcjgckrZG2IB8ADgXHMEByZ5DgaMl4AKZ1Gx8/q6KftTvmOT5rNTMLi76VN5KWQcDWK/DqXiOiZHM7Nr4dX4me3XeRgABJyNR8Fqxj3N1+HrYLe/zs7LOaK0++F9Ul3tLelhrhsvLxei3oCZkF9A/foD3on3luYA+1cRcxWpSY3h2J4/22+yo4+Q==").unwrap(),
        ];

        PrivateKey::from_components(
            BigUint::from_bytes_be(&n),
            primes.iter().map(|p| BigUint::from_bytes_be(p)).collect(),
        );
    }
}
