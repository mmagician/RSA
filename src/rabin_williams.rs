use alloc::vec::Vec;
use digest::{Digest, FixedOutput};

use num_bigint::{BigUint, ToBigInt};
use num_integer::Integer;
use num_traits::FromPrimitive;
#[cfg(feature = "serde")]
use serde_crate::{Deserialize, Serialize};

use crate::errors::Result;
use crate::*;
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;

/// Default exponent for Rabin-Williams keys.
const EXP: u8 = 2;
type DigestResult = Vec<u8>;
pub struct RWSignature {
    s: DigestResult,
    // e: {-1, 1}
    e: i8,
    // f: {1, 2}
    f: u8,
}
pub trait SignRW<H: Digest + FixedOutput> {
    fn sign(&self, message: &[u8]) -> Result<RWSignature>;
    fn validate(&self) -> Result<()>;
}

pub trait VerifyRW<H: Digest + FixedOutput> {
    /// Verify a signed message.
    /// `message` must be the original, unhashed message.
    /// If the message is valid, `Ok(())` is returned, otherwiese an `Err` indicating failure.
    fn verify(&self, message: &[u8], sig: RWSignature) -> bool;
}

impl<H: Digest + FixedOutput> VerifyRW<H> for PublicKey {
    fn verify(&self, message: &[u8], signature: RWSignature) -> bool {
        let mut hasher = H::new();
        Digest::update(&mut hasher, message);
        let c = BigUint::from_bytes_le(&hasher.finalize()).mod_floor(&self.n);
        let x = BigUint::from_bytes_le(&signature.s);
        // if the same hash function is used, then the digest `c` should match whatever the signer produced
        // Calculate e*f*H(m), which should be a square mod n
        let h: BigUint = (c.to_bigint().unwrap() * signature.e * signature.f)
            .mod_floor(&self.n.to_bigint().unwrap())
            .to_biguint()
            .unwrap();
        h == x.modpow(&BigUint::from_u8(EXP).unwrap(), &self.n)
    }
}

impl<H: Digest + FixedOutput + digest::core_api::CoreProxy> SignRW<H> for PrivateKey {
    fn sign(&self, message: &[u8]) -> Result<RWSignature> {
        let mut hasher = H::new();
        Digest::update(&mut hasher, message);
        let digest = hasher.finalize().to_vec();
        let c = BigUint::from_bytes_le(&digest).mod_floor(&self.n);

        // calculate HMAC of `message` using `hmac_secret` as key.
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.hmac_secret).expect("Failed to initialise HMAC!");
        mac.update(message);
        let result = mac.finalize();

        // only need the first byte of the result
        let r: u8 = result.into_bytes()[0];

        let (s, e, f) = self.sqrt_mod_pq(&c, r);
        Ok(RWSignature {
            s: s.to_bytes_le(),
            e,
            f,
        })
    }

    fn validate(&self) -> Result<()> {
        Self::validate(self)?;
        for prime in &self.primes {
            // For a Rabin scheme, we require the primes to be == 3 mod 4
            assert_eq!(
                prime % BigUint::from_u64(4).unwrap(),
                BigUint::from_u64(3).unwrap()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::algorithms::generate_private_key;
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
            hmac_secret: [0u8; 8],
        };
        let public_key: PublicKey = private_key.to_public_key();

        assert_eq!(public_key.n.to_u64(), Some(100));
    }

    fn test_key_basics(private_key: &PrivateKey) {
        private_key.validate().expect("invalid private key");

        let _pub_key: PublicKey = private_key.to_public_key();
        let _m = vec![42];
    }

    #[test]
    fn test_signing() {
        // Alice computes her private key
        let p = BigUint::from_u8(11u8).unwrap();
        let q = BigUint::from_u8(7u8).unwrap();
        let n = p.clone() * q.clone();
        let hmac_secret = [0u8; 8];
        let private_key = PrivateKey {
            pubkey_components: PublicKey { n },
            primes: vec![p, q],
            hmac_secret,
        };
        assert!(SignRW::<Sha256>::validate(&private_key).is_ok());
        // And a public key for Bob
        let public_key: PublicKey = private_key.to_public_key();
        // Sign the message
        let message = String::from("fast verification scheme");
        let signature = SignRW::<Sha256>::sign(&private_key, message.as_bytes());
        assert!(VerifyRW::<Sha256>::verify(
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
                    let private_key = generate_private_key(&mut rng, $size).unwrap();
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
            assert!(generate_private_key(&mut rng, i).is_err());
        }
        assert!(generate_private_key(&mut rng, 13).is_ok());
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
}
