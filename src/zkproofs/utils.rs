use std::borrow::Borrow;

use curv::arithmetic::traits::*;
use curv::BigInt;

use digest::Digest;
use sha2::Sha256;
use paillier::{DecryptionKey, EncryptionKey, KeyGeneration, Paillier};

pub fn compute_digest<IT>(it: IT) -> BigInt
where
    IT: Iterator,
    IT::Item: Borrow<BigInt>,
{
    let mut hasher = Sha256::new();
    for value in it {
        let bytes: Vec<u8> = value.borrow().to_bytes();
        hasher.update(&bytes);
    }

    let result_bytes = hasher.finalize();
    BigInt::from_bytes(&result_bytes[..])
}

pub fn sample_paillier_random(modulo: &BigInt) -> BigInt {
    let mut r_a = BigInt::sample_below(modulo);
    while BigInt::gcd(&r_a, modulo) != BigInt::one() {
        r_a = BigInt::sample_below(modulo);
    }
    r_a
}

pub fn gen_keys() -> EncryptionKey {
    let (ek, _) = Paillier::keypair().keys();
    ek
}

pub fn gen_keys_keypair() -> (EncryptionKey, DecryptionKey) {
    let (ek, sk) = Paillier::keypair_safe_primes().keys();
    (ek,sk)
}