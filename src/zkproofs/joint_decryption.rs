use std::borrow::{Borrow, Cow};
use std::ops::Div;

use crate::zkproofs::utils::*;
use curv::arithmetic::traits::*;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use paillier::{EncryptionKey, DecryptionKey, Paillier, KeyGeneration, Keypair, RawCiphertext, RawPlaintext};
use curv::arithmetic::traits::*;
use curv::BigInt;
use crate::zkproofs::traits::*;
use crate::zkproofs::array::*;
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::*;

use rayon::prelude::*; // parallelization
//[DONE: ADD PLAINTEXT CIPHERTEXT MULTIPLICATION PROOF IN PARTIAL DECRYPTION]

/// Public encryption key.
pub struct EncryptionKeyJoint {
    pub n: BigInt,
    pub nn: BigInt,
    pub theta: BigInt,
}

pub struct DecryptionKeyJoint {
    pub sk: BigInt,
    pub beta: BigInt,
}

pub struct NumParties{
    pub m:usize,
}    


// derive encryption key from joint encryption key to use the encryption method for paillier
impl<'e> From<&'e EncryptionKeyJoint> for EncryptionKey {
    fn from(ekj: &'e EncryptionKeyJoint) -> Self {
        let nn = ekj.nn.clone();
        let n = ekj.n.clone();
        EncryptionKey { n, nn }
    }
}

/// Private shared decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKeyShared {
    pub dks: Vec<BigInt>, // vector of key sharings
}

impl<'c, 'm> DecryptJoint<EncryptionKeyJoint, DecryptionKeyShared, NumParties, &'c RawCiphertext<'c>, RawPlaintext<'m>> for Paillier {
    fn joint_decrypt(ek: &EncryptionKeyJoint, dk: &DecryptionKeyShared, p: &NumParties, c: &'c RawCiphertext<'c>) -> RawPlaintext<'m> {
        //each party computes their partial dec
        let ciphertext = c.clone().0.into_owned();
        let mut partial_c: Vec<BigInt> = vec![BigInt::from(0); p.m];
        let mut dec_c: BigInt = BigInt::from(1);
        //prover
        let r_c : Vec<BigInt> = vec![BigInt::from(1); p.m];
        let r_b = ArrayPaillier::gen_array_randomness(p.m, &EncryptionKey::from(ek));
        let e_b = ArrayPaillier::encrypt_array(&dk.dks, &r_b, &EncryptionKey::from(ek));
        for i in 0..p.m{
            // ci = c^{sk_i}
            let ci = BigInt::mod_pow(&ciphertext, &dk.dks[i], &ek.nn);
            partial_c[i] = ci;
        }

         //zk that the multiplication is performed correctly.
        (0..p.m).into_par_iter().for_each(|i| {
        
            let witness = MulCiphWitness {
                b:dk.dks[i].clone(),
                r_b:r_b[i].clone(),
                r_c:r_c[i].clone(),
            };

            let statement = MulCiphStatement { 
                ek: EncryptionKey::from(ek).clone(), 
                e_a: ciphertext.clone(),
                e_b: e_b[i].clone(), 
                e_c: partial_c[i].clone() 
            };

            let proof = MulCiphProof::prove(&witness, &statement);
            (0..p.m)
            .into_par_iter()
            .filter(|&j| j != i) // Filter out j == i
            .for_each(|j| {
                let verify = proof.verify(&statement);
                assert!(verify.is_ok());
                
            });  
        });    
        
        for i in 0..p.m{
            dec_c = BigInt::mod_mul(&dec_c, &partial_c[i], &ek.nn);
        }
        // (c^βφ(n) - 1) /n
        let dec_c_minus_one = BigInt::sub(&dec_c, &BigInt::from(1));
        let lu = BigInt::div(dec_c_minus_one, &ek.n);
        let theta_inv = BigInt::mod_inv(&ek.theta, &ek.n).unwrap();
        let m = BigInt::mod_mul(&lu, &theta_inv, &ek.n);
        RawPlaintext(Cow::Owned(m))
    }
}

impl KeySharing<EncryptionKeyJoint, DecryptionKeyJoint, NumParties, DecryptionKeyShared> for Paillier {
    fn additive_shares(ek: &EncryptionKeyJoint, dk: &DecryptionKeyJoint, m: &NumParties ) -> DecryptionKeyShared {
        let mut keys: Vec<BigInt> = vec![BigInt::from(0); m.m];
        let mut sum: BigInt = BigInt::from(0);
        let modulo = BigInt::mul(&dk.sk, &ek.n);
        let blinded_sk = BigInt::mul(&dk.sk, &dk.beta);
        for i in 0..m.m-1{
            let si = BigInt::sample_below(&modulo);
            keys[i] = si;
            sum = sum + keys[i].clone();
        }
        keys[m.m-1] = BigInt::mod_sub(&blinded_sk, &sum, &modulo);
        DecryptionKeyShared{dks: keys}
    }
}

impl KeyGenerationJoint< EncryptionKey,  DecryptionKey,  EncryptionKeyJoint,  DecryptionKeyJoint> for Paillier {
    fn joint_dec_params(ek: &EncryptionKey, dk : &DecryptionKey) -> (EncryptionKeyJoint, DecryptionKeyJoint) {
        let one = BigInt::from(1);
        // p1 = p - 1
        let p1 = &dk.p - BigInt::one();
        // q1 = q - 1
        let q1 = &dk.q - BigInt::one();
        // sk = φ(n) = (p-1)(q-1)
        let sk = p1 * q1;
        // beta sampled randomly from Z*_n
        let beta = sample_paillier_random(&ek.n);
        // theta = β φ(n) mod n
        let theta = BigInt::mod_mul(&beta, &sk, &ek.n);
        // theta^{-1} = theta^{-1} mod n
        //let theta_inv = BigInt::mod_inv(&theta, &ek.n).unwrap();
        // shared key = β φ(n)
        //let blinded_sk = beta.clone() * sk.clone();
        let n = &ek.n;
        // public modulus n^2
        let nn = &ek.nn;
        // create necessary parameters for joint decryption Paillier
        
        // define joint encryption and decryption keys:
        let ekj = EncryptionKeyJoint{
            n: n.clone(),
            nn: nn.clone(),
            theta: theta,
        };
        let dkj = DecryptionKeyJoint{
            sk: sk,
            beta: beta,
        };
        (ekj, dkj) 
    }
}
#[cfg(test)]
mod tests {
    
    use super::*;

    use paillier::Paillier;
    use paillier::traits::EncryptWithChosenRandomness;
    use paillier::{ Randomness, RawPlaintext};


    #[test]
    fn test_params() {
        // generate classic paillier keys
        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        // public modulus n
        let n = ek.n.clone();
        // public modulus n^2
        let nn = ek.nn.clone();

        // create necessary parameters for joint decryption Paillier 
        // and put them inside public and private key
        let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

        // number of parties in the protocol        
        let m=NumParties{m:4};
        let shares = Paillier::additive_shares(&ekj, &dkj, &m).dks;
        let key_shares = DecryptionKeyShared{
            dks: shares,
        };
        // test values
        let x = BigInt::from(17);

        let r = BigInt::sample_below(&ek.n);
        let ciphertext = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x.clone()),
            &Randomness::from(r.clone()),
        );
       
        let message = Paillier::joint_decrypt(&ekj, &key_shares, &m, &ciphertext).0
        .into_owned();

        println!("plaintext is: {message}\n ");
    }
        
}

