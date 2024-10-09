use std::iter;

use serde::{Deserialize, Serialize};

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawPlaintext};

use super::errors::IncorrectProof;

/// This proof is a non-interactive version of "Proving Multiplications Corrrect" protocol taken from
/// CDN00 [https://eprint.iacr.org/2000/055]
///
/// The prover is given an encryption E(a,r_a) and knows one plaintext b, and the randomness r_b, r_c
/// and produces an encryption E_c 
/// The prover goal is to prove that E_c encrypts a*b mod N.
///
/// Witness: {b,r_b,r_c}
///
/// Statement: {e_a, e_b, e_c, ek}
///
/// Protocol:
///
/// 1. P picks random values d from Z_n, r_d, u from Z_n*
///    and computes e_d = Enc_ek(d,r_d), e_da = e_a^d * u^n mod n^2
/// 2. using Fiat-Shamir the parties computes a challenge e
/// 3. P sends f = e*b + d mod n , z1 = r_b^e *r_d * g^t mod n^2, z2 = u^f * e_a^t * r_c^e mod n^2
/// 4. V checks:
///     e_b^e * e_d = Enc_ek(f, z1),
///     e_a^f * z_2^n = e_da * e_c^e mod n^2
/// (how to find g? )
/// Paillier library actully uses g = n + 1
/// That means, g^m mod n^2 = (n+1)^m mod n^2 
/// Using the binomial expansion, the exponentiation g^m simplifies to: 1 + m*n mod n^2
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulCiphProof {
    pub f: BigInt,
    pub z1: BigInt,
    pub z2: BigInt,
    pub e_d: BigInt,
    pub e_da: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulCiphWitness {
    pub b: BigInt,
    pub r_b: BigInt,
    pub r_c: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MulCiphStatement {
    pub ek: EncryptionKey,
    pub e_a: BigInt,
    pub e_b: BigInt,
    pub e_c: BigInt,
}

impl MulCiphProof {
    pub fn prove(witness: &MulCiphWitness, statement: &MulCiphStatement) -> Self {
        // P picks random d, r_d in Z_n
        let d = BigInt::sample_below(&statement.ek.n);
        let r_d = sample_paillier_random(&statement.ek.n);
        // P computes e_d = g^d r_d^n mod n^2
        let e_d = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(d.clone()),
            &Randomness(r_d.clone()),
        )
        .0
        .into_owned();
        // P picks random r_da in Z_n
        let r_da = sample_paillier_random(&statement.ek.n);
        
        
        // ->>>>>>>
        //  P computes e_da = e_a^d * r_{da}^n mod n^2

        // e_a^d mod n^2
        let e_a_d = BigInt::mod_pow(&statement.e_a, &d, &statement.ek.nn);
        // r_{da}^n mod n^2
        let r_da_n = BigInt::mod_pow(&r_da, &statement.ek.n, &statement.ek.nn);
        // e_a^d mod n^2 * r_{da}^n mod n^2
        let e_da = BigInt::mod_mul(&e_a_d, &r_da_n, &statement.ek.nn);
        
        // compute random challenge e
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.e_a))
                .chain(iter::once(&statement.e_b))
                .chain(iter::once(&statement.e_c))
                .chain(iter::once(&e_d))
                .chain(iter::once(&e_da)),
        );
        // compute f = e*b + d (mod N)
        let eb = BigInt::mod_mul(&e, &witness.b, &statement.ek.n);
        let f = BigInt::mod_add(&eb, &d, &statement.ek.n);

        // compute integer quotient t
        let t :BigInt = (&e* &witness.b + &d) / &statement.ek.n ;

        // compute z1 = r_b^e * r_d * g^t (mod N^2)
        let r_b_e = BigInt::mod_pow(&witness.r_b, &e, &statement.ek.nn);
        let r_b_e_r_d = BigInt::mod_mul(&r_b_e, &r_d, &statement.ek.nn);
        let gt: BigInt = (&t * &statement.ek.n + 1) % &statement.ek.nn;
        let z1 = BigInt::mod_mul(&r_b_e_r_d, &gt, &statement.ek.nn);

        // compute z2 = r_{da} * e_a^t * r_c^e (mod n^2)
        let e_a_t = BigInt::mod_pow(&statement.e_a, &t, &statement.ek.nn);
        let r_c_e = BigInt::mod_pow(&witness.r_c, &e, &statement.ek.nn);
        let e_a_t_r_c_e = BigInt::mod_mul(&e_a_t, &r_c_e, &statement.ek.nn);
        let z2 = BigInt::mod_mul(&r_da, &e_a_t_r_c_e, &statement.ek.nn);
        
        MulCiphProof {
            f,
            z1,
            z2,
            e_d,
            e_da,
        }
    }

    pub fn verify(&self, statement: &MulCiphStatement) -> Result<(), IncorrectProof> {
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.e_a))
                .chain(iter::once(&statement.e_b))
                .chain(iter::once(&statement.e_c))
                .chain(iter::once(&self.e_d))
                .chain(iter::once(&self.e_da)),
        );
        // compute enc_f_z1 = g^f * z1^n (mod n^2)
        let enc_f_z1 = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.f.clone()),
            &Randomness(self.z1.clone()),
        )
        .0
        .into_owned();

        // compute enc_af_z2 * z2^n (mod n^2)
        let enc_af= BigInt:: mod_pow(&statement.e_a, &self.f.clone(), &statement.ek.nn);
        let z2_n= BigInt:: mod_pow(&self.z2.clone(), &statement.ek.n, &statement.ek.nn);
        let enc_af_z2 = BigInt:: mod_mul(&enc_af, &z2_n, &statement.ek.nn);

        // compute e_d * e_b^e mod n^2
        let e_b_e = BigInt::mod_pow(&statement.e_b, &e, &statement.ek.nn);
        let e_b_e_e_d = BigInt::mod_mul(&e_b_e, &self.e_d, &statement.ek.nn);

        // compute e_da e_c^e mod n^2
        let e_c_e = BigInt::mod_pow(&statement.e_c, &e, &statement.ek.nn);
        let e_da_e_c_e = BigInt::mod_mul(&self.e_da, &e_c_e, &statement.ek.nn);
        
        match e_b_e_e_d == enc_f_z1 && e_da_e_c_e == enc_af_z2 {
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
}

fn sample_paillier_random(modulo: &BigInt) -> BigInt {
    let mut r_a = BigInt::sample_below(modulo);
    while BigInt::gcd(&r_a, modulo) != BigInt::one() {
        r_a = BigInt::sample_below(modulo);
    }
    r_a
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::EncryptWithChosenRandomness;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;
    use paillier::RawPlaintext;

    use crate::zkproofs::multiplication_proof_plaintext_ciphertext::sample_paillier_random;
    use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphProof;
    use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphStatement;
    use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphWitness;

    #[test]
    fn test_mul_ciph_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let a = BigInt::sample_below(&ek.n);
        let b = BigInt::sample_below(&ek.n);
        let r_a = sample_paillier_random(&ek.n);
        let r_b = sample_paillier_random(&ek.n);
        let r_c = sample_paillier_random(&ek.n);

        let e_a = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness(r_a.clone()),
        )
        .0
        .into_owned();

        let e_b = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(b.clone()),
            &Randomness(r_b.clone()),
        )
        .0
        .into_owned();

        // compute enc(ab)
        let e_a_b  = BigInt:: mod_pow(&e_a, &b, &ek.nn);
        let r_c_n  = BigInt:: mod_pow(&r_c, &ek.n, &ek.nn);
        let e_c = BigInt:: mod_mul(&e_a_b, &r_c_n, &ek.nn);
        
        let witness = MulCiphWitness {
            b,
            r_b,
            r_c,
        };

        let statement = MulCiphStatement { ek, e_a, e_b, e_c };

        let proof = MulCiphProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_mul_ciph_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let a = BigInt::sample_below(&ek.n);
        let b = BigInt::sample_below(&ek.n);
        let mut c = BigInt::mod_mul(&a, &b, &ek.n);
        // we change c such that c != ab mod m
        c = &c + BigInt::one();
        let r_a = sample_paillier_random(&ek.n);
        let r_b = sample_paillier_random(&ek.n);
        let r_c = sample_paillier_random(&ek.n);

        let e_a = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness(r_a.clone()),
        )
        .0
        .into_owned();

        let e_b = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(b.clone()),
            &Randomness(r_b.clone()),
        )
        .0
        .into_owned();

        let e_c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(c.clone()),
            &Randomness(r_c.clone()),
        )
        .0
        .into_owned();

        let witness = MulCiphWitness {
            b,
            r_b,
            r_c,
        };

        let statement = MulCiphStatement { ek, e_a, e_b, e_c };

        let proof = MulCiphProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
    
    
    #[test]
    fn test_mul_matrix_ciph_proof() {
        let n:usize = 2;
        let d:usize = 3;
        // generate a fresh paillier keypair and extract encryption key. do not extract decryption key
        let (ek, _) = Paillier::keypair().keys();

        // define a matrix A with dimensions n x d with random BigInt values
        let mut matrix_a: Vec<Vec<BigInt>> = Vec::new();

        // Populate the matrix with random values
        for _ in 0..n {
            let mut row: Vec<BigInt> = Vec::new();
            for _ in 0..d {
                let random_value = BigInt::sample_below(&ek.n); // Generate random value for each element
                row.push(random_value);
            }
            matrix_a.push(row);
        }

        // define a matrix B with dimensions d x n with random BigInt values
        let mut matrix_b: Vec<Vec<BigInt>> = Vec::new();

        // Populate the matrix with random values
        for _ in 0..d {
            let mut row: Vec<BigInt> = Vec::new();
            for _ in 0..n {
                let random_value = BigInt::sample_below(&ek.n); // Generate random value for each element
                row.push(random_value);
            }
            matrix_b.push(row);
        }

        for row in matrix_a.iter() {
            for a in row.iter() {
                for column in matrix_b.iter() {
                    for b in column.iter(){
                        let r_a = sample_paillier_random(&ek.n);
                        let r_b = sample_paillier_random(&ek.n);
                        let r_c = sample_paillier_random(&ek.n);

                        let e_a = Paillier::encrypt_with_chosen_randomness(
                            &ek,
                            RawPlaintext::from(a.clone()),
                            &Randomness(r_a.clone()),
                        )
                        .0
                        .into_owned();

                        let e_b = Paillier::encrypt_with_chosen_randomness(
                            &ek,
                            RawPlaintext::from(b.clone()),
                            &Randomness(r_b.clone()),
                        )
                        .0
                        .into_owned();

                        // compute enc(ab)
                        let e_a_b  = BigInt:: mod_pow(&e_a, &b, &ek.nn);
                        let r_c_n  = BigInt:: mod_pow(&r_c, &ek.n, &ek.nn);
                        let e_c = BigInt:: mod_mul(&e_a_b, &r_c_n, &ek.nn);
        
                        let witness = MulCiphWitness {
                        b:b.clone(),
                        r_b,
                        r_c,
                        };

                        let statement = MulCiphStatement { ek: ek.clone(), e_a, e_b, e_c };

                        let proof = MulCiphProof::prove(&witness, &statement);
                        let verify = proof.verify(&statement);
                        assert!(verify.is_ok());
                    }
                }
            }
        }
    }
}
