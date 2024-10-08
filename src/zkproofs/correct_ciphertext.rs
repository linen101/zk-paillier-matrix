use std::iter;

use serde::{Deserialize, Serialize};

use curv::arithmetic::traits::{Modulo, Samplable};
use curv::BigInt;
use paillier::traits::{Add, Mul};
use paillier::EncryptWithChosenRandomness;
use paillier::Paillier;
use paillier::{EncryptionKey, Randomness, RawCiphertext, RawPlaintext};

use super::errors::IncorrectProof;

/// This proof shows that a paillier ciphertext was constructed correctly
///
/// The proof is taken from https://www.brics.dk/RS/00/14/BRICS-RS-00-14.pdf 9.1.3
/// Given a ciphertext c and a prover encryption key , a prover wants to prove that it knows (x,r) such that c = Enc(x,r)
/// 1) P picks x',r' at random, and computes c' = Enc(x', r')
/// 2) P computes z1 = x' + ex , z2 = r' *r^e  (e is a varifier challenge)
/// 3) P sends, c' , z1,z2
/// 4) V accepts if 1) Enc(z1,z2 ) = c' * c^e
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CiphertextProof {
    pub z1: BigInt,
    pub z2: BigInt,
    pub c_prime: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CiphertextWitness {
    pub x: BigInt,
    pub r: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CiphertextStatement {
    pub ek: EncryptionKey,
    pub c: BigInt,
}

impl CiphertextProof {
    pub fn prove(witness: &CiphertextWitness, statement: &CiphertextStatement) -> Self {
        let x_prime = BigInt::sample_below(&statement.ek.n);
        let r_prime = BigInt::sample_below(&statement.ek.n);
        let c_prime = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(x_prime.clone()),
            &Randomness(r_prime.clone()),
        )
        .0
        .into_owned();

        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&c_prime)),
        );

        let z1 = &x_prime + &witness.x * &e;
        let r_e = BigInt::mod_pow(&witness.r, &e, &statement.ek.nn);
        let z2 = BigInt::mod_mul(&r_prime, &r_e, &statement.ek.nn);

        CiphertextProof { z1, z2, c_prime }
    }

    pub fn verify(&self, statement: &CiphertextStatement) -> Result<(), IncorrectProof> {
        let e = super::compute_digest(
            iter::once(&statement.ek.n)
                .chain(iter::once(&statement.c))
                .chain(iter::once(&self.c_prime)),
        );

        let c_z = Paillier::encrypt_with_chosen_randomness(
            &statement.ek,
            RawPlaintext::from(self.z1.clone()),
            &Randomness(self.z2.clone()),
        )
        .0
        .into_owned();

        let c_e = Paillier::mul(
            &statement.ek,
            RawPlaintext::from(e),
            RawCiphertext::from(statement.c.clone()),
        );
        let c_z_test = Paillier::add(
            &statement.ek,
            c_e,
            RawCiphertext::from(self.c_prime.clone()),
        )
        .0
        .into_owned();

        match c_z == c_z_test {
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
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

    use crate::zkproofs::correct_ciphertext::CiphertextProof;
    use crate::zkproofs::correct_ciphertext::CiphertextStatement;
    use crate::zkproofs::correct_ciphertext::CiphertextWitness;

    #[test]
    fn test_ciphertext_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let x = BigInt::sample_below(&ek.n);
        let r = BigInt::sample_below(&ek.n);

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x.clone()),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let witness = CiphertextWitness { x, r };

        let statement = CiphertextStatement { ek, c };

        let proof = CiphertextProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_bad_ciphertext_proof() {
        let (ek, _) = Paillier::keypair().keys();
        let x = BigInt::sample_below(&ek.n);
        let r = BigInt::sample_below(&ek.n);

        let c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(x.clone()),
            &Randomness(r.clone()),
        )
        .0
        .into_owned();

        let witness = CiphertextWitness {
            x,
            r: r + BigInt::one(),
        };

        let statement = CiphertextStatement { ek, c };

        let proof = CiphertextProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }

    #[test]
    fn test_matrix_ciphertext_proof(){

        let n:usize = 100;
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

        for row in matrix_a.iter() {
            for element in row.iter() {
                // generate random r for each element which should be smaller than the public modulus n
                let r = BigInt::sample_below(&ek.n);
            
                // encrypt the element with chosen randomness r
                let c = Paillier::encrypt_with_chosen_randomness(
                    &ek,
                    RawPlaintext::from(element.clone()),
                    &Randomness(r.clone())
                )
                .0
                .into_owned();
        
             // Generate the witness (plaintext and randomness)
            let witness = CiphertextWitness {
                x: element.clone(),
                r,
            };
        
            // Step 5: Create the statement with the encryption key and ciphertext
            let statement = CiphertextStatement {
                ek: ek.clone(),
                c,
            };
        
            // Step 6: Prove knowledge of the plaintext for this element
            let proof = CiphertextProof::prove(&witness, &statement);
        
            // Step 7: Verify the proof
            let verify = proof.verify(&statement);
            assert!(verify.is_ok(), "Proof verification failed for element {:?}", element);
            }
        }
        println!("Proofs verified successfully for an n x d matrix: {} x {}", n, d);
        }
    }
