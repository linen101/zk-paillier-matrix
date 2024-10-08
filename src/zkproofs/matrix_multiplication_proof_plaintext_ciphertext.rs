use serde::{Deserialize, Serialize};

use curv::BigInt;
use curv::arithmetic::traits::*;
use paillier::Paillier;
use paillier::EncryptWithChosenRandomness;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphProof;
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphStatement;
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphWitness;
use crate::zkproofs::multiplication_proof::sample_paillier_random;

/// Τhis proof is a non'interactive proof for matrix multiplication C = AB
/// when the prover knows both only B[d*n] and does not know A[n*d].
/// To prove this, we apply the Paillier plaintext multiplication proof 
/// for each dot product in AB.
/// Note that we have n^2*d dot products in total 
 
/// This proof uses for each dot product the pailliers Multiplication protocol taken from
/// https://eprint.iacr.org/2000/055.pdf
/// which is implemented in the module "multiplication_proof_plaintext_ciphertext"
/// 
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixCiphStatement {
    pub ek: EncryptionKey,
    pub matrix_e_a: Vec<Vec<BigInt>>,
    pub matrix_e_b: Vec<Vec<BigInt>>,
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixCiphWitness {
    pub matrix_b: Vec<Vec<BigInt>>,
    pub matrix_r_b: Vec<Vec<BigInt>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncMatrixDots {
    pub matrix_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncDotProducts{
    pub a: Vec<Vec<BigInt>>,
    pub b: Vec<Vec<BigInt>>,
    pub c: Vec<Vec<Vec<BigInt>>>,
}


impl EncMatrixDots {
    pub fn matrix_dots_mul_prove_verify(mstatement: &MatrixCiphStatement, mwitness: &MatrixCiphWitness ) {
        let rows_a = mstatement.matrix_e_a.len();
        let cols_a = mstatement.matrix_e_a[0].len();
        let rows_b = mwitness.matrix_b.len();
        let cols_b = mwitness.matrix_b[0].len();
        for i in 0..rows_a {
            for j in 0..cols_b {
                for k in 0..cols_a {
                    // Access each element in the current row from  e_a
                    let e_a = &mstatement.matrix_e_a[i][k];

                    // Access each element in the current column from each matrix matrix_b, r_b, e_b
                    let b = &mwitness.matrix_b[k][j];
                    let r_b = &mwitness.matrix_r_b[k][j];
                    let e_b = &mstatement.matrix_e_b[k][j];

                    // Access each element in the current column from e_c
                    let r_c = &mwitness.matrix_r_c[i][j][k];
                    let e_c = &mstatement.matrix_e_c[i][j][k];
                            
                    let witness = MulCiphWitness {
                        b:b.clone(),
                        r_b:r_b.clone(),
                        r_c:r_c.clone(),
                    };
                
                    let statement = MulCiphStatement { ek:mstatement.ek.clone(), e_a:e_a.clone(), e_b:e_b.clone(), e_c:e_c.clone() };
                
                    let proof = MulCiphProof::prove(&witness, &statement);
                    let verify = proof.verify(&statement);
                    assert!(verify.is_ok());
                }
            }
        }
    }
}  

impl EncDotProducts {
    pub fn compute_encrypted_dot_products_homo(e_a: &Vec<Vec<BigInt>>, b: &Vec<Vec<BigInt>>, ek: &EncryptionKey) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<Vec<BigInt>>>) {
        let rows_a = e_a.len();
        let cols_a = e_a[0].len();
        let rows_b = b.len();
        let cols_b = b[0].len();

        // ensure the number of columns in A is equal to the number of rows in B
        if cols_a != rows_b {
            panic!("Cannot multiply matrices: incompatible dimensions");
        }

        // matrix declaration
        let zero = BigInt::from(0);
        let mut encrypted_dots_matrix: Vec<Vec<Vec<BigInt>>> = vec![vec![vec![zero.clone(); cols_a]; cols_b ]; rows_a];
        let mut randomness: Vec<Vec<Vec<BigInt>>> = vec![vec![vec![zero; cols_a]; cols_b ]; rows_a];

        // Matrix multiplication
        for i in 0..rows_a {
            for j in 0..cols_b {
                for k in 0..cols_a {
                    let r_c = sample_paillier_random(&ek.n);
                    randomness[i][j][k] = r_c.clone();
                    // compute enc(ab)
                    let e_a_b  = BigInt:: mod_pow(&e_a[i][k], &b[k][j], &ek.nn);
                    let r_c_n  = BigInt:: mod_pow(&r_c, &ek.n, &ek.nn);
                    let e_c = BigInt:: mod_mul(&e_a_b, &r_c_n, &ek.nn);
        
                    encrypted_dots_matrix[i][j][k] = e_c.clone();
                }
            }
        }
        return (encrypted_dots_matrix, randomness);
    }
}

