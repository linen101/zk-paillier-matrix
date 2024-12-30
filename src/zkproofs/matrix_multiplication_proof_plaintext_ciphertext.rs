use serde::{Deserialize, Serialize};

use curv::BigInt;
use curv::arithmetic::traits::*;

use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphProof;
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphStatement;
use crate::zkproofs::multiplication_proof_plaintext_ciphertext::MulCiphWitness;
use crate::zkproofs::multiplication_proof::sample_paillier_random;
use crate::zkproofs::joint_decryption::NumParties;
use crate::zkproofs::zero_enc_proof::{ZeroStatement, ZeroWitness, ZeroProof};

use rayon::prelude::*;



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
    pub matrix_e_d: Vec<Vec<BigInt>>,
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixCiphWitness {
    pub matrix_b: Vec<Vec<BigInt>>,
    pub matrix_r_b: Vec<Vec<BigInt>>,
    pub matrix_r_d: Vec<Vec<BigInt>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncMatrix {
    pub matrix_r_c: Vec<Vec<BigInt>>,
    pub matrix_e_c: Vec<Vec<BigInt>>,
}
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncMatrixDots {
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EncDotProducts{
    pub a: Vec<Vec<BigInt>>,
    pub b: Vec<Vec<BigInt>>,
    pub c: Vec<Vec<Vec<BigInt>>>,
}


impl EncMatrixDots {
    pub fn compute_encrypted_matrix_from_dots(e_c_r_c: &EncMatrixDots, ek: &EncryptionKey, parties: &NumParties) -> Vec<Vec<BigInt>>{
        let rows_c = e_c_r_c.matrix_e_c.len();
        let cols_c = e_c_r_c.matrix_e_c[0].len();
        let dots_c = e_c_r_c.matrix_e_c[0][0].len();

        let one = BigInt::from(1);
        let mut c: Vec<Vec<BigInt>> = vec![vec![one.clone(); cols_c]; rows_c ];

        for i in 0..rows_c {
            for j in 0..cols_c {
                for k in 0..dots_c {
                    let c1 = e_c_r_c.matrix_e_c[i][j][k].clone();
                    c[i][j] = BigInt::mod_mul(&c1, &c[i][j], &ek.nn);
                }
            }
        }
            
        return c;
    }
    pub fn matrix_dots_mul_prove_verify(mstatement: &MatrixCiphStatement, mwitness: &MatrixCiphWitness, parties: &NumParties ) {
        let rows_a = mstatement.matrix_e_a.len();
        let cols_a = mstatement.matrix_e_a[0].len();
        let rows_b = mwitness.matrix_b.len();
        let cols_b = mwitness.matrix_b[0].len();
        // Parallelize the outer loop
        (0..parties.m).into_par_iter().for_each(|l| {
            // here we construct the proof for each individual multiplication of the inner product
            (0..rows_a).into_par_iter().for_each(|i| {
                (0..cols_b).into_par_iter().for_each(|j| {
                    (0..cols_a).into_par_iter().for_each(|k| {
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
                        // prove each individual multiplication with paillier
                        let statement = MulCiphStatement { ek:mstatement.ek.clone(), e_a:e_a.clone(), e_b:e_b.clone(), e_c:e_c.clone() };
                        let proof = MulCiphProof::prove(&witness, &statement);
                        (0..parties.m)
                        .into_par_iter()
                        .filter(|&j| j != l) // Filter out j == l
                        .for_each(|j| {
                            let verify = proof.verify(&statement);
                            assert!(verify.is_ok());
                        });    
                    });     
                });
            });
        });
        
    }
    pub fn matrix_mul_prove_verify(
        mstatement: &MatrixCiphStatement,
        mwitness: &MatrixCiphWitness,
        parties: &NumParties,
    ) -> Vec<Vec<BigInt>> {
        let rows_c = mstatement.matrix_e_d.len();
        let cols_c = mstatement.matrix_e_d[0].len();
        println!("Dimensions c[{}][{}]", rows_c, cols_c);
        let mut c: Vec<Vec<BigInt>> = vec![vec![BigInt::from(0); cols_c]; rows_c];
    
        // Compute encrypted matrix from dots
        let e_c = EncMatrixDots {
            matrix_e_c: mstatement.matrix_e_c.clone(),
        };
        let matrix_e_d = EncMatrixDots::compute_encrypted_matrix_from_dots(&e_c, &mstatement.ek, parties);
    
        let exp = BigInt::sub(&mstatement.ek.n, &BigInt::from(1));
    
        // Debug dimensions
        assert_eq!(matrix_e_d.len(), rows_c, "matrix_e_d row count mismatch");
        assert_eq!(matrix_e_d[0].len(), cols_c, "matrix_e_d column count mismatch");
    
       for i in (0..rows_c) {
        for j in (0..cols_c) {
                let encrypted_d = &matrix_e_d[i][j];
                let encrypted_d_prime = &mstatement.matrix_e_d[i][j];
                println!("Processing element c[{}][{}]", i, j);
                //println!("encrypted_d: {}", encrypted_d);
                //println!("encrypted_d_prime: {}", encrypted_d_prime);
    
                // Compute Enc(c - d)
                c[i][j] = BigInt::mod_sub(encrypted_d, encrypted_d_prime, &mstatement.ek.nn);
    
                println!("Result c[{}][{}]: {}", i, j, c[i][j]);
            }
        }
    
        c
    }
    
    pub fn compute_encrypted_dot_products_homo(e_a: &Vec<Vec<BigInt>>, b: &Vec<Vec<BigInt>>, ek: &EncryptionKey, parties: &NumParties) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<Vec<BigInt>>>) {
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
                    for _ in 0..parties.m {
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
        }
  
        return (encrypted_dots_matrix, randomness);
    }
    
}  



#[cfg(test)]
mod tests {
    
    use crate::zkproofs::matrix_multiplication_proof_plaintext_ciphertext::{EncMatrixDots, MatrixCiphWitness, MatrixCiphStatement};
    use crate::zkproofs::matrix::MatrixPaillier;
    use crate::zkproofs::utils::gen_keys;
    use crate::zkproofs::joint_decryption::NumParties;
    use std::time::Instant;


    #[test]
    fn test_enc_mat_dot_prod() {
        let parties = NumParties{m: 3};
        // are [d,d]
        let n = 5;
        let d = 5;
        let ek = gen_keys();
        
        // generate randomness for zero encryption 
        let matrix_r_d  = MatrixPaillier::generate_randomness(n, d, &ek);

        // generate and encrypt matrix A
        let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
        let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
        let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

        // generate and encrypt matrix B
        // we dont implement the linear transformation described in helen
        // but the point is that the second matrix is of size [d,1]
        let matrix_b = MatrixPaillier::gen_matrix(d, 1, &ek);
        let matrix_r_b = MatrixPaillier::generate_randomness(d, 1, &ek);
        let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

        let start = Instant::now();
        let (matrix_e_c, matrix_r_c) = EncMatrixDots::compute_encrypted_dot_products_homo(&matrix_e_a, &matrix_b, &ek, &parties);
        let duration = start.elapsed();
        // Compute encrypted dot products with homomorphism
        println!("Time elapsed for matrix size ({}, {}) in encrypted dot products: {:?}", n, d, duration);
        
        let e_c = EncMatrixDots {
            matrix_e_c:matrix_e_c.clone(),
        };
        let start = Instant::now();
        
       
        let matrix_e_d = EncMatrixDots::compute_encrypted_matrix_from_dots(&e_c, &ek, &parties);
        let rows_c = matrix_e_d.len();
        let cols_c = matrix_e_d[0].len();
        println!("Dimensions c[{}][{}]", rows_c, cols_c);
        let duration = start.elapsed();
        // Compute encrypted dot products with homomorphism
        println!("Time elapsed for matrix size ({}, {}) in encrypted matrix computation from encrypted inner products: {:?}", n, d, duration);

        let matrix_ciph_witness = MatrixCiphWitness {
            matrix_b,
            matrix_r_b,
            matrix_r_d,
            matrix_r_c,
        };
    
        let matrix_ciph_statement = MatrixCiphStatement {
            ek,
            matrix_e_a,
            matrix_e_b,
            matrix_e_d,
            matrix_e_c,
        };
        /* 
        // Measure proving/verifying time
        let start = Instant::now();
        EncMatrixDots::matrix_dots_mul_prove_verify(&matrix_ciph_statement, &matrix_ciph_witness, &parties);
        let duration = start.elapsed();
    
        println!("Time elapsed for matrix size ({}, {}) in encrypted proving/verifying MATRIX inner products: {:?}", n, d, duration);
        */
        

        // Measure proving/verifying time
        let start = Instant::now();
        let c: Vec<Vec<curv::BigInt>>= EncMatrixDots::matrix_mul_prove_verify(&matrix_ciph_statement, &matrix_ciph_witness, &parties);
        let duration = start.elapsed();
    
        println!("Time elapsed for matrix size ({}, {}) in encrypted proving/verifying MATRIX CIPHERTEXT MULT: {:?}, result is: {}", n, d, duration, c[d-1][0]);
    }
}