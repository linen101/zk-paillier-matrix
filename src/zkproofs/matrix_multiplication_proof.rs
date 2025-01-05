use std::f32::RADIX;

use curv::arithmetic::Modulo;
use serde::{Deserialize, Serialize};


use curv::arithmetic::traits::*;
use curv::BigInt;

use paillier::Paillier;
use paillier::EncryptWithChosenRandomness;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::multiplication_proof::MulProof;
use crate::zkproofs::multiplication_proof::MulStatement;
use crate::zkproofs::multiplication_proof::MulWitness;
use crate::zkproofs::matrix::MatrixPaillier;
use crate::zkproofs::multiplication_proof::sample_paillier_random;
use crate::zkproofs::joint_decryption::NumParties;
use rayon::prelude::*;

use super::EncMatrixDots;
use super::{ ZeroStatement, ZeroProof, ZeroWitness};


/// Τhis proof is a non'interactive proof for matrix multiplication C = AB
/// when the prover knows both A[n*d], B[d*n].
/// To prove this, we apply the Paillier plaintext multiplication proof 
/// for each dot product in AB.
/// Note that we have n^2*d dot products in total 
 
/// This proof uses for each dot product the Multiplication-mod-n^s protocol taken from
/// DJ01 [https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf ]
/// which is implemented in the module "multiplication_proof"
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixStatement {
    pub ek: EncryptionKey,
    pub matrix_e_a: Vec<Vec<BigInt>>,
    pub matrix_e_b: Vec<Vec<BigInt>>,
    pub matrix_e_d: Vec<Vec<BigInt>>,
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

// matrix_d = matrix_a *  matrix_b
// matrix_d[i][j] = \Sigma_{k \in [n]} matrix_c[i][j][k] 
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixWitness {
    pub matrix_a: Vec<Vec<BigInt>>,
    pub matrix_b: Vec<Vec<BigInt>>,
    pub matrix_d: Vec<Vec<BigInt>>,
    pub matrix_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_r_a: Vec<Vec<BigInt>>,
    pub matrix_r_b: Vec<Vec<BigInt>>,
    pub matrix_r_d: Vec<Vec<BigInt>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
}

pub struct MatrixDots {
    pub matrix_d: Vec<Vec<BigInt>>,
    pub matrix_r_d: Vec<Vec<BigInt>>,
    pub matrix_e_d: Vec<Vec<BigInt>>,
}

pub struct MulDotProducts{
    pub a: Vec<Vec<BigInt>>,
    pub b: Vec<Vec<BigInt>>,
    pub c: Vec<Vec<Vec<BigInt>>>,
}


impl MatrixDots {
    pub fn compute_encrypted_matrix_from_plaintext_dots(matrix_c: &Vec<Vec<Vec<BigInt>>>, ek: &EncryptionKey, parties: &NumParties) -> MatrixDots{
        let rows_c = matrix_c.len();
        let cols_c = matrix_c[0].len();
        let dots_c = matrix_c[0][0].len();

        let one = BigInt::from(1);
        let mut c: Vec<Vec<BigInt>> = vec![vec![one.clone(); cols_c]; rows_c ];

        for i in 0..rows_c {
            for j in 0..cols_c {
                for k in 0..dots_c {
                    let c1 = matrix_c[i][j][k].clone();
                    c[i][j] = BigInt::mod_add(&c1, &c[i][j], &ek.nn);
                }
            }
        }
        let matrix_r_d = MatrixPaillier::generate_randomness(c.len(), c[0].len(), &ek);
        let matrix_e_d = MatrixPaillier::encrypt_matrix(&c, &matrix_r_d, &ek);  
        let a = MatrixDots{
            matrix_d: c.clone(),
            matrix_e_d,
            matrix_r_d,
        };
        return a;
    }
    pub fn matrix_dots_mul_prove_verify(mstatement: &MatrixStatement, mwitness: &MatrixWitness, parties: &NumParties ) {
        let rows_a = mwitness.matrix_a.len();
        let cols_a = mwitness.matrix_a[0].len();
        let rows_b = mwitness.matrix_b.len();
        let cols_b = mwitness.matrix_b[0].len();
        // Parallelize the outer loop
        (0..rows_a).into_par_iter().for_each(|i| {
            (0..cols_b).into_par_iter().for_each(|j| {
                (0..cols_a).into_par_iter().for_each(|k| {
                    // Access each element in the current row from each matrix matrix_a, r_a, e_a
                    let a = &mwitness.matrix_a[i][k];
                    let r_a = &mwitness.matrix_r_a[i][k];
                    let e_a = &mstatement.matrix_e_a[i][k];

                    // Access each element in the current column from each matrix matrix_b, r_b, e_b
                    let b = &mwitness.matrix_b[k][j];
                    let r_b = &mwitness.matrix_r_b[k][j];
                    let e_b = &mstatement.matrix_e_b[k][j];

                    let c = &mwitness.matrix_c[i][j][k];
                    let r_c = &mwitness.matrix_r_c[i][j][k];
                    let e_c = &mstatement.matrix_e_c[i][j][k];
                            
                    let witness = MulWitness {
                        a:a.clone(),
                        b:b.clone(),
                        c:c.clone(),
                        r_a:r_a.clone(),
                        r_b:r_b.clone(),
                        r_c:r_c.clone(),
                    };
                
                    let statement = MulStatement { ek:mstatement.ek.clone(), e_a:e_a.clone(), e_b:e_b.clone(), e_c:e_c.clone() };
                
                    (0..parties.m).into_par_iter().for_each(|i| {
                        let proof = MulProof::prove(&witness, &statement);
                        (0..parties.m)
                        .into_par_iter()
                        .filter(|&j| j != i) // Filter out j == i
                        .for_each(|j| {
                            let verify = proof.verify(&statement);
                            assert!(verify.is_ok());
                        });    
                    });

                });
            });
        });

        /*  let rows_c = mstatement.matrix_e_c.len();
        let cols_c = mstatement.matrix_e_c[0].len();
        let dots_c = mstatement.matrix_e_c[0][0].len();
        let exp: BigInt = BigInt::sub(&mstatement.ek.n, &BigInt::from(1));

        let mut randomness_dots: Vec<Vec<BigInt>> = vec![vec![BigInt::from(0); cols_c]; rows_c];

        randomness_dots.par_iter_mut().enumerate().for_each(|(k, row)| {
            row.iter_mut().enumerate().for_each(|(l, elem)| {
                let result_randomness  =  BigInt::mod_pow(&mwitness.matrix_r_d[k][l], &exp, &mstatement.ek.nn); 
                // Multiply all elements in mwitness.matrix_r_c[k][l] together
                let product = mwitness.matrix_r_c[k][l]
                    .iter()
                    .fold(BigInt::one(), |acc, value| { BigInt::mod_mul(&acc, &value, &mstatement.ek.nn) } );
                
                // Multiply the result with result_randomness
                *elem = product * &result_randomness;
            });
        });
        let enc  = EncMatrixDots{
            matrix_e_c:mstatement.matrix_e_c.clone(),
        };
        // each verifier computes homomorphically the result matrix from the dot products
        (0..parties.m).into_par_iter().for_each(|i| {
            // matrix C = AB        but computed homomorphically from the verifier
            let result_enc = EncMatrixDots::compute_encrypted_matrix_from_dots(&enc, &mstatement.ek, parties);
            

            // prover work on the randomness
            (0..rows_c).into_par_iter().for_each(|k| {
                (0..cols_c).into_par_iter().for_each(|l| {
                    //  -C [i][j]
                    let minus_result_enc = BigInt::mod_pow(&mstatement.matrix_e_d[k][l], &exp, &mstatement.ek.nn); 
                    // C[i][j]  - C[i][j]
                    let zero_statement  =   ZeroStatement {ek: mstatement.ek.clone() , c : BigInt::mod_mul(&minus_result_enc , &result_enc[k][l], &mstatement.ek.nn) };
                    let zero_witness  =  ZeroWitness { r :  randomness_dots[k][l].clone() };
                    let zero_proof = ZeroProof::prove(&zero_witness, &zero_statement);
                    (0..parties.m)
                    .into_par_iter()
                    .filter(|&j| j != i) // Filter out j == i
                    .for_each(|j| {
                        let verify = zero_proof.verify(&zero_statement);
                            assert!(verify.is_ok());
                    });    
                });
            });
        });
        */
        
    }
}  




impl MulDotProducts {
    pub fn compute_plaintext_dot_products(a: &Vec<Vec<BigInt>>, b: &Vec<Vec<BigInt>>) -> Vec<Vec<Vec<BigInt>>> {
        let rows_a = a.len();
        let cols_a = a[0].len();
        let rows_b = b.len();
        let cols_b = b[0].len();

        // ensure the number of columns in A is equal to the number of rows in B
        if cols_a != rows_b {
            panic!("Cannot multiply matrices: incompatible dimensions");
        }
        
        let mut result: Vec<Vec<Vec<BigInt>>> = Vec::new();
        // Initialize the result matrix with zeros
        let zero = BigInt::from(0);
        let mut result: Vec<Vec<Vec<BigInt>>> = vec![vec![vec![zero; cols_a]; cols_b ]; rows_a];

        // Matrix multiplication
        for i in 0..rows_a {
            for j in 0..cols_b {
                for k in 0..cols_a {
                    result[i][j][k] = a[i][k].clone() * b[k][j].clone();
                }
            }
        }

        result
    }

    pub fn compute_encrypted_dot_products(a: &Vec<Vec<Vec<BigInt>>>, ek: &EncryptionKey) -> (Vec<Vec<Vec<BigInt>>>, Vec<Vec<Vec<BigInt>>>) {
        let rows_a = a.len();
        let cols_a = a[0].len();
        let dots_a:usize = a[0][0].len();

        let mut encrypted_dots_matrix: Vec<Vec<Vec<BigInt>>> = Vec::new();
        let mut randomness: Vec<Vec<Vec<BigInt>>> = Vec::new();

        // Iterate over each row of the matrix
        for row_a in a.iter() {
            // Iterate over each row of the matrix
            let mut encrypted_rows: Vec<Vec<BigInt>> = Vec::new();
            let mut randomness_rows: Vec<Vec<BigInt>> = Vec::new();
            // Iterate over each dot product 
            for dot_a in row_a.iter()  {
                let mut encrypted_dots: Vec<BigInt> = Vec::new();
                let mut randomness_dots: Vec<BigInt> = Vec::new();
                for element_a in dot_a.iter()  {
                    // Encrypt the element with chosen randomness r
                    let r_c = sample_paillier_random(&ek.n);
                    randomness_dots.push(r_c.clone());
                    let c = Paillier::encrypt_with_chosen_randomness(
                        ek,
                        RawPlaintext::from(element_a.clone()),
                        &Randomness(r_c),
                    )
                    .0
                    .into_owned();
                encrypted_dots.push(c);
                }
                // Add the encrypted element to the encrypted row
                encrypted_rows.push(encrypted_dots);
                randomness_rows.push(randomness_dots);

            }
            // Add the encrypted row to the encrypted matrix
            encrypted_dots_matrix.push(encrypted_rows);
            randomness.push(randomness_rows);
        }

        // return a matrix containing each single dot product of the matrix multiplication
        (encrypted_dots_matrix, randomness)
    }
}

pub fn mul_plaintext_matrices(a: &Vec<Vec<BigInt>>, b: &Vec<Vec<BigInt>>) -> Vec<Vec<BigInt>> {
    let rows_a = a.len();
    let cols_a = a[0].len();
    let rows_b = b.len();
    let cols_b = b[0].len();

    // ensure the number of columns in A is equal to the number of rows in B
    if cols_a != rows_b {
        panic!("Cannot multiply matrices: incompatible dimensions");
    }

    // Initialize the result matrix with zeros
    let zero = BigInt::from(0);
    let mut result: Vec<Vec<BigInt>> = vec![vec![zero; cols_b]; rows_a];

    // Matrix multiplication
    for i in 0..rows_a {
        for j in 0..cols_b {
            for k in 0..cols_a {
                result[i][j] += a[i][k].clone() * b[k][j].clone();
            }
        }
    }

    result
}


#[cfg(test)]
mod tests {
    
    use crate::zkproofs::matrix_multiplication_proof::{MatrixDots, MatrixWitness, MatrixStatement, MulDotProducts};
    use crate::zkproofs::matrix::MatrixPaillier;
    use crate::zkproofs::utils::gen_keys;
    use crate::zkproofs::joint_decryption::NumParties;
    use std::time::Instant;


    #[test]
    fn test_mat_dot_prod() {

        let parties = NumParties{m: 3};
        // are [d,d]
        let n = 5;
        let d = 5;

        // Key generation
        let ek = gen_keys();

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

        // compute plaintext and encrypted dot products
        let matrix_c = MulDotProducts::compute_plaintext_dot_products(&matrix_a, &matrix_b);
        let (matrix_e_c, matrix_r_c) = MulDotProducts::compute_encrypted_dot_products(&matrix_c, &ek);  

        // compute plaintext and encrypted result matrix
        let result_matrices = MatrixDots::compute_encrypted_matrix_from_plaintext_dots(&matrix_c, &ek, &parties);
        
        let matrix_witness = MatrixWitness {
            matrix_a,
            matrix_b: matrix_b.clone(), // copy from memory
            matrix_d: result_matrices.matrix_d.clone(),
            matrix_c: matrix_c.clone(),
            matrix_r_a,
            matrix_r_b: matrix_r_b.clone(),
            matrix_r_d: result_matrices.matrix_r_d.clone(),
            matrix_r_c: matrix_r_c.clone(),
        };

        let matrix_statement = MatrixStatement {
            ek: ek.clone(),
            matrix_e_a: matrix_e_a.clone(),
            matrix_e_b: matrix_e_b.clone(),
            matrix_e_d: result_matrices.matrix_e_d.clone(),
            matrix_e_c: matrix_e_c.clone(),
        };

        // Measure proving/verifying time
        let start = Instant::now();
        MatrixDots::matrix_dots_mul_prove_verify(&matrix_statement, &matrix_witness, &parties);
        let duration = start.elapsed();

        println!("Time elapsed for matrix size ({}, {}) during proving/verifying MATRIX PLAINTEXT MUL: {:?}", n, d, duration);
    }


}