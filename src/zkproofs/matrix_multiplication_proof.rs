use serde::{Deserialize, Serialize};

use curv::BigInt;

use paillier::Paillier;
use paillier::EncryptWithChosenRandomness;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::multiplication_proof::MulProof;
use crate::zkproofs::multiplication_proof::MulStatement;
use crate::zkproofs::multiplication_proof::MulWitness;
use crate::zkproofs::multiplication_proof::sample_paillier_random;

use rayon::prelude::*; // Add this import

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
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixWitness {
    pub matrix_a: Vec<Vec<BigInt>>,
    pub matrix_b: Vec<Vec<BigInt>>,
    pub matrix_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_r_a: Vec<Vec<BigInt>>,
    pub matrix_r_b: Vec<Vec<BigInt>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
}

pub struct MatrixDots {
    pub matrix_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_r_c: Vec<Vec<Vec<BigInt>>>,
    pub matrix_e_c: Vec<Vec<Vec<BigInt>>>,
}

pub struct MulDotProducts{
    pub a: Vec<Vec<BigInt>>,
    pub b: Vec<Vec<BigInt>>,
    pub c: Vec<Vec<Vec<BigInt>>>,
}


impl MatrixDots {
    pub fn matrix_dots_mul_prove_verify(mstatement: &MatrixStatement, mwitness: &MatrixWitness ) {
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
                
                    let proof = MulProof::prove(&witness, &statement);
                    let verify = proof.verify(&statement);
                    assert!(verify.is_ok());
                });
            });
        });
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

