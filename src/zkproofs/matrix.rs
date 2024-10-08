use serde::{Deserialize, Serialize};

use curv::arithmetic::traits::*;
use curv::BigInt;
use paillier::core::Randomness;
use paillier::EncryptionKey;
use paillier::Paillier;
use paillier::RawPlaintext;
use paillier::EncryptWithChosenRandomness;
use crate::zkproofs::multiplication_proof::sample_paillier_random;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct MatrixPaillier {
    pub matrix: Vec<Vec<BigInt>>,
    pub randomness: Vec<Vec<BigInt>>,
    pub encryption: Vec<Vec<BigInt>>,
}

impl MatrixPaillier {
    pub fn gen_matrix(n:usize,d:usize, ek: &EncryptionKey) -> Vec<Vec<BigInt>>{
        // Define a matrix A with dimensions n x d with random BigInt values
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

        // Return  the matrix
        matrix_a
    }

    pub fn generate_randomness(n: usize, d: usize, ek: &EncryptionKey) -> Vec<Vec<BigInt>> {
        let mut randoms: Vec<Vec<BigInt>> = Vec::new();
        for _ in 0..n {
            let mut random_row: Vec<BigInt> = Vec::new();
            for _ in 0..d {
                let r = sample_paillier_random(&ek.n);
                random_row.push(r);
            }
            randoms.push(random_row);
        }
        randoms
    }

    pub fn encrypt_matrix( matrix: &Vec<Vec<BigInt>>, randomness: &Vec<Vec<BigInt>>, ek: &EncryptionKey) -> Vec<Vec<BigInt>> {
  
        let mut encrypted_matrix: Vec<Vec<BigInt>> = Vec::new();
        // Iterate over each row of the matrix
        for (row_a, row_r_a) in matrix.iter().zip(randomness.iter()) {
            let mut encrypted_row: Vec<BigInt> = Vec::new();
            for (element_a, element_r_a) in row_a.iter().zip(row_r_a.iter())  {
                // Encrypt the element with chosen randomness r
                let c = Paillier::encrypt_with_chosen_randomness(
                    ek,
                    RawPlaintext::from(element_a.clone()),
                    &Randomness(element_r_a.clone()),
                )
                .0
                .into_owned();
    
                // Add the encrypted element to the encrypted row
                encrypted_row.push(c);
            }
            // Add the encrypted row to the encrypted matrix
            encrypted_matrix.push(encrypted_row);
        }
    
        // Return the encrypted matrix
        encrypted_matrix
    }
    

}