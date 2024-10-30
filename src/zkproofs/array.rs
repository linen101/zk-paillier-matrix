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
pub struct ArrayPaillier {
    pub matrix: Vec<BigInt>,
    pub randomness: Vec<BigInt>,
    pub encryption: Vec<BigInt>,
}

impl ArrayPaillier {
    pub fn gen_array(n:usize, range: &BigInt) -> Vec<BigInt>{
        // Define a array A with dimension n  with random BigInt values < range
        let mut array_a: Vec<BigInt> = Vec::new();

        // Populate the array with random values with random values within range
        for _ in 0..n {
            let random_value = BigInt::sample_below(&range.div_floor(&BigInt::from(3))); // Generate random value for each element within range
            array_a.push(random_value);
        }

        // Return  the matrix
        array_a
    }

    pub fn gen_array_no_range(n:usize, ek: &EncryptionKey) -> Vec<BigInt>{
        // Define a array A with dimension n  with random BigInt values < range
        let mut array_a: Vec<BigInt> = Vec::new();

        // Populate the array with random values with random values within range
        for _ in 0..n {
            let random_value = BigInt::sample_below(&ek.n); // Generate random value for each element within range
            array_a.push(random_value);
        }

        // Return  the matrix
        array_a
    }
    pub fn gen_array_randomness(n: usize, ek: &EncryptionKey) -> Vec<BigInt>{
        let mut randoms: Vec<BigInt> = Vec::new();
        for _ in 0..n {
            let r = sample_paillier_random(&ek.n);
            randoms.push(r);
        }
        randoms
    }

    pub fn encrypt_array( array: &Vec<BigInt>, randomness: &Vec<BigInt>, ek: &EncryptionKey) -> Vec<BigInt> {
  
        let mut encrypted_array: Vec<BigInt> = Vec::new();
        // Iterate over each row of the matrix

        for (element_a, element_r_a) in array.iter().zip(randomness.iter())  {
            // Encrypt the element with chosen randomness r
            let c = Paillier::encrypt_with_chosen_randomness(
                ek,
                RawPlaintext::from(element_a.clone()),
                &Randomness(element_r_a.clone()),
            )
            .0
            .into_owned();

            // Add the encrypted element to the encrypted array
            encrypted_array.push(c);
        }

        // Return the encrypted matrix
        encrypted_array
    }
    

}