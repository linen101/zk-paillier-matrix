use serde::{Deserialize, Serialize};

use curv::BigInt;

use paillier::Paillier;
use paillier::EncryptWithChosenRandomness;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::range_proof::;
use crate::zkproofs::multiplication_proof::MulStatement;
use crate::zkproofs::multiplication_proof::MulWitness;
use crate::zkproofs::multiplication_proof::sample_paillier_random;

use rayon::prelude::*; // Add this import

/// Τhis proof is a non'interactive proof that 
/// an array A of size n
/// contains values A[i] s.t. 0 < A[i] < q
/// it is required that  A[i] < q/3

 
/// This proof uses for each element of the array the range proof taken from
///
/// which is implemented in the module "range_proof_ni"


/* define thearray structures for the proof.
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


*/
