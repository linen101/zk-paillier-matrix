use serde::{Deserialize, Serialize};
use curv::arithmetic::traits::*;
use curv::BigInt;

use paillier::Paillier;
use paillier::EncryptWithChosenRandomness;
use paillier::{EncryptionKey, Randomness, RawPlaintext};
use crate::zkproofs::range_proof::*;
use crate::zkproofs::range_proof_ni::*;
use crate::zkproofs::multiplication_proof::sample_paillier_random;
use crate::zkproofs::range_proof_ni::RangeStatement;

use rayon::prelude::*; // Add this import

/// Τhis proof is a non'interactive proof that 
/// an array A of size n
/// contains values A[i] s.t. 0 < A[i] < q
/// it is required that  A[i] < q/3

 
/// This proof uses for each element of the array the range proof taken from
/// which is implemented in the module "range_proof_ni"

//define the array structures for the proof.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ArrayRangeStatement {
    pub ek: EncryptionKey,
    pub range: BigInt,
    pub array_e_x: Vec<BigInt>,
}


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ArrayRangeWitness {
    pub array_x: Vec<BigInt>,
    pub array_r_x: Vec<BigInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArrayRangeProofNi {
    array_encrypted_pairs: Vec<EncryptedPairs>,
    array_proof: Vec<Proof>,
    array_error_factor: usize,
}

impl ArrayRangeProofNi {
    pub fn array_range_prove_verify(astatement: &ArrayRangeStatement, awitness: &ArrayRangeWitness ){
        let len_a = awitness.array_x.len();
       
         // Parallelize the  loop
         (0..len_a).into_par_iter().for_each(|i| {
            
            // Access each element in the current array from each array array_x, array_r_x, array_e_x
            let x = &awitness.array_x[i];
            let r_x = &awitness.array_r_x[i];
            let e_x = &astatement.array_e_x[i];
                    
            let witness = RangeWitness{
                x: x.clone(),
                r_x:r_x.clone(),    
            };
        
            let statement = RangeStatement { ek:astatement.ek.clone(), range:astatement.range.clone(), e_x:e_x.clone() };
        
            let proof = RangeProofNi::prove(&witness, &statement);
            let verify = proof.verify(&statement);
            
            if verify.is_err() {
                eprintln!("Verification failed for element {}: x = {:?}", i, x);
            }

            assert!(verify.is_ok(), "Proof failed for element at index {}", i);
        });

    }
}
#[cfg(test)]
mod tests {
    const RANGE_BITS: usize = 32; //for elliptic curves with 256bits for example
    
    use super::ArrayRangeProofNi;
    use super::RangeProofNi;
    use super::*;
    use curv::arithmetic::traits::Samplable;
    use paillier::EncryptWithChosenRandomness;
    use paillier::Paillier;
    use paillier::{Keypair, Randomness, RawPlaintext};
    use crate::zkproofs::array::*;
    fn test_keypair() -> Keypair {
        let p = BigInt::from_str_radix("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
        let q = BigInt::from_str_radix("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
        Keypair { p, q }
    }

    #[test]
    fn test_prover() {
        let n = 5;
        let (ek, _dk) = test_keypair().keys();
        let range = BigInt::sample(RANGE_BITS);
        let array_r = ArrayPaillier::gen_array_randomness(n, &ek);
        let array_x =ArrayPaillier::gen_array(n, &range);
        let encrypted_array_x = ArrayPaillier::encrypt_array(&array_x, &array_r, &ek);
        
        let witness = ArrayRangeWitness {
            array_x,
            array_r_x:array_r,
        };

        let statement = ArrayRangeStatement {
            ek,
            range,
            array_e_x:encrypted_array_x,
        };

        ArrayRangeProofNi::array_range_prove_verify(&statement, &witness);
    }
/* 
    #[test]
    fn test_verifier_for_correct_proof() {
        let (ek, _dk) = test_keypair().keys();
        let range = BigInt::sample(RANGE_BITS);
        let secret_r = BigInt::sample_below(&ek.n);
        let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
        let cipher_x = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(&secret_x),
            &Randomness(secret_r.clone()),
        ).0
        .into_owned();

        let witness = ArrayRangeWitness {
            x:secret_x,
            r_x:secret_r,
        };

        let statement = ArrayRangeStatement {
            ek,
            range,
            e_x:cipher_x,
        };
        
        let range_proof = RangeProofNi::prove(&witness, &statement);
        range_proof
            .verify(&statement)
            .expect("range proof error");
    }*/
}