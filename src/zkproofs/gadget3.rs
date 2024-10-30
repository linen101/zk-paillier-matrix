use std::iter;

use serde::{Deserialize, Serialize};

use paillier::{EncryptionKey, Paillier, KeyGeneration, RawPlaintext, RawCiphertext, Randomness};
use paillier::EncryptWithChosenRandomness;

use curv::arithmetic::traits::*;
use curv::BigInt;

use super::errors::IncorrectProof;
use super::DecryptJoint;
use crate::zkproofs::joint_decryption::*;
use crate::zkproofs::array::*;
use crate::zkproofs::utils::*;


/// 
/// Gadget 3. 
/// For m parties, each party having the public key PK 
/// and a share of  the secret key SK, 
/// given public ciphertext EncPK (a), 
/// convert a into m shares ai ∈ Zp such that 
/// a ≡  P ai mod p. 
/// Each party Pi receives secret share ai 
/// and does not learn the original secret value a.
/// 

/// 
/// Protocol. The protocol proceeds as follows:
/// 1. Each party Pi generates a random value ri ∈ [0, 2^{|p|+κ} ] and encrypts it, 
    /// where κ is a statistical security parameter, p spdz modulo. 
    /// Each party should also generate an interval plaintext proof of knowledge of ri , 
    /// then publish EncPK (ri ) along with the proofs. 
/// 2. Each party Pi takes as input the published {EncPK (rj)}^m_{j=1}
    /// and compute the product with EncPK (a). 
    /// The result is c = EncPK (a + \Sigma_{j=1}^m r_j ).
/// 3. All parties jointly decrypt c to get plaintext b.
/// 4. Party 0 sets a0 = b − r0 mod p. Every other party sets ai ≡ −ri mod p.
/// 5. Each party publishes EncPK(ai) as well as an interval proof of plaintext knowledge.
/// 

// |p| = 64 bits,
const MOD_BITS: u32 = 64; 
// κ = 40
const K_PARAMETER: u32 = 40;
// m = 3, e.g. helen is run among 3 parties.
const N_PARTIES: usize = 3; 

// derive encryption key from joint encryption key to use the encryption method for paillier
impl<'e> From<&'e EncryptionKeyJoint> for EncryptionKey {
    fn from(ekj: &'e EncryptionKeyJoint) -> Self {
        let nn = ekj.nn.clone();
        let n = ekj.n.clone();
        EncryptionKey { n, nn }
    }
}



#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GadgetThreeSingleParty {
    pub share: BigInt,
    //pub share_range: RangeProofNi,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GadgetThree {
    pub shares: Vec<BigInt>,
    //pub share_range: RangeProofNi,
}
impl GadgetThree {
    pub fn protocol(a:&BigInt, ekj: &EncryptionKeyJoint, sk_shares: &DecryptionKeyShared, pis: &NumParties, spdz_modulus: &BigInt) -> Self{
        // STEP 1:
        let mut masks: Vec<BigInt> = Vec::new();
        let mut randoms: Vec<BigInt> = Vec::new();
        let mut encrypted_masks: Vec<BigInt> = Vec::new();
        // each party generates a random value ri ∈ [0, 2^{|p|+κ} ]
        for i in 0..N_PARTIES{
            let m = gen_mask();
            masks.push(m);
            // create randomnesses for encryptions
            let r = sample_paillier_random(&ekj.n);
            randoms.push(r);
        }
        for i in 0..N_PARTIES{
            let e_m = Paillier::encrypt_with_chosen_randomness(
                &EncryptionKey::from(ekj),
                RawPlaintext::from(masks[i].clone()),
                &Randomness(randoms[i].clone()),
            )
            .0
            .into_owned();
            // Add the encrypted element to the encrypted array
            encrypted_masks.push(e_m);
        }
        
        // publish encrypted masks: publish enc(r_i) ?
        // Rust’s standard library provides threads for concurrency 
        // and channels for inter-thread communication. 
        // Each party can be represented as a separate thread, 
        // and they can send and receive messages using channels (std::sync::mpsc).
        // for asynchronnous communication we can use async and tokio.
        // TODO ^

        // STEP 2:
        // each party takes as input {Enc_pk(r_i)}_{i \in [m]}
        // and compputes the product with Enc_pk(a)
        // the result is Enc_pk(a + Σ r_i)
        let zero = BigInt::from(0);
        let mut c: Vec<BigInt> = vec![zero; N_PARTIES];
        // double for loop is to show that each party does the computation of c.
        for i in 0..N_PARTIES{
            c[i] = a.clone();
            //BigInt::mod_mul(&a, &encrypted_masks[1], &ekj.nn);
            for j in 1..N_PARTIES{
                let c1 = encrypted_masks[j].clone();
                c[i] = BigInt::mod_mul(&c1, &c[i], &ekj.nn);
            } 
        }
        // STEP 3: jointly decrypt c to get plaintext b
        let b_raw = Paillier::joint_decrypt(ekj, sk_shares, pis, &RawCiphertext::from(c[0].clone()));
        let b = BigInt::from(b_raw);

        // STEP 4: Create shares of a using the masked b.

        GadgetThree{shares: sk_shares.dks.clone()}
    }
}

fn gen_mask() -> BigInt {
    let bit_len = MOD_BITS + K_PARAMETER;
    let big_val = BigInt::pow(&BigInt::from(2),bit_len);
    let upper = BigInt::pow(&BigInt::from(2),bit_len);
    let r = BigInt::sample_below(&upper);
    r
}

