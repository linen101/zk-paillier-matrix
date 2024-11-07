use std::iter;

use serde::{Deserialize, Serialize};

use paillier::{EncryptionKey, Paillier, RawPlaintext, RawCiphertext, Randomness};
use paillier::EncryptWithChosenRandomness;

use curv::arithmetic::traits::*;
use curv::BigInt;

use super::errors::IncorrectProof;
use super::DecryptJoint;
use crate::zkproofs::joint_decryption::*;
use crate::zkproofs::range_proof_ni::*;
use crate::zkproofs::utils::*;
use rayon::prelude::*;

use tokio::sync::mpsc;
use tokio::task;
use tokio::sync::broadcast;

//[DONE: ADD RANGE PROOFS IN STEP 1]
//[done: ADD RANGE PROOFS IN STEP 5]

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




#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GadgetThreeSingleParty {
    pub share: BigInt,
    //pub share_range: RangeProofNi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GadgetThree {
    pub a: BigInt,
    pub a_shares: Vec<BigInt>,
    pub e_a: BigInt,
    pub range_proof_shares: Vec<RangeProofNi>,
    pub mac_shares: Vec<BigInt>,
    pub global_mac_shares: Vec<BigInt>,
    pub spdz_mod: BigInt,
    //pub share_range: RangeProofNi,
}
impl GadgetThree {
    pub  fn protocol(e_a:&BigInt, ekj: &EncryptionKeyJoint, sk_shares: &DecryptionKeyShared, parties: &NumParties, spdz_modulus: &BigInt) -> Self{

        let mut masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut encrypted_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut enc_shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut proof_shares: Vec<RangeProofNi> = Vec::new();
        
        // STEP 1:
        // each party generates a random value ri ∈ [0, 2^{|p|+κ} ]
        // Simulate Party 1 sending a message
        for i in 0..parties.m{

            let m = gen_mask(&MOD_BITS);
            masks.push(m);
            // create randomnesses for encryptions
            let r1 = sample_paillier_random(&ekj.n);
            randoms_masks.push(r1);
            let r2 = sample_paillier_random(&ekj.n);
            randoms_shares.push(r2);
        }
        encrypted_masks.par_iter_mut().enumerate().for_each(|(i, x)|{
            let e_m = Paillier::encrypt_with_chosen_randomness(
                &EncryptionKey::from(ekj),
                RawPlaintext::from(masks[i].clone()),
                &Randomness(randoms_masks[i].clone()),
            )
            .0
            .into_owned();
            // Add the encrypted element to the encrypted array
            *x = e_m;
        });

        //zk that the mask is chosen correctly within range with range_proof_ni (Lindell et al 2017).
        (0..parties.m).into_par_iter().for_each(|i| {
            let witness = RangeWitness{
                x: masks[i].clone(),
                r_x:randoms_masks[i].clone(),    
            };
        
            let statement = RangeStatement { 
                ek: EncryptionKey::from(ekj).clone(), 
                range: range(&MOD_BITS), 
                e_x:encrypted_masks[i].clone() 
            };
        
            let proof = RangeProofNi::prove(&witness, &statement);
            (0..parties.m)
            .into_par_iter()
            .filter(|&j| j != i) // Filter out j == i
            .for_each(|j| {
                let verify = proof.verify(&statement);
                
                if verify.is_err() {
                    eprintln!("Verification failed for party {} with: mask = {:?}", i, masks[i]);
                }

                assert!(verify.is_ok(), "Proof failed for element at index {}", i);
            });
        });
        
        // publish encrypted masks: publish enc(r_i) 
        // Rust’s standard library provides threads for concurrency 
        // and channels for inter-thread communication. 
        // Each party can be represented as a separate thread, 
        // and they can send and receive messages using channels (std::sync::mpsc).
        // for asynchronnous communication we can use async and tokio.
        // TODO ^

        // STEP 2:
        // each party upon receiving {Enc_pk(r_i)}_{i \in [m]} from each other party in the protocol
        // compputes the product with Enc_pk(a)
        // the result is Enc_pk(a + Σ r_i)
        let mut c: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        // double for loop is to show that each party does the computation of c.
        for i in 0..parties.m{
            c[i] = e_a.clone();
            //BigInt::mod_mul(&a, &encrypted_masks[1], &ekj.nn);
            for j in 1..parties.m{
                let c1 = encrypted_masks[j].clone();
                c[i] = BigInt::mod_mul(&c1, &c[i], &ekj.nn);
            } 
        }
        // STEP 3: the parties jointly decrypt c to get plaintext b
        let b_raw = Paillier::joint_decrypt(ekj, sk_shares, parties, &RawCiphertext::from(c[0].clone()));
        let b = BigInt::from(b_raw);

        // STEP 4: Create shares of a using the masked b.
        // Party 0 sets a0 = b − r0 mod p. Every other party sets ai ≡ −ri mod p.
        let spdz_mod_range = spdz_modulus.div_floor(&BigInt::from(3));
        shares[0] = BigInt::mod_sub(&b, &masks[0], &spdz_mod_range);
        let mut shared_value = shares[0].clone();
        for i in 1..parties.m{
            shares[i] = BigInt::mod_sub(&BigInt::from(0), &masks[i], &spdz_mod_range);
            shared_value = shared_value + shares[i].clone();
        }
        // STEP 5: Each party publishes EncPK(ai) as well as an interval proof of plaintext knowledge.
        enc_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::from
                (Paillier::encrypt_with_chosen_randomness(
                    &EncryptionKey::from(ekj),
                    RawPlaintext::from(shares[i].clone()),
                    &Randomness(randoms_shares[i].clone()),)
                );
        });
        //zk that the shares are chosen correctly within range with range_proof_ni (Lindell et al 2017).
        for i in (0..parties.m) {
            let witness_shares = RangeWitness{
                x: shares[i].clone(),
                r_x:randoms_shares[i].clone(),    
            };
        
            let statement_shares = RangeStatement { 
                ek: EncryptionKey::from(ekj).clone(), 
                range: spdz_modulus.clone(), 
                e_x:enc_shares[i].clone() 
            };
        
            let proof_share = RangeProofNi::prove(&witness_shares, &statement_shares);
            proof_shares.push(proof_share.clone());
            
            (0..parties.m)
            .into_par_iter()
            .filter(|&j| j != i) // Filter out j == i
            .for_each(|j| {
                let verify = proof_share.verify(&statement_shares);
                
                if verify.is_err() {
                    eprintln!("Verification failed for party {} with share = {:?}", i, shares[i]);
                }

                assert!(verify.is_ok(), "Proof failed for element at index {}", i);
            });
        }
        
        // this is not secure because we give the value a, the global mac an the mac_shares in the plaintext
        // just for benchmark purposes
        GadgetThree{
            a : shared_value.clone(),
            a_shares: enc_shares.clone(),
            e_a: e_a.clone(),
            range_proof_shares: proof_shares,
            mac_shares: vec![BigInt::from(0); parties.m],
            global_mac_shares: vec![BigInt::from(0); parties.m],
            spdz_mod: spdz_modulus.clone(),
        }
    }    
    pub fn gen_mac(inp: &Self) -> Self{
        // genetate global mac key
        let global_mac_str:BigInt = BigInt::from_str_radix("17286628927586312160", 10).unwrap();
        let global_mac = BigInt::modulus(&global_mac_str, &inp.spdz_mod);
        // extract number of parties
        let m = inp.a_shares.len();
        // generate shares of global mac key
        let mut global_mac_shares: Vec<BigInt> = vec![BigInt::from(0); m];
        let mut sum_mac_shares: BigInt = BigInt::from(0);
        // generate additive shares of global mac key
        global_mac_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::sample_below(&inp.spdz_mod);
        });
        // generate mac on the shared value
        for i in 0..m-1{
            sum_mac_shares = sum_mac_shares + global_mac_shares[i].clone();
        }
        global_mac_shares[m-1] = BigInt::mod_sub(&global_mac, &sum_mac_shares, &inp.spdz_mod);
        
        let value_mac = BigInt::mod_mul(&inp.a, &global_mac, &inp.spdz_mod);
        
        // generate sharings of the mac
        let mut value_mac_shares: Vec<BigInt> = vec![BigInt::from(0); m];
        let mut sum_value_mac_shares: BigInt = BigInt::from(0);
        value_mac_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::sample_below(&inp.spdz_mod);
        });
        // generate mac on the shared value
        for i in 0..m-1{
            sum_value_mac_shares = sum_value_mac_shares + value_mac_shares[i].clone();
        }
        value_mac_shares[m-1] = BigInt::mod_sub(&value_mac, &sum_value_mac_shares, &inp.spdz_mod);
        GadgetThree{
            a : inp.a.clone(),
            a_shares: inp.a_shares.clone(),
            e_a: inp.e_a.clone(),
            range_proof_shares: inp.range_proof_shares.clone(),
            mac_shares: value_mac_shares.clone(),
            global_mac_shares,
            spdz_mod: inp.spdz_mod.clone(),
        }
        }
}

pub fn range(bits: &u32)-> BigInt {
    let bit_len = bits + K_PARAMETER;
    let big_val = BigInt::pow(&BigInt::from(2),bit_len);
    big_val
}

pub fn gen_mask(bits: &u32) -> BigInt {
    let bit_len = bits + K_PARAMETER;
    let big_val = BigInt::pow(&BigInt::from(2),bit_len);
    // this is for the range proof which currently has slack 1/3 from Lindel et all 2017.
    let upper = big_val.div_floor(&BigInt::from(3));
    let r = BigInt::sample_below(&upper);
    r
}

use std::iter;

use serde::{Deserialize, Serialize};

use paillier::{EncryptionKey, Paillier, RawPlaintext, RawCiphertext, Randomness};
use paillier::EncryptWithChosenRandomness;

use curv::arithmetic::traits::*;
use curv::BigInt;

use super::errors::IncorrectProof;
use super::DecryptJoint;
use crate::zkproofs::joint_decryption::*;
use crate::zkproofs::range_proof_ni::*;
use crate::zkproofs::utils::*;
use rayon::prelude::*;

use tokio::sync::mpsc;
use tokio::task;
use tokio::sync::broadcast;

//[DONE: ADD RANGE PROOFS IN STEP 1]
//[done: ADD RANGE PROOFS IN STEP 5]

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




#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GadgetThreeSingleParty {
    pub share: BigInt,
    //pub share_range: RangeProofNi,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GadgetThree {
    pub a: BigInt,
    pub a_shares: Vec<BigInt>,
    pub e_a: BigInt,
    pub range_proof_shares: Vec<RangeProofNi>,
    pub mac_shares: Vec<BigInt>,
    pub global_mac_shares: Vec<BigInt>,
    pub spdz_mod: BigInt,
    //pub share_range: RangeProofNi,
}
impl GadgetThree {
    pub  fn protocol(e_a:&BigInt, ekj: &EncryptionKeyJoint, sk_shares: &DecryptionKeyShared, parties: &NumParties, spdz_modulus: &BigInt) -> Self{

        let mut masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut encrypted_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut enc_shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut proof_shares: Vec<RangeProofNi> = Vec::new();
        
        // STEP 1:
        // each party generates a random value ri ∈ [0, 2^{|p|+κ} ]
        // Simulate Party 1 sending a message
        for i in 0..parties.m{

            let m = gen_mask(&MOD_BITS);
            masks.push(m);
            // create randomnesses for encryptions
            let r1 = sample_paillier_random(&ekj.n);
            randoms_masks.push(r1);
            let r2 = sample_paillier_random(&ekj.n);
            randoms_shares.push(r2);
        }
        encrypted_masks.par_iter_mut().enumerate().for_each(|(i, x)|{
            let e_m = Paillier::encrypt_with_chosen_randomness(
                &EncryptionKey::from(ekj),
                RawPlaintext::from(masks[i].clone()),
                &Randomness(randoms_masks[i].clone()),
            )
            .0
            .into_owned();
            // Add the encrypted element to the encrypted array
            *x = e_m;
        });

        //zk that the mask is chosen correctly within range with range_proof_ni (Lindell et al 2017).
        (0..parties.m).into_par_iter().for_each(|i| {
            let witness = RangeWitness{
                x: masks[i].clone(),
                r_x:randoms_masks[i].clone(),    
            };
        
            let statement = RangeStatement { 
                ek: EncryptionKey::from(ekj).clone(), 
                range: range(&MOD_BITS), 
                e_x:encrypted_masks[i].clone() 
            };
        
            let proof = RangeProofNi::prove(&witness, &statement);
            (0..parties.m)
            .into_par_iter()
            .filter(|&j| j != i) // Filter out j == i
            .for_each(|j| {
                let verify = proof.verify(&statement);
                
                if verify.is_err() {
                    eprintln!("Verification failed for party {} with: mask = {:?}", i, masks[i]);
                }

                assert!(verify.is_ok(), "Proof failed for element at index {}", i);
            });
        });
        
        // publish encrypted masks: publish enc(r_i) 
        // Rust’s standard library provides threads for concurrency 
        // and channels for inter-thread communication. 
        // Each party can be represented as a separate thread, 
        // and they can send and receive messages using channels (std::sync::mpsc).
        // for asynchronnous communication we can use async and tokio.
        // TODO ^

        // STEP 2:
        // each party upon receiving {Enc_pk(r_i)}_{i \in [m]} from each other party in the protocol
        // compputes the product with Enc_pk(a)
        // the result is Enc_pk(a + Σ r_i)
        let mut c: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        // double for loop is to show that each party does the computation of c.
        for i in 0..parties.m{
            c[i] = e_a.clone();
            //BigInt::mod_mul(&a, &encrypted_masks[1], &ekj.nn);
            for j in 1..parties.m{
                let c1 = encrypted_masks[j].clone();
                c[i] = BigInt::mod_mul(&c1, &c[i], &ekj.nn);
            } 
        }
        // STEP 3: the parties jointly decrypt c to get plaintext b
        let b_raw = Paillier::joint_decrypt(ekj, sk_shares, parties, &RawCiphertext::from(c[0].clone()));
        let b = BigInt::from(b_raw);

        // STEP 4: Create shares of a using the masked b.
        // Party 0 sets a0 = b − r0 mod p. Every other party sets ai ≡ −ri mod p.
        let spdz_mod_range = spdz_modulus.div_floor(&BigInt::from(3));
        shares[0] = BigInt::mod_sub(&b, &masks[0], &spdz_mod_range);
        let mut shared_value = shares[0].clone();
        for i in 1..parties.m{
            shares[i] = BigInt::mod_sub(&BigInt::from(0), &masks[i], &spdz_mod_range);
            shared_value = shared_value + shares[i].clone();
        }
        // STEP 5: Each party publishes EncPK(ai) as well as an interval proof of plaintext knowledge.
        enc_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::from
                (Paillier::encrypt_with_chosen_randomness(
                    &EncryptionKey::from(ekj),
                    RawPlaintext::from(shares[i].clone()),
                    &Randomness(randoms_shares[i].clone()),)
                );
        });
        //zk that the shares are chosen correctly within range with range_proof_ni (Lindell et al 2017).
        for i in (0..parties.m) {
            let witness_shares = RangeWitness{
                x: shares[i].clone(),
                r_x:randoms_shares[i].clone(),    
            };
        
            let statement_shares = RangeStatement { 
                ek: EncryptionKey::from(ekj).clone(), 
                range: spdz_modulus.clone(), 
                e_x:enc_shares[i].clone() 
            };
        
            let proof_share = RangeProofNi::prove(&witness_shares, &statement_shares);
            proof_shares.push(proof_share.clone());
            
            (0..parties.m)
            .into_par_iter()
            .filter(|&j| j != i) // Filter out j == i
            .for_each(|j| {
                let verify = proof_share.verify(&statement_shares);
                
                if verify.is_err() {
                    eprintln!("Verification failed for party {} with share = {:?}", i, shares[i]);
                }

                assert!(verify.is_ok(), "Proof failed for element at index {}", i);
            });
        }
        
        // this is not secure because we give the value a, the global mac an the mac_shares in the plaintext
        // just for benchmark purposes
        GadgetThree{
            a : shared_value.clone(),
            a_shares: enc_shares.clone(),
            e_a: e_a.clone(),
            range_proof_shares: proof_shares,
            mac_shares: vec![BigInt::from(0); parties.m],
            global_mac_shares: vec![BigInt::from(0); parties.m],
            spdz_mod: spdz_modulus.clone(),
        }
    }    
    pub fn gen_mac(inp: &Self) -> Self{
        // genetate global mac key
        let global_mac_str:BigInt = BigInt::from_str_radix("17286628927586312160", 10).unwrap();
        let global_mac = BigInt::modulus(&global_mac_str, &inp.spdz_mod);
        // extract number of parties
        let m = inp.a_shares.len();
        // generate shares of global mac key
        let mut global_mac_shares: Vec<BigInt> = vec![BigInt::from(0); m];
        let mut sum_mac_shares: BigInt = BigInt::from(0);
        // generate additive shares of global mac key
        global_mac_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::sample_below(&inp.spdz_mod);
        });
        // generate mac on the shared value
        for i in 0..m-1{
            sum_mac_shares = sum_mac_shares + global_mac_shares[i].clone();
        }
        global_mac_shares[m-1] = BigInt::mod_sub(&global_mac, &sum_mac_shares, &inp.spdz_mod);
        
        let value_mac = BigInt::mod_mul(&inp.a, &global_mac, &inp.spdz_mod);
        
        // generate sharings of the mac
        let mut value_mac_shares: Vec<BigInt> = vec![BigInt::from(0); m];
        let mut sum_value_mac_shares: BigInt = BigInt::from(0);
        value_mac_shares.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::sample_below(&inp.spdz_mod);
        });
        // generate mac on the shared value
        for i in 0..m-1{
            sum_value_mac_shares = sum_value_mac_shares + value_mac_shares[i].clone();
        }
        value_mac_shares[m-1] = BigInt::mod_sub(&value_mac, &sum_value_mac_shares, &inp.spdz_mod);
        GadgetThree{
            a : inp.a.clone(),
            a_shares: inp.a_shares.clone(),
            e_a: inp.e_a.clone(),
            range_proof_shares: inp.range_proof_shares.clone(),
            mac_shares: value_mac_shares.clone(),
            global_mac_shares,
            spdz_mod: inp.spdz_mod.clone(),
        }
        }
}

pub fn range(bits: &u32)-> BigInt {
    let bit_len = bits + K_PARAMETER;
    let big_val = BigInt::pow(&BigInt::from(2),bit_len);
    big_val
}

pub fn gen_mask(bits: &u32) -> BigInt {
    let bit_len = bits + K_PARAMETER;
    let big_val = BigInt::pow(&BigInt::from(2),bit_len);
    // this is for the range proof which currently has slack 1/3 from Lindel et all 2017.
    let upper = big_val.div_floor(&BigInt::from(3));
    let r = BigInt::sample_below(&upper);
    r
}

