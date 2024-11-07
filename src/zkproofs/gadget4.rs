
use std::iter;


use serde::{Deserialize, Serialize};

use paillier::{EncryptionKey, Paillier, RawPlaintext, RawCiphertext, Randomness};
use paillier::EncryptWithChosenRandomness;

use curv::arithmetic::traits::*;
use curv::BigInt;

use super::errors::IncorrectProof;
use super::{DecryptJoint, GadgetThree};
use crate::zkproofs::joint_decryption::*;
use crate::zkproofs::range_proof_ni::*;
use crate::zkproofs::gadget3::*;
use crate::zkproofs::utils::*;
use rayon::prelude::*;
use tokio::sync::broadcast;

const A_BITS: u32 = 32;

/// 
/// Gadget 4. 
/// For m parties, each party holding the public key PK 
/// and a share of  the secret key SK, 
/// given 1. public ciphertext EncPK(a), 2. encrypted spdz input shares EncPK(b_i), 
///       3. encrypted spdz MACs EncPK(c_i), 4. interval proofs  of plaintext knowledge for (1), (2), (3)
/// each party verifies that 1. a = Σ b_i mod p, 
///                          2. b_i s are valid spdz shares, 
///                          3. c_i s are valid MACs on b_i s.
/// 

/// 
/// Protocol. The protocol proceeds as follows:
/// 1. Each party Pi verifies that EncPK(a), EncPK(b_j), EncPK(c_j) with j \in [1,m]/i are within range.
    /// e.g b_j, c_j \in [0,p] 
/// 2. Each party Pi takes as input the published {EncPK (b_j)}^m_{j=1} and compute homomorphically
    /// Their product to obtain EncPK(Σ b_j). 
    /// The product of EncPK(a) with  EncPK(-Σ b_j) (exponentiation with EncPK(-1)) to obtain E_d = EncPK (a - Σ b_i ).
/// 3. Each party Pi generates a random value ri ∈ [0, 2^{|a|+κ} ] and encrypts it, 
    /// where κ is a statistical security parameter. 
    /// Each party should also generate an interval plaintext proof of knowledge of ri , 
    /// then publish EncPK (ri ) along with the proofs. 
/// 4. Each party calculates E_f = E_d Π(ΕncPK(r_i)^p) = EncPK ((a - Σ b_i) + Σ (p r_i) )
    /// We assume that  log |m| + |p| + |a| + |κ| < |n|.  
/// 5. All parties jointly decrypt E_f to get plaintext e_f.
/// 6. Each party locally checks that e_f is a multiple of  p. If not, abort.
/// 7.
/// 8.
/// 9.
/// 



#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct GadgetFour {
    pub shares: Vec<BigInt>,
    //pub share_range: RangeProofNi,
}
impl GadgetFour {
    pub fn verify(a:&BigInt, b: &BigInt) -> Result<(), IncorrectProof> {
        let check_mod = BigInt::is_multiple_of(a, b);
        match check_mod == true{
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
    pub fn sub_protocol (c: &Vec<BigInt>
                       , d: &BigInt
                       , inp: &GadgetThree
                       , ekj: &EncryptionKeyJoint
                       , sk_shares: &DecryptionKeyShared
                       , parties: &NumParties
                       , spdz_modulus: &BigInt) 
                       -> () {
        
        let mut masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut randoms_shares: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        let mut encrypted_masks: Vec<BigInt> = vec![BigInt::from(0); parties.m];     
        let mut e_d: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        
         
        // and finally, 
        // for shares: E_d[i] =  EncPK (a - Σ b_i ) as: The product of EncPK(a) with  EncPK(-Σ b_j)  
        // for macs: E_d[i] = EncPK(Σci - αΣbi)
        e_d.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::mod_mul(&c[i], &d, &ekj.nn); 
        }  );

        // Step 3:
        // each party generates a random value ri ∈ [0, 2^{|a|+κ} ]
        for i in 0..parties.m{
            let m = gen_mask(&A_BITS);
            masks.push(m);
            // create randomnesses for encryptions
            let r1 = sample_paillier_random(&ekj.n);
            randoms_masks.push(r1);
            /* let r2 = sample_paillier_random(&ekj.n);
            randoms_shares.push(r2); */
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
                range: range(&A_BITS), 
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
        // STEP 4:
        //Each party calculates E_f = E_d Π(ΕncPK(r_i)^p) = EncPK ((a - Σ b_i) + Σ (p r_i) )
        let mut enc_e_f: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        enc_e_f.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = e_d[i].clone();
            for j in 0..parties.m{
                let enc_r_p = BigInt::mod_pow(&encrypted_masks[i], spdz_modulus, &ekj.nn);
                *x = BigInt::mod_mul(x, &enc_r_p, spdz_modulus);
            }
        });
        
        // STEP 5:
        // joint decryption of E_f to obtain e_f (the masked difference of a - shares of a)
        // If two ciphertexts encrypt plaintexts that are equivalent to each other, they must satisfy that 
        // a ≡ b mod p or a = b + ηp. Thus, if we take the difference of the two ciphertexts, this difference must be ηp 
        let cipher = RawCiphertext::from(enc_e_f[0].clone());
        let e_f = Paillier::joint_decrypt(ekj, sk_shares, parties, &cipher);
        
        //STEP 6: VERIFY e_f divides sdpz_mod.
        (0..parties.m).into_par_iter().for_each(|i| {

            let verify = GadgetFour::verify(&BigInt::from(e_f.clone()), spdz_modulus);
            assert!(verify.is_ok());
        });
    }
    pub fn protocol(inp: &GadgetThree
                 , ekj: &EncryptionKeyJoint
                 , sk_shares: &DecryptionKeyShared
                 , parties: &NumParties
                 , spdz_modulus: &BigInt) 
                 -> () 
    {
                    
        // step 1:
        // verify ranges
        

        // step 2:
        // each party takes as input {Enc_pk(b_i)}_{i \in [m]}'
        // and compputes their product 
        // the result is Enc_pk(Σ b_i)
        
        let mut c: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        // double for loop is to show that each party does the computation of c.
        c.par_iter_mut().enumerate().for_each(|(i, x)|{
            //BigInt::mod_mul(&a, &encrypted_masks[1], &ekj.nn);
            for j in 0..parties.m{
                let c1 = inp.a_shares[j].clone();
                *x = BigInt::mod_mul(&c1, x, &ekj.nn);
            } 
        });
        
        // then computes c = EncPK(-Σ b_j) (exponentiation with EncPK(n-1)) 
        let exp = BigInt::sub(&ekj.n, &BigInt::from(1));
        c.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::mod_pow(x, &exp, &ekj.nn); 
        } );
        // and d = EncPK(a)
        let d = &inp.e_a;
        
        // steps 3-6:
        // run the subprotcol with extra inputs c = -Σbi, d=EncPK(a)
        GadgetFour::sub_protocol(&c, &d, inp, ekj, sk_shares, parties, spdz_modulus);

        // check correctness of SPDZ macs
        // step 2: compute c = EncPK(-αΣbi)

        // compute global mac key alpha by adding the shares.
        let mut alpha : BigInt = BigInt::from(0);
        for i in 0..parties.m{
            alpha = BigInt::mod_add(&alpha, &inp.global_mac_shares[i], spdz_modulus);
        }
        // compute c = EncPK(-αΣbi) by exponetiating c with alpha for each player i. 
        c.par_iter_mut().enumerate().for_each(|(i, x)|{
            *x = BigInt::mod_pow(x, &alpha, &ekj.nn);
        } );

        // compute  d = EncPK(Σci)
        let mut d: Vec<BigInt> = vec![BigInt::from(0); parties.m];
        // double for loop is to show that each party does the computation of c.
        d.par_iter_mut().enumerate().for_each(|(i, x)|{

            //BigInt::mod_mul(&a, &encrypted_masks[1], &ekj.nn);
            for j in 0..parties.m{
                let c1 = inp.mac_shares[j].clone();
                *x = BigInt::mod_mul(&c1, x, &ekj.nn);
            } 
        });
         // steps 3-6:
        // run the subprotcol with extra inputs c = -Σbi, d=EncPK(a)
        GadgetFour::sub_protocol(&c, &d[0], inp, ekj, sk_shares, parties, spdz_modulus);
    }
}
    
//cargo 'test' '--package' 'zk-paillier' '--lib' '--' 'zkproofs::gadget4::tests::test_gadget4' '--exact' '--show-output'
#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::EncryptWithChosenRandomness;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;

    
    use paillier::RawPlaintext;
    use tokio::time::Instant;

    use crate::zkproofs::gadget3::*;
    use crate::zkproofs::gadget4::*;
    use crate::zkproofs::joint_decryption::*;
    use crate::zkproofs::traits::*;
    use crate::zkproofs::array::*;
    use tokio::sync::broadcast;

    const RANGE_BITS: usize = 32; //for elliptic curves with 256bits for example


    #[test]
    fn test_gadget4() {
        let parties = NumParties{m: 3};
        let spdz_mod:BigInt = BigInt::from_str_radix("12492985848356528369", 10).unwrap();
        // generate classic paillier keys
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        // create necessary parameters for joint decryption Paillier 
        // and put them inside public and private key
        let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

        // create shared secret key     
        let shares = Paillier::additive_shares(&ekj, &dkj, &parties).dks;
        let sk_shares = DecryptionKeyShared{
            dks: shares,
        };

        
        let range = BigInt::sample(RANGE_BITS);
        // Key generation

        let n= 1;
        // generate and encrypt array X
        let array_x = ArrayPaillier::gen_array_no_range(n, &EncryptionKey::from(&ekj));
        let array_r_x = ArrayPaillier::gen_array_randomness(n, &EncryptionKey::from(&ekj));
        let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &EncryptionKey::from(&ekj));  
        
        
        let mut inp: Vec<GadgetThree> =  Vec::new();
        // Measure gadget3 time without keygeneration and key sharing benchmarks
        let start = Instant::now();
            let input = GadgetThree::protocol(&array_e_x[0], &ekj, &sk_shares, &parties, &spdz_mod);
        let duration = start.elapsed();
        println!("Time elapsed in gadget3: {:?}", duration);
       
        let start = Instant::now();
            GadgetFour::protocol(&input, &ekj, &sk_shares, &parties, &spdz_mod);
        let duration2 = start.elapsed();    

        println!("Time elapsed in gadget4: {:?}", duration2);

    }
}    