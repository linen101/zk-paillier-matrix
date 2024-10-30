use std::iter;

use serde::{Deserialize, Serialize};

use paillier::{EncryptionKey, Paillier, KeyGeneration};
use curv::arithmetic::traits::*;
use curv::BigInt;

use super::errors::IncorrectProof;

use crate::zkproofs::fujisaki_okamoto_commitment::Commitment;
use crate::zkproofs::fujisaki_okamoto_commitment::PublicParamsCom;

// |b| = 512 bits,
const RANGE_BITS: usize = 32; //for elliptic curves with 32bits for example
// t = 80
const SOUNDNESS_PARAMETER : usize = 80;
// l = 40
const ZK_PARAMETER: usize = 40;
// s1 = 40
const S1_PARAMETER: usize = 40;
// s2 = 552
const S2_PARAMETER: usize = 552;


/// This proof is a non-interactive version of Boudot's range proof
/// Protocol:
///
/// 1. P picks 
/// 2. using Fiat-Shamir the parties computes a challenge e
/// 3. P sends d = , d1 = , d2 = 
/// 4. V checks:
///     
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqComProof {
    pub e: BigInt,
    pub w1: BigInt,
    pub w2: BigInt,
    pub d: BigInt,
    pub d1: BigInt,
    pub d2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqComWitness {
    pub x: BigInt,
    pub r1: BigInt,
    pub r2: BigInt,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EqComStatement {
    pub n: BigInt,
    pub e1: BigInt,
    pub e2: BigInt,
}

impl EqComProof {
    pub fn prove(witness: &EqComWitness, statement: &EqComStatement, pp1: &PublicParamsCom, pp2: &PublicParamsCom) -> Self {
        // P picks random w, eta1, eta2 in [1, 2^{l+t}b - 1], [1, 2^{l+t+s1}b - 1], [1, 2^{l+t+s2}b - 1]
        let w = BigInt::sample(SOUNDNESS_PARAMETER+ZK_PARAMETER+RANGE_BITS);
        let eta1 = BigInt::sample(SOUNDNESS_PARAMETER+ZK_PARAMETER+RANGE_BITS+S1_PARAMETER);        
        let eta2 = BigInt::sample(SOUNDNESS_PARAMETER+ZK_PARAMETER+RANGE_BITS+S2_PARAMETER);

        // P sets the commitment params of w1
        let com1 = Commitment {
            m: w.clone(),
            r: eta1.clone(),
        };
        // P computes W_1 = g_1^w h_1^eta1 mod n
        let w1 = Commitment::commitment(&com1, &pp1);

        // P sets the commitment params of w2
        let com2 = Commitment {
            m: w.clone(),
            r: eta2.clone(),
        };
        // P computes W_1 = g_1^w h_1^eta1 mod n
        let w2 = Commitment::commitment(&com2, &pp2);

        // compute random challenge e
        let e = super::compute_digest(
            iter::once(&statement.n)
                .chain(iter::once(&statement.e1))
                .chain(iter::once(&statement.e2))
                .chain(iter::once(&w1))
                .chain(iter::once(&w2)),
        );
        let ex = BigInt::mul(&e, &witness.x);
        let d = BigInt:: add(&w, &ex);

        let er1 = BigInt::mul(&e, &witness.r1);
        let d1 = BigInt:: add(&eta1, &er1);

        let er2 = BigInt::mul(&e, &witness.r2);
        let d2 = BigInt:: add(&eta2, &er2);

        EqComProof {
            e,
            w1,
            w2,
            d,
            d1,
            d2,
        }
        
    }

    pub fn verify(&self, statement: &EqComStatement, pp1: &PublicParamsCom, pp2: &PublicParamsCom) -> Result<(), IncorrectProof> {
        // compute random challenge e
        let e = super::compute_digest(
            iter::once(&statement.n)
                .chain(iter::once(&statement.e1))
                .chain(iter::once(&statement.e2))
                .chain(iter::once(&self.w1))
                .chain(iter::once(&self.w2)),
        );

        let g1_d = BigInt::mod_pow(&pp1.g, &self.d, &statement.n);
        let h1_d1 = BigInt::mod_pow(&pp1.h, &self.d1, &statement.n);
        let g1_d_h1_d1 = BigInt::mod_mul(&g1_d, &h1_d1, &statement.n);
        let zero = BigInt::from(0);
        let minus_e = BigInt::sub(&zero, &e);
        let e1_e = BigInt::mod_pow(&statement.e1, &minus_e, &statement.n);
        let g1_d_h1_d1_e1_e = BigInt::mod_mul(&g1_d_h1_d1, &e1_e, &statement.n);

        let g2_d = BigInt::mod_pow(&pp2.g, &self.d, &statement.n);
        let h2_d2 = BigInt::mod_pow(&pp2.h, &self.d2, &statement.n);
        let g2_d_h2_d2 = BigInt::mod_mul(&g2_d, &h2_d2, &statement.n);
        let e2_e = BigInt::mod_pow(&statement.e2, &minus_e, &statement.n);
        let g2_d_h2_d2_e2_e = BigInt::mod_mul(&g2_d_h2_d2, &e2_e, &statement.n);
        match g1_d_h1_d1_e1_e == self.w1 && g2_d_h2_d2_e2_e == self.w2 {
            true => Ok(()),
            false => Err(IncorrectProof),
        }
    }
}

/* 
#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use paillier::core::Randomness;
    use paillier::traits::KeyGeneration;
    use paillier::Paillier;
    use paillier::RawPlaintext;

    use crate::zkproofs::boudot_range_proof::*;
    use crate::zkproofs::fujisaki_okamoto_commitment;
    use crate::zkproofs::fujisaki_okamoto_commitment::*;
    #[test]
    fn test_mul_proof() {
        let ek = fujisaki_okamoto_commitment::gen_keys();
        let a = BigInt::sample(RANGE_BITS);
        
        let r_a = sample_paillier_random(&ek.n);
        let r_b = sample_paillier_random(&ek.n);
        let r_c = sample_paillier_random(&ek.n);

        let e_a = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(a.clone()),
            &Randomness(r_a.clone()),
        )
        .0
        .into_owned();

        let e_b = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(b.clone()),
            &Randomness(r_b.clone()),
        )
        .0
        .into_owned();

        let e_c = Paillier::encrypt_with_chosen_randomness(
            &ek,
            RawPlaintext::from(c.clone()),
            &Randomness(r_c.clone()),
        )
        .0
        .into_owned();

        let witness = MulWitness {
            a,
            b,
            c,
            r_a,
            r_b,
            r_c,
        };

        let statement = MulStatement { ek, e_a, e_b, e_c };

        let proof = MulProof::prove(&witness, &statement);
        let verify = proof.verify(&statement);
        assert!(verify.is_ok());
    }
*/