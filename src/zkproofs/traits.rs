//! Abstract operations exposed by the library.

use curv::BigInt;
pub trait KeyGenerationJoint<EK, DK, EKJ, DKJ> {
    fn joint_dec_params(ek: &EK, dk: &DK) -> (EKJ, DKJ);
}

/// Secure generation of additive shares of the blinded secret key
pub trait KeySharing<EK, DK, NP, DKS> {
    /// Generate additive shares modulo nφ(n)
    fn additive_shares(ek: &EK, dk: &DK, m: &NP ) -> DKS;
}


pub trait DecryptJoint<EK, DK, NP, CT, PT> {
    /// Decrypt ciphertext `c` using key `dk` into a plaintext.
    fn joint_decrypt(ek: &EK, dk: &DK, p: &NP, c: CT) -> PT;
}