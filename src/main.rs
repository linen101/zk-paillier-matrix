mod serialize;
pub mod zkproofs;



use paillier::traits::KeyGeneration;
use paillier::EncryptionKey;
use paillier::Paillier;

use zk_paillier::zkproofs::*;



fn gen_keys() -> EncryptionKey{
    let (ek, _) = Paillier::keypair().keys();

    // Return  the encryption key 
    ek
}


fn main() {
    let n:usize = 3;
    let d:usize = 2;
    let ek = gen_keys();

    // generate matrix A
    let matrix_a= MatrixPaillier::gen_matrix(n, d, &ek);
    // generate randomness for matrix A
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    // encrypt A
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    // generate matrix B
    let matrix_b= MatrixPaillier::gen_matrix(d, n, &ek);
    // generate randomness for matrix B
    let matrix_r_b = MatrixPaillier::generate_randomness(d, n, &ek);
    // encrypt B
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

    // plaintext plaintext matrix proof
    // compute plaintext dot products C[]
    let matrix_c = MulDotProducts::compute_plaintext_dot_products(&matrix_a, &matrix_b);
    // compute encrypted dot products, and return with their randomness r_c[]
    let (matrix_e_c, matrix_r_c) = MulDotProducts::compute_encrypted_dot_products(&matrix_c, &ek);


    let matrix_witness = MatrixWitness {
        matrix_a,
        matrix_b:matrix_b.clone(),
        matrix_c:matrix_c.clone(),
        matrix_r_a,
        matrix_r_b:matrix_r_b.clone(),
        matrix_r_c:matrix_r_c.clone(),
    };

    let matrix_statement = MatrixStatement {
        ek:ek.clone(),
        matrix_e_a:matrix_e_a.clone(),
        matrix_e_b:matrix_e_b.clone(),
        matrix_e_c:matrix_e_c.clone(),
    };

    MatrixDots::matrix_dots_mul_prove_verify(&matrix_statement, &matrix_witness);

    /// plaintext - ciphertext matrix proof
    // compute encrypted dot products with unknown decryption, and return with their randomness r_c[]
    let (matrix_e_c, matrix_r_c) = EncDotProducts::compute_encrypted_dot_products_homo(&matrix_e_a, &matrix_b, &ek);    

    let matrix_ciph_witness = MatrixCiphWitness {
        matrix_b,
        matrix_r_b,
        matrix_r_c,
    };

    let matrix_ciph_statement = MatrixCiphStatement {
        ek,
        matrix_e_a,
        matrix_e_b,
        matrix_e_c,
    };

    EncMatrixDots::matrix_dots_mul_prove_verify(&matrix_ciph_statement, &matrix_ciph_witness);

}