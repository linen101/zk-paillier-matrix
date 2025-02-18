use std::env;
use std::time::Instant;
use paillier::{Paillier, EncryptionKey, RawCiphertext};
use paillier::traits::{KeyGeneration, EncryptWithChosenRandomness};
use zk_paillier::zkproofs::*;
use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::borrow::Borrow
use std::sync::Arc;
use std::{thread, time::Duration};

//cargo run  2 10 0


pub fn start_listener(port: u16) -> TcpListener {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("Failed to bind TCP listener");
    println!("Listening on port {}", port);
    listener
}

// Constants
const RANGE_BITS: usize = 16;
const SECURITY_PARAMETER: usize = 128;

// Generate encryption keys
fn gen_keys() -> EncryptionKey {
    let (ek, _) = Paillier::keypair().keys();
    ek
}

// Joint Decryption Initialization
fn joint_dec_init(array_size: usize, parties: &NumParties) {
    let (ek, dk) = Paillier::keypair_safe_primes().keys();
    let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

    let shares = Paillier::additive_shares(&ekj, &dkj, &parties).dks;
    let key_shares = DecryptionKeyShared { dks: shares };

    let array_x = ArrayPaillier::gen_array_no_range(array_size, &ek);
    let array_r_x = ArrayPaillier::gen_array_randomness(array_size, &ek);
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &ek);

    let start = Instant::now();
    (0..array_size).into_par_iter().for_each(|i| {
        let ciphertext = RawCiphertext::from(array_e_x[i].clone());
        Paillier::joint_decrypt(&ekj, &key_shares, &parties, &ciphertext);
    });
    let duration = start.elapsed();

    println!(
        "Time elapsed for array size ({}) during joint decryption: {:?}",
        array_size, duration
    );
}

// Benchmark Proving & Verifying Matrix Multiplication
fn benchmark_prove_verify(
    matrix_size: (usize, usize),
    parties: &NumParties,
    party_id: &u16,
    address: &str,
    listener: &TcpListener,
) {
    let (n, d) = matrix_size;

    let ek = gen_keys();
    let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    let matrix_b = MatrixPaillier::gen_matrix(d, 1, &ek);
    let matrix_r_b = MatrixPaillier::generate_randomness(d, 1, &ek);
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

    let matrix_c = MulDotProducts::compute_plaintext_dot_products(&matrix_a, &matrix_b);
    let (matrix_e_c, matrix_r_c) = MulDotProducts::compute_encrypted_dot_products(&matrix_c, &ek);

    let result_matrices = MatrixDots::compute_encrypted_matrix_from_plaintext_dots(&matrix_c, &ek, &parties);

    let matrix_witness = MatrixWitness {
        matrix_a,
        matrix_b: matrix_b.clone(),
        matrix_d: result_matrices.matrix_d.clone(),
        matrix_c: matrix_c.clone(),
        matrix_r_a,
        matrix_r_b: matrix_r_b.clone(),
        matrix_r_d: result_matrices.matrix_r_d.clone(),
        matrix_r_c: matrix_r_c.clone(),
    };

    let matrix_statement = MatrixStatement {
        ek: ek.clone(),
        matrix_e_a: matrix_e_a.clone(),
        matrix_e_b: matrix_e_b.clone(),
        matrix_e_d: result_matrices.matrix_e_d.clone(),
        matrix_e_c: matrix_e_c.clone(),
    };

    let start = Instant::now();
    MatrixDots::matrix_dots_mul_prove_verify(
        &matrix_statement,
        &matrix_witness,
        parties,
    );
    let duration = start.elapsed();

    println!(
        "Time elapsed for matrix size ({}, {}) during proving/verifying: {:?}",
        n, d, duration
    );
}
// Benchmark Proving & Verifying Matrix Multiplication unknown plaintext
fn benchmark_enc_prove_verify(matrix_size: (usize, usize), parties:&NumParties) {
    // in gadget 1,2 the dimensions of the resulted matrix needed to proof correctness
    // are [d,d]
    let n = matrix_size.0;
    let d = matrix_size.1;
    let ek = gen_keys();

    // generate randomness for zero encryption 
    let matrix_r_d  = MatrixPaillier::generate_randomness(n, d, &ek);
    
    // generate and encrypt matrix A
    let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    // generate and encrypt matrix B
    // we dont implement the linear transformation described in helen
    // but the point is that the second matrix is of size [d,1]
    let matrix_b = MatrixPaillier::gen_matrix(d, 1, &ek);
    let matrix_r_b = MatrixPaillier::generate_randomness(d, 1, &ek);
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

    // Compute encrypted dot products with homomorphism
    let (matrix_e_c, matrix_r_c) = EncMatrixDots::compute_encrypted_dot_products_homo(&matrix_e_a, &matrix_b, &ek, &parties);
    let e_c = EncMatrixDots{
        matrix_e_c:matrix_e_c.clone(),
    };
    let matrix_e_d = EncMatrixDots::compute_encrypted_matrix_from_dots(&e_c, &ek, &parties);
    let matrix_ciph_witness = MatrixCiphWitness {
        matrix_b,
        matrix_r_b,
        matrix_r_d,
        matrix_r_c,
    };

    let matrix_ciph_statement = MatrixCiphStatement {
        ek,
        matrix_e_a,
        matrix_e_b,
        matrix_e_d,
        matrix_e_c,
    };

    // Measure proving/verifying time
    let start = Instant::now();
    EncMatrixDots::matrix_dots_mul_prove_verify(&matrix_ciph_statement, &matrix_ciph_witness, parties);
    let duration = start.elapsed();

    println!("Time elapsed for matrix size ({}, {}) in encrypted proving/verifying MATRIX CIPHERTEXT MULT: {:?}", n, d, duration);
}

fn benchmark_enc_dots_homo(matrix_size: (usize, usize), parties:&NumParties) {
    // in gadget 1,2 the dimensions of the resulted matrix needed to proof correctness
    // are [d,d]
    let n = matrix_size.0;
    let d = matrix_size.1;
    let ek = gen_keys();

    // generate randomness for zero encryption 
    let matrix_r_d  = MatrixPaillier::generate_randomness(n, d, &ek);
    
    // generate and encrypt matrix A
    let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    // generate and encrypt matrix B
    // we dont implement the linear transformation described in helen
    // but the point is that the second matrix is of size [d,1]
    let matrix_b = MatrixPaillier::gen_matrix(d, 1, &ek);
    let matrix_r_b = MatrixPaillier::generate_randomness(d, 1, &ek);
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);
    // Measure proving/verifying time
    let start = Instant::now();
    // Compute encrypted dot products with homomorphism
    let (matrix_e_c, matrix_r_c) = EncMatrixDots::compute_encrypted_dot_products_homo(&matrix_e_a, &matrix_b, &ek, &parties);
    let e_c = EncMatrixDots{
        matrix_e_c:matrix_e_c.clone(),
    };
    let matrix_e_d = EncMatrixDots::compute_encrypted_matrix_from_dots(&e_c, &ek, &parties);
    let duration = start.elapsed();    

    println!("Time elapsed for matrix size ({}, {}) in encrypted dot products compute: {:?}", n, d, duration);
}

// Benchmark Range Proof Verification
fn benchmark_range_prove_verify(array_size: usize, parties: &NumParties) {
    let ek = gen_keys();
    let range = BigInt::sample(RANGE_BITS);

    let array_x = ArrayPaillier::gen_array(array_size, &range);
    let array_r_x = ArrayPaillier::gen_array_randomness(array_size, &ek);
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &ek);

    let witness = ArrayRangeWitness {
        array_x,
        array_r_x: array_r_x.clone(),
    };

    let statement = ArrayRangeStatement {
        ek: ek.clone(),
        range,
        array_e_x: array_e_x.clone(),
    };

    let start = Instant::now();
    ArrayRangeProofNi::array_range_prove_verify(&statement, &witness, parties);
    let duration = start.elapsed();

    println!(
        "Time elapsed for array size ({}) during proving/verifying RANGE: {:?}",
        array_size, duration
    );
}

fn benchmark_gadget4(array_size: usize, spdz_mod: &BigInt, parties: &NumParties){
    // generate classic paillier keys
    let (ek, dk) = Paillier::keypair_safe_primes().keys();

    // create necessary parameters for joint decryption Paillier 
    // and put them inside public and private key
    let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

    // create shared secret key     
    let shares = Paillier::additive_shares(&ekj, &dkj, parties).dks;
    let sk_shares = DecryptionKeyShared{
        dks: shares,
    };

    let n = array_size;
    
    let range = BigInt::sample(RANGE_BITS);
    // Key generation
    let ek = gen_keys();

    // generate and encrypt array X
    let array_x = ArrayPaillier::gen_array_no_range(n, &EncryptionKey::from(&ekj));
    let array_r_x = ArrayPaillier::gen_array_randomness(n, &EncryptionKey::from(&ekj));
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &EncryptionKey::from(&ekj));  
    
    let input =  GadgetThree {
         a: BigInt::from(0),
         a_shares: vec![BigInt::from(0); parties.m],
         e_a: BigInt::from(0),
         range_proof_shares: Vec::new(),
         mac_shares: vec![BigInt::from(0); parties.m],
         global_mac_shares: vec![BigInt::from(0); parties.m],
         spdz_mod: BigInt::from(0),
        //pub share_range: RangeProofNi,
    };
    let mut inp: Vec<GadgetThree>  = vec![input; n];
    // Measure gadget3 time without keygeneration and key sharing benchmarks
    let start = Instant::now();
    inp.par_iter_mut().enumerate().for_each(|(i, x)|{
        *x = GadgetThree::protocol(&array_e_x[i], &ekj, &sk_shares, parties, spdz_mod);
    });
    let duration = start.elapsed();

    println!("Time elapsed in gadget3: {:?}", duration);

    let start1 = Instant::now();
    (0..n).into_par_iter().for_each(|i| {
    
        GadgetFour::protocol(&inp[i], &ekj, &sk_shares, parties, spdz_mod);
    });
    let duration1 = start1.elapsed();
    println!("Time elapsed in gadget4: {:?}", duration1);

}

fn benchmark_gadget3(array_size: usize, spdz_mod: &BigInt, parties: &NumParties){
    // generate classic paillier keys
    let (ek, dk) = Paillier::keypair_safe_primes().keys();
    // public modulus n
    let n = ek.n.clone();
    // public modulus n^2
    let nn = ek.nn.clone();

    // create necessary parameters for joint decryption Paillier 
    // and put them inside public and private key
    let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

    // create shared secret key     
    let shares = Paillier::additive_shares(&ekj, &dkj, parties).dks;
    let sk_shares = DecryptionKeyShared{
        dks: shares,
    };
    /*/ test values
    let x = BigInt::from(17);

    let r = BigInt::sample_below(&ek.n);
    let ciphertext = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(x.clone()),
        &Randomness::from(r.clone()),
    );
    let a = BigInt::from(ciphertext);
    */
    let n = array_size;
    
    let range = BigInt::sample(RANGE_BITS);
    // Key generation
    let ek = gen_keys();

    // generate and encrypt array X
    let array_x = ArrayPaillier::gen_array_no_range(n, &EncryptionKey::from(&ekj));
    let array_r_x = ArrayPaillier::gen_array_randomness(n, &EncryptionKey::from(&ekj));
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &EncryptionKey::from(&ekj));  
    
    
    
    // Measure gadget3 time without keygeneration and key sharing benchmarks
    let start = Instant::now();
    (0..n).into_par_iter().for_each(|i| {
    
        GadgetThree::protocol(&array_e_x[i], &ekj, &sk_shares, parties, spdz_mod);
    });
    let duration = start.elapsed();

    println!("Time elapsed in gadget3: {:?}", duration);

}



// Main function to accept user input and execute all benchmarks
fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage: {} <num_players> <matrix_size> <player_id>", args[0]);
        return;
    }

    let num_players: usize = args[1].parse().expect("Invalid number of players");
    let matrix_size: usize = args[2].parse().expect("Invalid matrix size");
    let player_id: u16 = args[3].parse().expect("Invalid player ID");

    let base_port = 5000;
    let address = format!("127.0.0.1:{}", base_port + player_id);
    let listener = TcpListener::bind(&address).expect("Failed to bind TCP listener");

    let parties = NumParties { m: num_players };
    let spdz_mod = BigInt::from(3305569710899353_u64);

    // Execute all benchmarks sequentially
    println!("\n[1] Running Joint Decryption...");
    joint_dec_init(matrix_size, &parties);

    println!("\n[2] Running Gadget1 Execution...");
    benchmark_enc_prove_verify((matrix_size, matrix_size),  &parties);

    println!("\n[2] Running Gadget2 Execution...");
    benchmark_prove_verify((matrix_size, matrix_size), &parties, &player_id, &address, &listener);

    println!("\n[3] Running Gadget4 Execution...");
    benchmark_gadget4(matrix_size, &spdz_mod, &parties);

    println!("\n[4] Running Range Proof Verification...");
    benchmark_range_prove_verify(matrix_size, &parties);

    println!("\n[4] Running Enc Dot Product Compute...");
    benchmark_enc_dots_homo(matrix_size, &parties);
}