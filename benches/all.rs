use paillier::{Paillier, EncryptionKey, RawCiphertext, Randomness};
use paillier::traits::{KeyGeneration, EncryptWithChosenRandomness};
use zk_paillier::zkproofs::*;
use curv::BigInt;
use curv::arithmetic::traits::Samplable;
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkGroup, SamplingMode};
use std::time::Instant;
use rayon::prelude::*; 

const RANGE_BITS: usize = 16; //for elliptic curves with 256bits for example
const SECURITY_PARAMETER: usize = 128;


fn custom_criterion() -> Criterion {
    Criterion::default()
        //.measurement_time(std::time::Duration::from_millis(100)) // Lower measurement time
        .sample_size(10) // Specify a smaller sample size
}

fn gen_keys() -> EncryptionKey{
    let (ek, _) = Paillier::keypair().keys();

    // Return  the encryption key 
    ek
}

fn joint_dec_init(array_size: usize,  parties: &NumParties)  {

    // generate classic paillier keys
    let (ek, dk) = Paillier::keypair_safe_primes().keys();
    // public modulus n
    let n = ek.n.clone();
    // public modulus n^2
    let nn = ek.nn.clone();

    // create necessary parameters for joint decryption Paillier 
    // and put them inside public and private key
    let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

    // number of parties in the protocol        
    let shares = Paillier::additive_shares(&ekj, &dkj, &parties).dks;
    let key_shares = DecryptionKeyShared{
        dks: shares,
    };


    // generate and encrypt array X
    let array_x = ArrayPaillier::gen_array_no_range(array_size, &ek);
    let array_r_x = ArrayPaillier::gen_array_randomness(array_size, &ek);
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &ek);

    // Measure proving/verifying time
    let start = Instant::now();
    (0..array_size).into_par_iter().for_each(|i| {
        let ciphertext = RawCiphertext::from(array_e_x[i].clone());
        Paillier::joint_decrypt(&ekj, &key_shares, &parties, &ciphertext);
    });
    let duration = start.elapsed();

    println!("Time elapsed for array size ({}) during proving/verifying joint decryption of ciphertext: {:?}", array_size, duration);
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

fn benchmark_prove_verify(matrix_size: (usize, usize), parties:&NumParties) {
    // in gadget 1,2 the dimensions of the resulted matrix needed to proof correctness
    // are [d,d]
    let n = matrix_size.0;
    let d = matrix_size.1;

    // Key generation
    let ek = gen_keys();

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

    // compute dot products
    let matrix_c = MulDotProducts::compute_plaintext_dot_products(&matrix_a, &matrix_b);
    let (matrix_e_c, matrix_r_c) = MulDotProducts::compute_encrypted_dot_products(&matrix_c, &ek);

    // compute plaintext and encrypted result matrix
    let result_matrices = MatrixDots::compute_encrypted_matrix_from_plaintext_dots(&matrix_c, &ek, &parties);
        
    let matrix_witness = MatrixWitness {
        matrix_a,
        matrix_b: matrix_b.clone(), // copy from memory
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

    // Measure proving/verifying time
    let start = Instant::now();
    MatrixDots::matrix_dots_mul_prove_verify(&matrix_statement, &matrix_witness, parties);
    let duration = start.elapsed();

    println!("Time elapsed for matrix size ({}, {}) during proving/verifying MATRIX PLAINTEXT MUL: {:?}", n, d, duration);
}

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


fn benchmark_range_prove_verify(array_size: usize, parties:&NumParties) {
    let n = array_size;
  
    let range = BigInt::sample(RANGE_BITS);
    // Key generation
    let ek = gen_keys();

    // generate and encrypt array X
    let array_x = ArrayPaillier::gen_array(n, &range);
    let array_r_x = ArrayPaillier::gen_array_randomness(n, &ek);
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &ek);

    let witness = ArrayRangeWitness {
        array_x,
        array_r_x:array_r_x.clone(),
    };

    let statement = ArrayRangeStatement {
        ek:ek.clone(),
        range,
        array_e_x:array_e_x.clone(),
    };

    // Measure proving/verifying time
    let start = Instant::now();
    ArrayRangeProofNi::array_range_prove_verify(&statement, &witness, &parties);
    let duration = start.elapsed();

    println!("Time elapsed for array size ({}) during proving/verifying RANGE: {:?}", n, duration);
}


fn benchmark_matrices(c: &mut Criterion) {
    let mut group = c.benchmark_group("MatrixProving");
    let parties = NumParties{m: 4};
    // Reduce the sample size to avoid long running benchmarks
    //group.sample_size(5);  // Reduce sample size here

    let sizes = vec![(25,25), (50, 50), (75, 75), (100, 100)];


    for size in &sizes {
        group.bench_function(
            &format!(
                "prove_verify_Gadget2_MATRIX_PLAINTEXT_PLAINTEXT_size_{:?}_parties_{}",
                size, parties.m
            ),
            |b| {
                b.iter(|| benchmark_prove_verify(black_box(*size), &parties));
            },
        );

        group.bench_function(
            &format!(
                "enc_prove_verify_Gadget1_MATRIX_PLAINTEXT_CIPHERTEXT_size_{:?}_parties_{}",
                size, parties.m
            ),
            |b| {
                b.iter(|| benchmark_enc_prove_verify(black_box(*size), &parties));
            },
        );
    }
    group.finish();

}

fn benchmark_array_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("ArrayRangeProving");

    let num_parties  = 4;
    // Reduce the sample size to avoid long-running benchmarks
    group.sample_size(10);

    let sizes: Vec<usize> = vec![25, 50, 75, 100];

    for size in &sizes {
        group.bench_function(
            &format!("prove_verify_RANGE_size_{}_parties_{}", size, num_parties),
            |b| {
                b.iter(|| benchmark_range_prove_verify(black_box(*size), &NumParties{ m: num_parties} ));
            },
        );
    }
    group.finish();
}


fn benchmark_gadget3_exec(c: &mut Criterion) {
    let mut group = c.benchmark_group("Gadget3");
    let parties = NumParties{m: 4};
    let spdz_mod:BigInt = BigInt::from(3305569710899353_u64);
    // Reduce the sample size to avoid long running benchmarks
    group.sample_size(10);  // Reduce sample size here

    let sizes: Vec<usize> = vec![ 25, 50, 75, 100];

    for size in sizes {
        group.bench_function(&format!("gadget3_{:?}", size), |b| {
            b.iter(|| benchmark_gadget3(black_box(size), &spdz_mod, &parties ));
        });
    }
    group.finish();

}

fn benchmark_gadget4_exec(c: &mut Criterion) {

    use curv::arithmetic::traits::*;
    use curv::BigInt;
    let mut group = c.benchmark_group("Gadget3");
    let parties = NumParties{m: 4};
    let spdz_mod:BigInt = BigInt::from_str_radix("12492985848356528369", 10).unwrap();
    // Reduce the sample size to avoid long running benchmarks
    group.sample_size(10);  // Reduce sample size here

    let sizes: Vec<usize> = vec![ 25, 50  ,75, 100];

    for size in sizes {
        group.bench_function(&format!("gadget4_{:?}", size), |b| {
            b.iter(|| benchmark_gadget4(black_box(size), &spdz_mod, &parties ));
        });
    }
    group.finish();

}


fn benchmark_joint_dec(c: &mut Criterion) {
    let mut group = c.benchmark_group("JointDec");
    // Reduce the sample size to avoid long running benchmarks
    group.sample_size(10);  // Reduce sample size here

    let sizes: Vec<usize> = vec![ 25, 50  ,75, 100];
    let parties = NumParties{m: 4};
    for size in sizes {
        group.bench_function(&format!("joint_dec_{:?}", size), |b| {
            b.iter(|| joint_dec_init(black_box(size),  &parties ));
        });
    }
    group.finish();

}


fn benchmark_parties_all(c: &mut Criterion) {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    let mut group = c.benchmark_group("MatrixProving");
    let parties = NumParties{m: 3};
    let spdz_mod:BigInt = BigInt::from_str_radix("12492985848356528369", 10).unwrap();

    // Reduce the sample size to avoid long running benchmarks
    //group.sample_size(5);  // Reduce sample size here

    let sizes = vec![(10,10)];
    

    let num_parties_list = vec![NumParties { m: 2 }, NumParties { m: 4 }, NumParties { m: 6 }, NumParties { m: 8 }, NumParties { m: 10}];

    for num_parties in &num_parties_list {
        for size in &sizes {
            let (first, second) = *size;
            group.bench_function(
                &format!(
                    "prove_verify_Gadget2_size_{:?}_parties_{}",
                    size, num_parties.m
                ),
                |b| {
                    b.iter(|| benchmark_prove_verify(black_box(*size), num_parties));
                },
            );

            group.bench_function(
                &format!(
                    "enc_prove_verify_Gadget1_size_{:?}_parties_{:}",
                    size, num_parties.m
                ),
                |b| {
                    b.iter(|| benchmark_enc_prove_verify(black_box(*size), num_parties));
                },
            );

            group.bench_function(
                &format!("prove_verify_RANGE_size_{:?}_parties_{:}",  size, num_parties.m),
                |b| {
                    b.iter(|| benchmark_range_prove_verify(black_box(first), num_parties ));
                },
            );

            group.bench_function(
                &format!("gadget3_{:?}_parties_{:}", size, num_parties.m), |b| {
                b.iter(|| benchmark_gadget3(black_box(first), &spdz_mod, &num_parties ));
            });

            group.bench_function(&format!("gadget4_{:?}_parties_{:}", size, num_parties.m), |b| {
                b.iter(|| benchmark_gadget4(black_box(first), &spdz_mod, &num_parties ));
            });

            group.bench_function(
                &format!("joint_dec_{:?}", size), |b| {
                b.iter(|| joint_dec_init(black_box(first),  &parties ));
            });

        }
    }
    group.finish();

}




criterion_group! {
    name = benches;
    config = custom_criterion();
    targets = benchmark_parties_all, benchmark_matrices,  benchmark_array_range,  benchmark_gadget3_exec, benchmark_gadget4_exec, benchmark_joint_dec
}
criterion_main!(benches);



/*fn range_proof() {
    // TODO: bench range for 256bit range.
    // common:
    let range = BigInt::sample(RANGE_BITS);
    // prover:
    let (ek, _dk) = test_keypair().keys();
    let (verifier_ek, _verifier_dk) = test_keypair().keys();
    // verifier:
    let (_com, _r, e) = RangeProof::verifier_commit(&verifier_ek);
    // prover:
    let (encrypted_pairs, data_and_randmoness_pairs) =
        RangeProof::generate_encrypted_pairs(&ek, &range, STATISTICAL_ERROR_FACTOR);
    // prover:
    let secret_r = BigInt::sample_below(&ek.n);
    let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    //let secret_x = BigInt::from(0xFFFFFFFi64);
    // common:
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&secret_x),
        &Randomness(secret_r.clone()),
    );
    // verifer decommits (tested in test_commit_decommit)
    // prover:
    let z_vector = RangeProof::generate_proof(
        &ek,
        &secret_x,
        &secret_r,
        &e,
        &range,
        &data_and_randmoness_pairs,
        STATISTICAL_ERROR_FACTOR,
    );
    // verifier:
    let _result = RangeProof::verifier_output(
        &ek,
        &e,
        &encrypted_pairs,
        &z_vector,
        &range,
        &cipher_x.0,
        STATISTICAL_ERROR_FACTOR,
    );
}

fn range_proof_ni() {
    // TODO: bench range for 256bit range.
    let (ek, _dk) = test_keypair().keys();
    let range = BigInt::sample(RANGE_BITS);
    let secret_r = BigInt::sample_below(&ek.n);
    let secret_x = BigInt::sample_below(&range.div_floor(&BigInt::from(3)));
    let cipher_x = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(&secret_x),
        &Randomness(secret_r.clone()),
    );
    let range_proof = RangeProofNi::prove(&ek, &range, &cipher_x.0, &secret_x, &secret_r);

    range_proof
        .verify(&ek, &cipher_x.0)
        .expect("range proof error");
}

fn test_keypair() -> Keypair {
    let p = BigInt::from_str_radix("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517", 10).unwrap();
    let q = BigInt::from_str_radix("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463", 10).unwrap();
    Keypair { p, q }
}

const RANGE_BITS: usize = 256; //for elliptic curves with 256bits for example

fn criterion_benchmark(c: &mut Criterion) {
    c.bench(
        "range proof",
        ParameterizedBenchmark::new("few", |b, _| b.iter(range_proof), vec![0]).sample_size(20),
    );
    c.bench(
        "range proof ni",
        ParameterizedBenchmark::new("few", |b, _| b.iter(range_proof_ni), vec![0]).sample_size(10),
    );
}

const STATISTICAL_ERROR_FACTOR: usize = 40;

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
*/