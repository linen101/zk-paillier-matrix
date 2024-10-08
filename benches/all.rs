use paillier::{Paillier, EncryptionKey};
use paillier::traits::KeyGeneration;

use zk_paillier::zkproofs::*;

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Instant;

fn gen_keys() -> EncryptionKey{
    let (ek, _) = Paillier::keypair().keys();

    // Return  the encryption key 
    ek
}

fn benchmark_prove_verify(matrix_size: (usize, usize)) {
    let n = matrix_size.0;
    let d = matrix_size.1;

    // Key generation
    let ek = gen_keys();

    // generate and encrypt matrix A
    let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    // generate and encrypt matrix B
    let matrix_b = MatrixPaillier::gen_matrix(d, n, &ek);
    let matrix_r_b = MatrixPaillier::generate_randomness(d, n, &ek);
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

    // compute dot products
    let matrix_c = MulDotProducts::compute_plaintext_dot_products(&matrix_a, &matrix_b);
    let (matrix_e_c, matrix_r_c) = MulDotProducts::compute_encrypted_dot_products(&matrix_c, &ek);

    let matrix_witness = MatrixWitness {
        matrix_a,
        matrix_b: matrix_b.clone(),
        matrix_c: matrix_c.clone(),
        matrix_r_a,
        matrix_r_b: matrix_r_b.clone(),
        matrix_r_c: matrix_r_c.clone(),
    };

    let matrix_statement = MatrixStatement {
        ek: ek.clone(),
        matrix_e_a: matrix_e_a.clone(),
        matrix_e_b: matrix_e_b.clone(),
        matrix_e_c: matrix_e_c.clone(),
    };

    // Measure proving/verifying time
    let start = Instant::now();
    MatrixDots::matrix_dots_mul_prove_verify(&matrix_statement, &matrix_witness);
    let duration = start.elapsed();

    println!("Time elapsed for matrix size ({}, {}) during proving/verifying: {:?}", n, d, duration);
}

fn benchmark_enc_prove_verify(matrix_size: (usize, usize)) {
    let n = matrix_size.0;
    let d = matrix_size.1;

    let ek = gen_keys();

    // generate and encrypt matrix A
    let matrix_a = MatrixPaillier::gen_matrix(n, d, &ek);
    let matrix_r_a = MatrixPaillier::generate_randomness(n, d, &ek);
    let matrix_e_a = MatrixPaillier::encrypt_matrix(&matrix_a, &matrix_r_a, &ek);

    // generate and encrypt matrix B
    let matrix_b = MatrixPaillier::gen_matrix(d, n, &ek);
    let matrix_r_b = MatrixPaillier::generate_randomness(d, n, &ek);
    let matrix_e_b = MatrixPaillier::encrypt_matrix(&matrix_b, &matrix_r_b, &ek);

    // Compute encrypted dot products with homomorphism
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

    // Measure proving/verifying time
    let start = Instant::now();
    EncMatrixDots::matrix_dots_mul_prove_verify(&matrix_ciph_statement, &matrix_ciph_witness);
    let duration = start.elapsed();

    println!("Time elapsed for matrix size ({}, {}) in encrypted proving/verifying: {:?}", n, d, duration);
}

fn benchmark_matrices(c: &mut Criterion) {
    let mut group = c.benchmark_group("MatrixProving");

    // Reduce the sample size to avoid long running benchmarks
    group.sample_size(10);  // Reduce sample size here

    let sizes = vec![(2, 2), (4, 2), (8, 2), (16, 2)];

    for size in sizes {
        group.bench_function(&format!("prove_verify_{:?}", size), |b| {
            b.iter(|| benchmark_prove_verify(black_box(size)));
        });

        group.bench_function(&format!("enc_prove_verify_{:?}", size), |b| {
            b.iter(|| benchmark_enc_prove_verify(black_box(size)));
        });
    }
    group.finish();

}

criterion_group!(benches, benchmark_matrices);
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