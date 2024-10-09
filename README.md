[![Latest version](https://img.shields.io/crates/v/zk-paillier.svg)](https://crates.io/crates/zk-paillier)

Zero Knowledge Paillier for Matrices
-------------------
This library is a copy of [zk-paillier](https://github.com/ZenGo-X/zk-paillier) which contains a collection of Paillier cryptosystem zero knowledge proofs written in Rust. 
We have used this library to write proofs on matrices.

We have extended the library with the following proofs:
* [proof of plaintext matrix - plaintext matrix multiplication (uses proof of plaintext knowledge)](https://github.com/linen101/zk-paillier-matrix/blob/master/src/zkproofs/matrix_multiplication_proof.rs)
* [proof of plaintext matrix - ciphertext matrix multiplication (uses proof of plaintext knowledge)](https://github.com/linen101/zk-paillier-matrix/blob/master/src/zkproofs/matrix_multiplication_proof_plaintext_ciphertext.rs)
