#[tokio::test]
async fn test_gadget4_with_communication() {
    use tokio::sync::broadcast;

    let parties = NumParties { m: 3 };
    let spdz_mod: BigInt = BigInt::from_str_radix("12492985848356528369", 10).unwrap();

    // Generate classic Paillier keys
    let (ek, dk) = Paillier::keypair_safe_primes().keys();

    // Create necessary parameters for joint decryption Paillier 
    let (ekj, dkj) = Paillier::joint_dec_params(&ek, &dk);

    // Create shared secret key
    let shares = Paillier::additive_shares(&ekj, &dkj, &parties).dks;
    let sk_shares = DecryptionKeyShared { dks: shares };

    let range = BigInt::sample(RANGE_BITS);

    // Generate and encrypt array X
    let n = 1;
    let array_x = ArrayPaillier::gen_array_no_range(n, &EncryptionKey::from(&ekj));
    let array_r_x = ArrayPaillier::gen_array_randomness(n, &EncryptionKey::from(&ekj));
    let array_e_x = ArrayPaillier::encrypt_array(&array_x, &array_r_x, &EncryptionKey::from(&ekj));

    // Set up broadcast channels
    let (tx, _) = broadcast::channel(16); // Create broadcast channel with buffer size of 16

    // Spawn tasks for each party
    let gadget3_handles: Vec<_> = (0..parties.m)
        .map(|i| {
            let tx_clone = tx.clone(); // Cloning the sender is cheap
            let mut rx = tx.subscribe(); // Each task gets its own receiver
            let ekj_clone = ekj.clone();
            let sk_shares_clone = sk_shares.clone();
            let spdz_mod_clone = spdz_mod.clone();

            tokio::spawn(async move {
                let received_message = rx.recv().await.expect("Failed to receive message");
                // Run GadgetThree protocol and return its output
                GadgetThree::protocol(
                    &array_e_x[0],
                    &ekj_clone,
                    &sk_shares_clone,
                    &parties,
                    &spdz_mod_clone,
                    tx_clone,
                    received_message,
                )
                .await
            })
        })
        .collect();

    // Collect all results using `join_all`
    let gadget3_results: Vec<_> = futures::future::join_all(gadget3_handles)
        .await
        .into_iter()
        .map(|res| res.expect("Task panicked"))
        .collect();

    println!("All GadgetThree protocols completed");

    // Process results as needed for GadgetFour
    let input_for_gadget4 = gadget3_results[0].clone(); // Assuming GadgetFour requires a single result

    // Measure GadgetFour
    let start = tokio::time::Instant::now();
    GadgetFour::protocol(&input_for_gadget4, &ekj, &sk_shares, &parties, &spdz_mod);
    let duration2 = start.elapsed();

    println!("Time elapsed in gadget4: {:?}", duration2);
}
