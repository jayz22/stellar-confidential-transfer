use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soroban_sdk::Env;
use stellar_confidential_crypto::{
    arith::pubkey_from_secret_key,
    confidential_balance::ConfidentialBalance,
    proof,
};
use confidential_token::testutil::*;
use std::time::Duration;

fn bench_confidential_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_operations");
    
    // Configure for longer running benchmarks
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(5));

    group.bench_function("withdraw", |b| {
        b.iter(|| {
            let e = Env::default();
            e.mock_all_auths();

            // Setup
            let initial_available_balance_u64 = 500u64;
            let initial_pending_balance_u64 = 500u64;

            let (token, _admin, user, user_secret_key, user_public_key, current_balance, _) =
                setup_confidential_token_account_with_balances(
                    &e,
                    initial_available_balance_u64,
                    initial_pending_balance_u64,
                );

            let withdraw_amount = 200u64;
            let new_balance_amount_u128 = (initial_available_balance_u64 - withdraw_amount) as u128;

            // Generate withdrawal proof
            let (withdraw_proof, withdraw_new_balance) = proof::testutils::prove_withdrawal(
                &e,
                &user_secret_key,
                &user_public_key,
                withdraw_amount,
                new_balance_amount_u128,
                &current_balance,
            );

            // The operation being benchmarked
            black_box(token.withdraw(
                &user,
                &withdraw_amount,
                &withdraw_new_balance,
                &withdraw_proof,
            ));
        });
    });

    group.bench_function("rollover", |b| {
        b.iter(|| {
            let e = Env::default();
            e.mock_all_auths();

            // Setup
            let initial_pending_balance = 500u64;
            let (token, _admin, user, user_secret_key, user_public_key) =
                setup_confidential_token_with_deposit(&e, 1000i128, initial_pending_balance);

            let new_balance_amount = initial_pending_balance as u128;
            let balance_pre_normalization =
                ConfidentialBalance::new_balance_with_no_randomness(new_balance_amount);

            // Generate normalization proof for rollover
            let (proof, new_balance_bytes) = proof::testutils::prove_normalization(
                &e,
                &user_secret_key,
                &user_public_key,
                new_balance_amount,
                &balance_pre_normalization,
            );

            // The operation being benchmarked
            black_box(token.rollover_pending_balance(&user, &new_balance_bytes, &proof));
        });
    });

    group.bench_function("transfer", |b| {
        b.iter(|| {
            let e = Env::default();
            e.mock_all_auths();

            // Setup
            let src_initial_balance = 1000u64;
            let des_initial_balance = 500u64;

            let (
                token,
                _admin,
                src,
                des,
                src_secret_key,
                src_public_key,
                _des_secret_key,
                des_public_key,
                src_current_balance,
                _des_current_balance,
                auditor_key,
            ) = setup_confidential_token_two_accounts(
                &e,
                src_initial_balance,
                0,
                des_initial_balance,
                0,
                None,
            );

            // Transfer amount
            let transfer_amount = 200u64;
            let new_src_balance_amount = src_initial_balance - transfer_amount;

            // Get auditor public key
            let auditor_public_key = pubkey_from_secret_key(&auditor_key);

            // Generate transfer proof
            let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
                proof::testutils::prove_transfer(
                    &e,
                    &src_secret_key,
                    &src_public_key,
                    &des_public_key,
                    transfer_amount,
                    new_src_balance_amount as u128,
                    &src_current_balance,
                    &auditor_public_key,
                );

            // The operation being benchmarked
            black_box(token.confidential_transfer(
                &src,
                &des,
                &src_amount,
                &des_amount,
                &auditor_amount,
                &src_new_balance,
                &transfer_proof,
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_confidential_operations);
criterion_main!(benches);