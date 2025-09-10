use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use soroban_sdk::Env;
use stellar_confidential_crypto::{
    arith::{new_scalar_from_u64, pubkey_from_secret_key},
    confidential_balance::{
        testutils::generate_balance_randomness,
        ConfidentialBalance,
    },
    proof::{testutils, verify_withdrawal_proof, CompressedPubkeyBytes},
};
use std::time::Duration;
use confidential_token::testutil::*;

fn bench_confidential_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_operations");
    
    // Configure for benchmarks
    group.measurement_time(Duration::from_secs(8));
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(3));

    let e = Env::default();
    e.mock_all_auths();
    group.bench_function("token_withdraw", |b| {
        b.iter_batched(
            || {
                let initial_available_balance_u64 = 500u64;
                let initial_pending_balance_u64 = 500u64;
            
                let (token, _admin, user, user_secret_key, user_public_key, current_balance, _) =
                    setup_confidential_token_account_with_balances(
                        &e,
                        initial_available_balance_u64,
                        initial_pending_balance_u64,
                    );
            
                // Now test withdrawal
                let withdraw_amount = 200u64;
                let new_balance_amount_u128 = (initial_available_balance_u64 - withdraw_amount) as u128;
            
                // Generate withdrawal proof
                let (withdraw_proof, withdraw_new_balance) = testutils::prove_withdrawal(
                    &e,
                    &user_secret_key,
                    &user_public_key,
                    withdraw_amount,
                    new_balance_amount_u128,
                    &current_balance,
                );
                (token, user, withdraw_amount, withdraw_new_balance, withdraw_proof)   
            },
            |(token, user, withdraw_amount, withdraw_new_balance, withdraw_proof)| {
                black_box(token.withdraw(
                    &user,
                    &withdraw_amount,
                    &withdraw_new_balance,
                    &withdraw_proof,
                ));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("token_rollover_pending_balance", |b| {
        b.iter_batched(
            || {
                let initial_pending_balance = 500u64;
                let (token, _admin, user, user_secret_key, user_public_key) =
                    setup_confidential_token_with_deposit(&e, 1000i128, initial_pending_balance);
            
                let new_balance_amount = initial_pending_balance as u128;
                let balance_pre_normalization =
                    ConfidentialBalance::new_balance_with_no_randomness(new_balance_amount);
                
                    // Generate normalization proof for rollover
                    let (proof, new_balance_bytes) = testutils::prove_normalization(
                        &e,
                        &user_secret_key,
                        &user_public_key,
                        new_balance_amount,
                        &balance_pre_normalization,
                    );
                    (token,
                        user,
                        new_balance_bytes,
                        proof)                    
            },
            |(token,
                user,
                new_balance_bytes,
                proof)| {
                black_box(token.rollover_pending_balance(&user, &new_balance_bytes, &proof));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("token_confidential_transfer", |b| {
        b.iter_batched(
            || {
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
                let auditor_public_key = auditor_key.to_point();
            
                // Generate transfer proof
                let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
                    testutils::prove_transfer(
                        &e,
                        &src_secret_key,
                        &src_public_key,
                        &des_public_key,
                        transfer_amount,
                        new_src_balance_amount as u128,
                        &src_current_balance,
                        &auditor_public_key,
                    );
                (token, 
                    src,
                    des,
                    src_amount,
                    des_amount,
                    auditor_amount,
                    src_new_balance,
                    transfer_proof,)
            },
            |(token, 
                src,
                des,
                src_amount,
                des_amount,
                auditor_amount,
                src_new_balance,
                transfer_proof,)| {
                black_box(token.confidential_transfer(
                    &src,
                    &des,
                    &src_amount,
                    &des_amount,
                    &auditor_amount,
                    &src_new_balance,
                    &transfer_proof,
                ));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_confidential_operations);
criterion_main!(benches);