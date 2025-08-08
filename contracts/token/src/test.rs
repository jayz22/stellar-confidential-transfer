#![cfg(test)]
extern crate std;

use crate::{
    contract::{ConfidentialToken, MAX_PENDING_BALANCE_COUNTER},
    utils::{
        read_account_confidential_ext, read_balance, read_token_confidential_ext, write_account_confidential_ext, write_token_confidential_ext
    },
    ConfidentialTokenClient,
};
use soroban_sdk::{
    symbol_short, testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation}, xdr::{FromXdr, ToXdr}, Address, Env, FromVal, IntoVal, String, Symbol
};
use stellar_confidential_crypto::{
    arith::{new_scalar_from_u64, pubkey_from_secret_key}, confidential_balance::testutils::{generate_amount_randomness, generate_balance_randomness}, proof::{self, CompressedPubkeyBytes}, ConfidentialAmount, ConfidentialBalanceBytes, RistrettoPoint, Scalar
};
use stellar_confidential_crypto::{
    confidential_balance::ConfidentialBalance, ConfidentialAmountBytes,
};

fn create_token<'a>(e: &Env, admin: &Address) -> ConfidentialTokenClient<'a> {
    let token_contract = e.register(
        ConfidentialToken,
        (
            admin,
            7_u32,
            String::from_val(e, &"name"),
            String::from_val(e, &"symbol"),
        ),
    );
    ConfidentialTokenClient::new(e, &token_contract)
}

#[test]
fn test() {
    let e = Env::default();
    e.mock_all_auths();

    let admin1 = Address::generate(&e);
    let admin2 = Address::generate(&e);
    let user1 = Address::generate(&e);
    let user2 = Address::generate(&e);
    let user3 = Address::generate(&e);
    let token = create_token(&e, &admin1);

    token.mint(&user1, &1000);
    assert_eq!(
        e.auths(),
        std::vec![(
            admin1.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("mint"),
                    (&user1, 1000_i128).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(token.balance(&user1), 1000);

    token.approve(&user2, &user3, &500, &200);
    assert_eq!(
        e.auths(),
        std::vec![(
            user2.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("approve"),
                    (&user2, &user3, 500_i128, 200_u32).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(token.allowance(&user2, &user3), 500);

    token.transfer(&user1, &user2, &600);
    assert_eq!(
        e.auths(),
        std::vec![(
            user1.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("transfer"),
                    (&user1, &user2, 600_i128).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(token.balance(&user1), 400);
    assert_eq!(token.balance(&user2), 600);

    token.transfer_from(&user3, &user2, &user1, &400);
    assert_eq!(
        e.auths(),
        std::vec![(
            user3.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    Symbol::new(&e, "transfer_from"),
                    (&user3, &user2, &user1, 400_i128).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(token.balance(&user1), 800);
    assert_eq!(token.balance(&user2), 200);

    token.transfer(&user1, &user3, &300);
    assert_eq!(token.balance(&user1), 500);
    assert_eq!(token.balance(&user3), 300);

    token.set_admin(&admin2);
    assert_eq!(
        e.auths(),
        std::vec![(
            admin1.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("set_admin"),
                    (&admin2,).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );

    // Increase to 500
    token.approve(&user2, &user3, &500, &200);
    assert_eq!(token.allowance(&user2, &user3), 500);
    token.approve(&user2, &user3, &0, &200);
    assert_eq!(
        e.auths(),
        std::vec![(
            user2.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("approve"),
                    (&user2, &user3, 0_i128, 200_u32).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );
    assert_eq!(token.allowance(&user2, &user3), 0);
}

#[test]
fn test_burn() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let user1 = Address::generate(&e);
    let user2 = Address::generate(&e);
    let token = create_token(&e, &admin);

    token.mint(&user1, &1000);
    assert_eq!(token.balance(&user1), 1000);

    token.approve(&user1, &user2, &500, &200);
    assert_eq!(token.allowance(&user1, &user2), 500);

    token.burn_from(&user2, &user1, &500);
    assert_eq!(
        e.auths(),
        std::vec![(
            user2.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("burn_from"),
                    (&user2, &user1, 500_i128).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );

    assert_eq!(token.allowance(&user1, &user2), 0);
    assert_eq!(token.balance(&user1), 500);
    assert_eq!(token.balance(&user2), 0);

    token.burn(&user1, &500);
    assert_eq!(
        e.auths(),
        std::vec![(
            user1.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    token.address.clone(),
                    symbol_short!("burn"),
                    (&user1, 500_i128).into_val(&e),
                )),
                sub_invocations: std::vec![]
            }
        )]
    );

    assert_eq!(token.balance(&user1), 0);
    assert_eq!(token.balance(&user2), 0);
}

#[test]
#[should_panic(expected = "insufficient balance")]
fn transfer_insufficient_balance() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let user1 = Address::generate(&e);
    let user2 = Address::generate(&e);
    let token = create_token(&e, &admin);

    token.mint(&user1, &1000);
    assert_eq!(token.balance(&user1), 1000);

    token.transfer(&user1, &user2, &1001);
}

#[test]
#[should_panic(expected = "insufficient allowance")]
fn transfer_from_insufficient_allowance() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let user1 = Address::generate(&e);
    let user2 = Address::generate(&e);
    let user3 = Address::generate(&e);
    let token = create_token(&e, &admin);

    token.mint(&user1, &1000);
    assert_eq!(token.balance(&user1), 1000);

    token.approve(&user1, &user3, &100, &200);
    assert_eq!(token.allowance(&user1, &user3), 100);

    token.transfer_from(&user3, &user1, &user2, &101);
}

#[test]
#[should_panic(expected = "Decimal must not be greater than 18")]
fn decimal_is_over_eighteen() {
    let e = Env::default();
    let admin = Address::generate(&e);
    let _ = ConfidentialTokenClient::new(
        &e,
        &e.register(
            ConfidentialToken,
            (
                admin,
                19_u32,
                String::from_val(&e, &"name"),
                String::from_val(&e, &"symbol"),
            ),
        ),
    );
}

#[test]
fn test_zero_allowance() {
    // Here we test that transfer_from with a 0 amount does not create an empty allowance
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let spender = Address::generate(&e);
    let from = Address::generate(&e);
    let token = create_token(&e, &admin);

    token.transfer_from(&spender, &from, &spender, &0);
    assert!(token.get_allowance(&from, &spender).is_none());
}

// Helper function to create a CompressedPubkeyBytes for account encryption key
fn create_test_account_key(e: &Env, seed: u64) -> CompressedPubkeyBytes {
    let secret_key = new_scalar_from_u64(seed);
    let public_key = pubkey_from_secret_key(&secret_key);
    CompressedPubkeyBytes::from_point(e, &public_key)
}

#[test]
fn test_token_confidential_extension() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let token = create_token(&e, &admin);

    // Create test auditor key
    let auditor_key = create_test_account_key(&e, 123);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Check that TokenConfidentialExt exists and its fields are as expected
    let token_ext = e.as_contract(&token.address, || read_token_confidential_ext(&e));
    assert_eq!(token_ext.enabled_flag, true);
    assert_eq!(token_ext.auditor, auditor_key);
    assert_eq!(token_ext.total_confidential_supply, 0u128);

    // Set token enabled flag to false
    token.set_token_enabled_flag(&false);

    // Check that TokenConfidentialExt has been updated
    let updated_token_ext = e.as_contract(&token.address, || read_token_confidential_ext(&e));
    assert_eq!(updated_token_ext.enabled_flag, false);
}

#[test]
fn test_account_confidential_extension_and_disabled_deposit() {
    use stellar_confidential_crypto::{ConfidentialAmountBytes, ConfidentialBalanceBytes};

    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let user = Address::generate(&e);
    let token = create_token(&e, &admin);

    // Create test keys
    let auditor_key = create_test_account_key(&e, 123);
    let user_encryption_key = create_test_account_key(&e, 456);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register an account
    token.register_account(&user, &user_encryption_key);

    // Check the AccountConfidentialExt and its fields are expected
    let account_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    assert_eq!(account_ext.enabled_flag, true);
    assert_eq!(account_ext.encryption_key, user_encryption_key);

    // Check that available_balance and pending_balance are zero
    let zero_balance = ConfidentialBalanceBytes::zero(&e);
    let zero_amount = ConfidentialAmountBytes::zero(&e);
    assert_eq!(account_ext.available_balance.0.len(), zero_balance.0.len());
    assert_eq!(account_ext.pending_balance.0.len(), zero_amount.0.len());
    assert_eq!(account_ext.pending_counter, 0u32);

    // Set account enabled flag to false
    token.set_account_enabled_flag(&user, &false);

    // Check that AccountConfidentialExt has been updated with the new flag
    let updated_account_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    assert_eq!(updated_account_ext.enabled_flag, false);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_deposit_with_disabled_account() {
    let e = Env::default();
    e.mock_all_auths();

    let admin = Address::generate(&e);
    let user = Address::generate(&e);
    let token = create_token(&e, &admin);

    // Create test keys
    let auditor_key = create_test_account_key(&e, 123);
    let user_encryption_key = create_test_account_key(&e, 456);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register an account
    token.register_account(&user, &user_encryption_key);

    // Set account enabled flag to false
    token.set_account_enabled_flag(&user, &false);

    // Mint some tokens to the user first so they have balance to deposit
    token.mint(&user, &1000);
    assert_eq!(token.balance(&user), 1000);

    // Try to call deposit - this should panic
    token.deposit(&user, &100);
}

// Helper function to setup confidential token for testing
fn setup_confidential_token_with_account(e: &Env) -> (ConfidentialTokenClient, Address, Address) {
    let admin = Address::generate(e);
    let user = Address::generate(e);
    let token = create_token(e, &admin);

    // Create test keys
    let auditor_key = create_test_account_key(e, 12345);
    let user_encryption_key = create_test_account_key(e, 54321);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register user account
    token.register_account(&user, &user_encryption_key);

    (token, admin, user)
}

#[test]
fn test_deposit_success() {
    use stellar_confidential_crypto::ConfidentialAmountBytes;

    let e = Env::default();
    e.mock_all_auths();

    let (token, _admin, user) = setup_confidential_token_with_account(&e);

    // Mint some tokens to the user
    let initial_balance = 1000i128;
    let deposit_amount = 300u64;
    token.mint(&user, &initial_balance);
    assert_eq!(token.balance(&user), initial_balance);

    // Get initial confidential balances
    let initial_account_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    let initial_pending_counter = initial_account_ext.pending_counter;

    // Perform deposit
    token.deposit(&user, &deposit_amount);

    // Check transparent balance was reduced
    assert_eq!(
        token.balance(&user),
        initial_balance - deposit_amount as i128
    );

    // Check confidential account state was updated
    let updated_account_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    assert_eq!(
        updated_account_ext.pending_counter,
        initial_pending_counter + 1
    );

    // Validate the pending balance (because this is the first deposit, we can check the amount w.r.t amt encrypted with zero randomness)
    let expected_balance = ConfidentialAmountBytes::from_u64_with_no_randomness(&e, deposit_amount);
    assert_eq!(updated_account_ext.pending_balance, expected_balance); // Same structure but different values
}

#[test]
#[should_panic(expected = "insufficient balance")]
fn test_deposit_insufficient_balance() {
    let e = Env::default();
    e.mock_all_auths();

    let (token, _admin, user) = setup_confidential_token_with_account(&e);

    // Mint some tokens to the user
    let initial_balance = 100i128;
    let deposit_amount = 150u64; // More than balance
    token.mint(&user, &initial_balance);
    assert_eq!(token.balance(&user), initial_balance);

    // Try to deposit more than balance - should panic
    token.deposit(&user, &deposit_amount);
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #1)")]
fn test_deposit_disabled_token() {
    let e = Env::default();
    e.mock_all_auths();

    let (token, _admin, user) = setup_confidential_token_with_account(&e);

    // Mint some tokens to the user
    let initial_balance = 1000i128;
    let deposit_amount = 300u64;
    token.mint(&user, &initial_balance);

    // Disable the token
    token.set_token_enabled_flag(&false);

    // Try to deposit - should fail with ConfidentialTokenNotEnabled error
    token.deposit(&user, &deposit_amount);
}

// Helper function to setup confidential token with deposit and return user keys for proof generation
fn setup_confidential_token_with_deposit(
    e: &Env,
    initial_total_supply: i128,
    initial_pending_balance: u64,
) -> (
    ConfidentialTokenClient,
    Address,
    Address,
    Scalar,
    RistrettoPoint,
) {
    let admin = Address::generate(e);
    let user = Address::generate(e);
    let token = create_token(e, &admin);

    // Create test keys
    let auditor_key = create_test_account_key(e, 12345);
    let user_secret_key = new_scalar_from_u64(54321);
    let user_public_key = pubkey_from_secret_key(&user_secret_key);
    let user_encryption_key = CompressedPubkeyBytes::from_point(e, &user_public_key);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register user account
    token.register_account(&user, &user_encryption_key);

    // Mint and deposit some tokens
    token.mint(&user, &initial_total_supply);
    token.deposit(&user, &initial_pending_balance);

    (token, admin, user, user_secret_key, user_public_key)
}

#[test]
fn test_rollover_pending_balance() {
    let e = Env::default();
    e.mock_all_auths();

    let initial_pending_balance = 500u64;
    let (token, _admin, user, user_secret_key, user_public_key) =
        setup_confidential_token_with_deposit(&e, 1000i128, initial_pending_balance);

    // Get account state before rollover
    let account_ext_before = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    assert_eq!(account_ext_before.pending_counter, 1);

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

    // Perform rollover
    token.rollover_pending_balance(&user, &new_balance_bytes, &proof);

    // Verify rollover results
    let account_ext_after = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, user.clone())
    });
    assert_eq!(account_ext_after.pending_counter, 0);
    // Verify pending balance is now zero
    assert_eq!(
        account_ext_after.pending_balance,
        ConfidentialAmountBytes::zero(&e)
    );
    // Actual balance has been set to the new_balance
    assert_eq!(account_ext_after.available_balance, new_balance_bytes);
}

// Helper function to setup confidential token with deposit and return user keys for proof generation
fn setup_confidential_token_account_with_balances(
    e: &Env,
    initial_available_balance: u64,
    initial_pending_balance: u64,
) -> (
    ConfidentialTokenClient,
    Address,
    Address,
    Scalar,
    RistrettoPoint,
    ConfidentialBalance,
    ConfidentialAmount,
) {
    let admin = Address::generate(e);
    let user = Address::generate(e);
    let token = create_token(e, &admin);

    // Create test keys
    let auditor_key = create_test_account_key(e, 12345);
    let user_secret_key = new_scalar_from_u64(54321);
    let user_public_key = pubkey_from_secret_key(&user_secret_key);
    let user_encryption_key = CompressedPubkeyBytes::from_point(e, &user_public_key);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register user account
    token.register_account(&user, &user_encryption_key);

    let available_balance = ConfidentialBalance::new_balance_from_u128(
        initial_available_balance as u128,
        &generate_balance_randomness(),
        &user_public_key,
    );
    let pending_balance = ConfidentialAmount::new_amount_from_u64(
        initial_pending_balance,
        &generate_amount_randomness(),
        &user_public_key,
    );
    // let available_balance = ConfidentialBalance::new_balance_with_no_randomness(initial_available_balance as u128);
    // let pending_balance = ConfidentialAmount::new_amount_with_no_randomness(initial_available_balance);

    // we cheat a bit here by directly setting the values of balances, in reality there should be a deposit followed by rollover (with proof)
    e.as_contract(&token.address, || {
        let mut ext = read_account_confidential_ext(&e, user.clone());
        ext.available_balance = available_balance.to_env_bytes(&e);
        ext.pending_balance = pending_balance.to_env_bytes(&e);
        write_account_confidential_ext(&e, user.clone(), &ext);

        let mut token_ext = read_token_confidential_ext(&e);
        token_ext.total_confidential_supply =
            (initial_available_balance + initial_pending_balance) as u128;
        write_token_confidential_ext(&e, &token_ext);
    });

    (
        token,
        admin,
        user,
        user_secret_key,
        user_public_key,
        available_balance,
        pending_balance,
    )
}

#[test]
fn test_withdraw_success() {
    let e = Env::default();
    e.mock_all_auths();

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
    let (withdraw_proof, withdraw_new_balance) = proof::testutils::prove_withdrawal(
        &e,
        &user_secret_key,
        &user_public_key,
        withdraw_amount,
        new_balance_amount_u128,
        &current_balance,
    );

    let transparent_balance_before = token.balance(&user);
    let total_confidential_supply_before = e.as_contract(&token.address, || {
        read_token_confidential_ext(&e).total_confidential_supply
    });

    // Perform withdrawal
    token.withdraw(
        &user,
        &withdraw_amount,
        &withdraw_new_balance,
        &withdraw_proof,
    );

    // Verify transparent balance increased
    assert_eq!(
        token.balance(&user),
        transparent_balance_before + withdraw_amount as i128
    );
    // Verify total confidential supply has decreased
    let total_confidential_supply_after = e.as_contract(&token.address, || {
        read_token_confidential_ext(&e).total_confidential_supply
    });
    assert_eq!(
        total_confidential_supply_after,
        total_confidential_supply_before - withdraw_amount as u128
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_withdraw_wrong_amount() {
    let e = Env::default();
    e.mock_all_auths();

    let initial_available_balance_u64 = 500u64;
    let initial_pending_balance_u64 = 500u64;

    let (token, _admin, user, user_secret_key, user_public_key, current_balance, _) =
        setup_confidential_token_account_with_balances(
            &e,
            initial_available_balance_u64,
            initial_pending_balance_u64,
        );

    // Generate proof for one amount but call with different amount
    let withdraw_amount = 200u64;
    let wrong_withdraw_amount = 250u64; // Different amount
    let new_balance_amount = initial_available_balance_u64 - withdraw_amount;

    // Generate proof for withdraw_amount
    let (withdraw_proof, withdraw_new_balance) = proof::testutils::prove_withdrawal(
        &e,
        &user_secret_key,
        &user_public_key,
        withdraw_amount, // Proof for this amount
        new_balance_amount as u128,
        &current_balance,
    );

    // Try to withdraw with wrong amount - should fail with WithdrawalProofVerificationFailed
    token.withdraw(
        &user,
        &wrong_withdraw_amount,
        &withdraw_new_balance,
        &withdraw_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #4)")]
fn test_withdraw_wrong_new_balance() {
    let e = Env::default();
    e.mock_all_auths();

    let initial_available_balance_u64 = 500u64;
    let initial_pending_balance_u64 = 500u64;

    let (token, _admin, user, user_secret_key, user_public_key, current_balance, _) =
        setup_confidential_token_account_with_balances(
            &e,
            initial_available_balance_u64,
            initial_pending_balance_u64,
        );

    // Test with mismatched new balance
    let withdraw_amount = 200u64;
    let correct_new_balance_amount = initial_available_balance_u64 - withdraw_amount;
    let wrong_new_balance_amount = initial_available_balance_u64 - (withdraw_amount + 50); // Wrong balance

    // Generate proof for correct new balance amount
    let (withdraw_proof, _) = proof::testutils::prove_withdrawal(
        &e,
        &user_secret_key,
        &user_public_key,
        withdraw_amount,
        correct_new_balance_amount as u128, // Proof for correct amount
        &current_balance,
    );

    // But create wrong new balance
    let (_, wrong_new_balance) = proof::testutils::prove_withdrawal(
        &e,
        &user_secret_key,
        &user_public_key,
        withdraw_amount + 50, // Different amount to get wrong balance
        wrong_new_balance_amount as u128,
        &current_balance,
    );

    // Try to withdraw with wrong new_balance - should fail with WithdrawalProofVerificationFailed
    token.withdraw(&user, &withdraw_amount, &wrong_new_balance, &withdraw_proof);
}

// Now help me implement tests for confidential_transfer. Setup: confidential token. two accounts: src, des. Both with
// the some initial available and pending balances, you can set it up in the simliar way as before, i.e. directly setting
// the data entry instead of calling deposit, rollover etc.
//
// Here are the test scenrios:
// 1. successful transfer
// 2. destination account is disabled, fail
// 3. src account has insufficient balance
// 4. des account's pending counter already at maximum (for this you need to sweak the initial setup to allow overriding the pending counter)

// Helper function to setup confidential token with two accounts for transfer testing
fn setup_confidential_token_two_accounts(
    e: &Env,
    src_available_balance: u64,
    src_pending_balance: u64,
    des_available_balance: u64,
    des_pending_balance: u64,
    des_pending_counter: Option<u32>, // Allow overriding destination pending counter
) -> (
    ConfidentialTokenClient,
    Address,
    Address,
    Address,
    Scalar,
    RistrettoPoint,
    Scalar,
    RistrettoPoint,
    ConfidentialBalance,
    ConfidentialBalance,
    CompressedPubkeyBytes, // auditor key
) {
    let admin = Address::generate(e);
    let src = Address::generate(e);
    let des = Address::generate(e);
    let token = create_token(e, &admin);

    // Create test keys
    let auditor_secret_key = new_scalar_from_u64(12345);
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);
    let auditor_key = CompressedPubkeyBytes::from_point(e, &auditor_public_key);

    let src_secret_key = new_scalar_from_u64(54321);
    let src_public_key = pubkey_from_secret_key(&src_secret_key);
    let src_encryption_key = CompressedPubkeyBytes::from_point(e, &src_public_key);

    let des_secret_key = new_scalar_from_u64(98765);
    let des_public_key = pubkey_from_secret_key(&des_secret_key);
    let des_encryption_key = CompressedPubkeyBytes::from_point(e, &des_public_key);

    // Register token for confidential extension
    token.register_confidential_token(&auditor_key);

    // Register both accounts
    token.register_account(&src, &src_encryption_key);
    token.register_account(&des, &des_encryption_key);

    // Create confidential balances
    let src_available_balance_conf = ConfidentialBalance::new_balance_from_u128(
        src_available_balance as u128,
        &generate_balance_randomness(),
        &src_public_key,
    );
    let src_pending_balance_conf = ConfidentialAmount::new_amount_from_u64(
        src_pending_balance,
        &generate_amount_randomness(),
        &src_public_key,
    );

    let des_available_balance_conf = ConfidentialBalance::new_balance_from_u128(
        des_available_balance as u128,
        &generate_balance_randomness(),
        &des_public_key,
    );
    let des_pending_balance_conf = ConfidentialAmount::new_amount_from_u64(
        des_pending_balance,
        &generate_amount_randomness(),
        &des_public_key,
    );

    // Set up account states directly
    e.as_contract(&token.address, || {
        // Set source account
        let mut src_ext = read_account_confidential_ext(&e, src.clone());
        src_ext.available_balance = src_available_balance_conf.to_env_bytes(&e);
        src_ext.pending_balance = src_pending_balance_conf.to_env_bytes(&e);
        write_account_confidential_ext(&e, src.clone(), &src_ext);

        // Set destination account
        let mut des_ext = read_account_confidential_ext(&e, des.clone());
        des_ext.available_balance = des_available_balance_conf.to_env_bytes(&e);
        des_ext.pending_balance = des_pending_balance_conf.to_env_bytes(&e);
        if let Some(counter) = des_pending_counter {
            des_ext.pending_counter = counter;
        }
        write_account_confidential_ext(&e, des.clone(), &des_ext);

        // Update total confidential supply
        let mut token_ext = read_token_confidential_ext(&e);
        token_ext.total_confidential_supply = (src_available_balance
            + des_available_balance
            + src_pending_balance
            + des_pending_balance) as u128;
        write_token_confidential_ext(&e, &token_ext);
    });

    (
        token,
        admin,
        src,
        des,
        src_secret_key,
        src_public_key,
        des_secret_key,
        des_public_key,
        src_available_balance_conf,
        des_available_balance_conf,
        auditor_key,
    )
}

#[test]
fn test_confidential_transfer_success() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Get initial states for verification
    let initial_src_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, src.clone())
    });
    let initial_des_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, des.clone())
    });

    // Perform confidential transfer
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );

    // Verify state changes
    let final_src_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, src.clone())
    });
    let final_des_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, des.clone())
    });

    // Source available balance should be updated
    assert_eq!(final_src_ext.available_balance, src_new_balance);
    // Source pending balance and counter should stay the same
    assert_eq!(
        final_src_ext.pending_balance,
        initial_src_ext.pending_balance
    );
    assert_eq!(
        final_src_ext.pending_counter,
        initial_src_ext.pending_counter
    );

    // Destination pending balance should be updated (encrypted amount is added)
    assert_ne!(
        final_des_ext.pending_balance,
        initial_des_ext.pending_balance
    );
    // Destination pending counter should be incremented
    assert_eq!(
        final_des_ext.pending_counter,
        initial_des_ext.pending_counter + 1
    );
    // Destination available balance should stay the same
    assert_eq!(
        final_des_ext.available_balance,
        initial_des_ext.available_balance
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_confidential_transfer_destination_disabled() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Disable destination account
    token.set_account_enabled_flag(&des, &false);

    // Transfer amount
    let transfer_amount = 200u64;
    let new_src_balance_amount = src_initial_balance - transfer_amount;

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

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

    // Try to perform confidential transfer - should fail with ConfidentialAccountNotEnabled
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_confidential_transfer_insufficient_balance() {
    let e = Env::default();
    e.mock_all_auths();

    let src_initial_balance = 100u64; // Small balance
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

    // Try to transfer more than available balance
    let transfer_amount = 200u64; // More than src_initial_balance
    let wrong_new_src_balance_amount = 1000u64; // Wrong calculation - should cause proof verification to fail

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

    // Generate transfer proof with wrong balance calculation
    let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
        proof::testutils::prove_transfer(
            &e,
            &src_secret_key,
            &src_public_key,
            &des_public_key,
            transfer_amount,
            wrong_new_src_balance_amount as u128, // This will make the proof invalid
            &src_current_balance,
            &auditor_public_key,
        );

    // Try to perform confidential transfer - should fail with TransferProofVerificationFailed
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #3)")]
fn test_confidential_transfer_pending_counter_at_maximum() {
    let e = Env::default();
    e.mock_all_auths();

    let src_initial_balance = 1000u64;
    let des_initial_balance = 500u64;

    // Set destination pending counter to MAX_PENDING_BALANCE_COUNTER
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
        Some(MAX_PENDING_BALANCE_COUNTER),
    );

    // Transfer amount
    let transfer_amount = 200u64;
    let new_src_balance_amount = src_initial_balance - transfer_amount;

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

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

    // Try to perform confidential transfer - should fail with PendingBalanceCounterAtMaximum
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #2)")]
fn test_confidential_transfer_source_disabled() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Disable source account
    token.set_account_enabled_flag(&src, &false);

    // Transfer amount
    let transfer_amount = 200u64;
    let new_src_balance_amount = src_initial_balance - transfer_amount;

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

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

    // Try to perform confidential transfer - should fail with ConfidentialAccountNotEnabled
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #1)")]
fn test_confidential_transfer_token_disabled() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Disable token confidential functionality
    token.set_token_enabled_flag(&false);

    // Transfer amount
    let transfer_amount = 200u64;
    let new_src_balance_amount = src_initial_balance - transfer_amount;

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

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

    // Try to perform confidential transfer - should fail with ConfidentialTokenNotEnabled
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_confidential_transfer_mismatched_auditor_amount() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Transfer amounts
    let transfer_amount = 200u64;
    let different_amount = 250u64; // Different amount for auditor
    let new_src_balance_amount = src_initial_balance - transfer_amount;

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

    // Generate transfer proof
    let (transfer_proof, src_new_balance, src_amount, des_amount, _auditor_amount) =
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

    // Generate different auditor amount (this should cause verification failure)
    let different_auditor_amount = ConfidentialAmount::new_amount_from_u64(
        different_amount,
        &generate_amount_randomness(),
        &auditor_public_key,
    );
    let auditor_amount_bytes = different_auditor_amount.to_env_bytes(&e);

    // Try to perform confidential transfer with mismatched amounts - should fail with TransferProofVerificationFailed
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount_bytes,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_confidential_transfer_wrong_current_balance() {
    let e = Env::default();
    e.mock_all_auths();

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
        _src_current_balance,
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

    // Create wrong current balance for proof generation
    let wrong_current_balance = ConfidentialBalance::new_balance_from_u128(
        2000u128,
        &generate_balance_randomness(),
        &src_public_key,
    );

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

    // Generate transfer proof with wrong current balance
    let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
        proof::testutils::prove_transfer(
            &e,
            &src_secret_key,
            &src_public_key,
            &des_public_key,
            transfer_amount,
            new_src_balance_amount as u128,
            &wrong_current_balance, // Wrong balance used in proof
            &auditor_public_key,
        );

    // Try to perform confidential transfer - should fail with TransferProofVerificationFailed
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_confidential_transfer_wrong_recipient_key() {
    let e = Env::default();
    e.mock_all_auths();

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
        _des_public_key,
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

    // Create wrong recipient key
    let wrong_recipient_secret = new_scalar_from_u64(99999);
    let wrong_recipient_public = pubkey_from_secret_key(&wrong_recipient_secret);

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

    // Generate transfer proof with wrong recipient key
    let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
        proof::testutils::prove_transfer(
            &e,
            &src_secret_key,
            &src_public_key,
            &wrong_recipient_public, // Wrong recipient key
            transfer_amount,
            new_src_balance_amount as u128,
            &src_current_balance,
            &auditor_public_key,
        );

    // Try to perform confidential transfer - should fail with TransferProofVerificationFailed
    // because the proof was generated with a different recipient key than what's registered
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
fn test_confidential_transfer_zero_amount() {
    let e = Env::default();
    e.mock_all_auths();

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

    // Zero transfer amount
    let transfer_amount = 0u64;
    let new_src_balance_amount = src_initial_balance; // Balance should remain the same

    // Get auditor public key
    let auditor_public_key = auditor_key.to_point();

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

    // Get initial states for verification
    let initial_des_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, des.clone())
    });

    // Perform confidential transfer (should succeed even with zero amount)
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );

    // Verify state changes
    let final_src_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, src.clone())
    });
    let final_des_ext = e.as_contract(&token.address, || {
        read_account_confidential_ext(&e, des.clone())
    });

    // Source available balance should be updated (even though amount is zero)
    assert_eq!(final_src_ext.available_balance, src_new_balance);

    // Destination pending balance should be updated (even with zero amount)
    assert_ne!(
        final_des_ext.pending_balance,
        initial_des_ext.pending_balance
    );

    // Destination pending counter should still be incremented
    assert_eq!(
        final_des_ext.pending_counter,
        initial_des_ext.pending_counter + 1
    );
}

#[test]
#[should_panic(expected = "HostError: Error(Contract, #5)")]
fn test_confidential_transfer_wrong_auditor_key() {
    let e = Env::default();
    e.mock_all_auths();

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
        _auditor_key,
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

    // Create wrong auditor key
    let wrong_auditor_secret = new_scalar_from_u64(77777);
    let wrong_auditor_public = pubkey_from_secret_key(&wrong_auditor_secret);

    // Generate transfer proof with wrong auditor key
    let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
        proof::testutils::prove_transfer(
            &e,
            &src_secret_key,
            &src_public_key,
            &des_public_key,
            transfer_amount,
            new_src_balance_amount as u128,
            &src_current_balance,
            &wrong_auditor_public, // Wrong auditor key
        );

    // Try to perform confidential transfer - should fail with TransferProofVerificationFailed
    // because the proof was generated with a different auditor key than what's registered
    token.confidential_transfer(
        &src,
        &des,
        &src_amount,
        &des_amount,
        &auditor_amount,
        &src_new_balance,
        &transfer_proof,
    );
}

#[test]
fn end_to_end_demo() {
    let e = Env::default();
    e.mock_all_auths();

    // Step 1: Create token and admin
    let admin = Address::generate(&e);
    let token = create_token(&e, &admin);

    // Step 2: Create accounts - Alice, Bob, and Carol (observer)
    let alice = Address::generate(&e);
    let bob = Address::generate(&e);
    let _carol = Address::generate(&e); // Observer who shouldn't be able to decrypt

    // Step 3: Create cryptographic keys for all parties
    let alice_secret_key = new_scalar_from_u64(11111);
    let alice_public_key = pubkey_from_secret_key(&alice_secret_key);
    let alice_compressed_pk = CompressedPubkeyBytes::from_point(&e, &alice_public_key);

    let bob_secret_key = new_scalar_from_u64(22222);
    let bob_public_key = pubkey_from_secret_key(&bob_secret_key);
    let bob_compressed_pk = CompressedPubkeyBytes::from_point(&e, &bob_public_key);

    let _carol_secret_key = new_scalar_from_u64(33333); // Carol's key (shouldn't work for decryption)

    // Create auditor key
    let auditor_secret_key = new_scalar_from_u64(99999);
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);
    let auditor_compressed_pk = CompressedPubkeyBytes::from_point(&e, &auditor_public_key);

    // Step 4: Register confidential token extension with auditor
    token.register_confidential_token(&auditor_compressed_pk);

    // Step 5: Register Alice and Bob for confidential transfers
    token.register_account(&alice, &alice_compressed_pk);
    token.register_account(&bob, &bob_compressed_pk);

    // Step 6: Mint tokens to Alice and Bob (transparent balance)
    let alice_initial_amount = 1000i128;
    let bob_initial_amount = 500i128;
    
    token.mint(&alice, &alice_initial_amount);
    token.mint(&bob, &bob_initial_amount);

    // Verify initial transparent balances
    assert_eq!(token.balance(&alice), alice_initial_amount);
    assert_eq!(token.balance(&bob), bob_initial_amount);

    // Step 7: Alice and Bob make confidential deposits (transparent → confidential pending balance)
    let alice_deposit_amount = (alice_initial_amount / 2) as u64; // 500
    let bob_deposit_amount = (bob_initial_amount / 2) as u64;     // 250

    // The deposit() function moves tokens from transparent balance to confidential pending balance
    // This is the entry point into the confidential transfer system
    token.deposit(&alice, &alice_deposit_amount);
    token.deposit(&bob, &bob_deposit_amount);

    // ═══════════════════════════════════════════════════════════════════════════════
    //  STATE AFTER MINT AND CONFIDENTIAL DEPOSIT
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    //                    ┌─────────────────────────────────┐
    //                    │         TOKEN STATE             │
    //                    │  Total Confidential Supply: 750 │
    //                    └─────────────────────────────────┘
    //
    //   ┌─────────────────────────────┐          ┌─────────────────────────────┐
    //   │           ALICE             │          │            BOB              │
    //   │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │
    //   │ │ Transparent:       500  │ │          │ │ Transparent:       250  │ │
    //   │ │ Available:           0  │ │          │ │ Available:           0  │ │
    //   │ │ Pending:           500  │ │          │ │ Pending:           250  │ │
    //   │ │ Counter:             1  │ │          │ │ Counter:             1  │ │
    //   │ └─────────────────────────┘ │          │ └─────────────────────────┘ │
    //   └─────────────────────────────┘          └─────────────────────────────┘
    //
    //   Original: 1000 → 500 deposited            Original: 500 → 250 deposited
    //
    // ═══════════════════════════════════════════════════════════════════════════════

    // Dump the state for Sanity check
    let (token_ext, alice_ext, bob_ext, alice_transparent, bob_transparent) = e.as_contract(&token.address, || {
        (read_token_confidential_ext(&e),
        read_account_confidential_ext(&e, alice.clone()),
        read_account_confidential_ext(&e, bob.clone()),
        read_balance(&e, alice.clone()),
        read_balance(&e, bob.clone()))
    });
    std::eprintln!("After mint and confidential deposit");
    std::eprintln!("Token extention: {:?}", token_ext);
    std::eprintln!("Alice extention: {:?}", alice_ext);
    std::eprintln!("Alice (transparent) balance: {:?}", alice_transparent);
    std::eprintln!("Bob extention: {:?}", bob_ext);
    std::eprintln!("Bob (transparent) balance: {:?}", bob_transparent);
    
    // Verify transparent balances after deposits
    assert_eq!(token.balance(&alice), alice_initial_amount - alice_deposit_amount as i128);
    assert_eq!(token.balance(&bob), bob_initial_amount - bob_deposit_amount as i128);

    // Step 8: Alice performs rollover to move pending balance to available balance
    let alice_new_balance_amount = alice_deposit_amount as u128;
    let balance_pre_normalization = ConfidentialBalance::new_balance_with_no_randomness(alice_new_balance_amount);
    
    // Create normalization proof for Alice's rollover
    let (alice_rollover_proof, alice_new_balance_bytes) = proof::testutils::prove_normalization(
        &e,
        &alice_secret_key,
        &alice_public_key,
        alice_new_balance_amount,
        &balance_pre_normalization,
    );

    token.rollover_pending_balance(
        &alice,
        &alice_new_balance_bytes,
        &alice_rollover_proof,
    );

    // ═══════════════════════════════════════════════════════════════════════════════
    // STATE AFTER ALICE'S ROLLOVER (Pending → Available)
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    //                    ┌─────────────────────────────────┐
    //                    │         TOKEN STATE             │
    //                    │  Total Confidential Supply: 750 │
    //                    └─────────────────────────────────┘
    //
    //   ┌─────────────────────────────┐          ┌─────────────────────────────┐
    //   │           ALICE             │          │            BOB              │
    //   │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │
    //   │ │ Transparent:       500  │ │          │ │ Transparent:       250  │ │
    //   │ │ Available:         500  │ │◄──────   │ │ Available:           0  │ │
    //   │ │ Pending:             0  │ │ Rolled   │ │ Pending:           250  │ │
    //   │ │ Counter:             0  │ │ Over     │ │ Counter:             1  │ │
    //   │ └─────────────────────────┘ │          │ └─────────────────────────┘ │
    //   └─────────────────────────────┘          └─────────────────────────────┘
    //
    //   Alice can now make confidential transfers!   Bob still needs to rollover
    //
    // ═══════════════════════════════════════════════════════════════════════════════

    // Dump the state for Sanity check
    let (alice_ext_after_rollover, alice_transparent_after_rollover) = e.as_contract(&token.address, || {
        (read_account_confidential_ext(&e, alice.clone()),
         read_balance(&e, alice.clone()))
    });
    std::eprintln!("After alice's rollover");
    std::eprintln!("Alice extention: {:?}", alice_ext_after_rollover);
    std::eprintln!("Alice (transparent) balance: {:?}", alice_transparent_after_rollover);

    // Step 9: Alice performs confidential transfer to Bob
    let transfer_amount = 200u64;
    let alice_new_balance_after_transfer = alice_deposit_amount as u128 - transfer_amount as u128; // 300

    // Get Alice's current balance (after rollover)
    let alice_current_balance = ConfidentialBalance::from_env_bytes(&alice_new_balance_bytes);

    // Generate transfer proof
    let (transfer_proof, alice_balance_after_transfer, amount_for_alice, amount_for_bob, amount_for_auditor) =
        proof::testutils::prove_transfer(
            &e,
            &alice_secret_key,
            &alice_public_key,
            &bob_public_key,
            transfer_amount,
            alice_new_balance_after_transfer,
            &alice_current_balance,
            &auditor_public_key,
        );

    // Execute the confidential transfer
    token.confidential_transfer(
        &alice,
        &bob,
        &amount_for_alice,
        &amount_for_bob,
        &amount_for_auditor,
        &alice_balance_after_transfer,
        &transfer_proof,
    );

    // ═══════════════════════════════════════════════════════════════════════════════
    // STATE AFTER CONFIDENTIAL TRANSFER (Alice → Bob: 200 tokens)
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    //                    ┌─────────────────────────────────┐
    //                    │         TOKEN STATE             │
    //                    │  Total Confidential Supply: 750 │
    //                    └─────────────────────────────────┘
    //
    //   ┌─────────────────────────────┐          ┌─────────────────────────────┐
    //   │           ALICE             │   200    │            BOB              │
    //   │ ┌─────────────────────────┐ │ ──────►  │ ┌─────────────────────────┐ │
    //   │ │ Transparent:       500  │ │          │ │ Transparent:       250  │ │
    //   │ │ Available:         300  │ │          │ │ Available:           0  │ │
    //   │ │ Pending:             0  │ │          │ │ Pending:           450  │ │
    //   │ │ Counter:             0  │ │          │ │ Counter:             2  │ │
    //   │ └─────────────────────────┘ │          │ └─────────────────────────┘ │
    //   └─────────────────────────────┘          └─────────────────────────────┘
    //
    //   Alice sent 200 confidentially            Bob received 200 + had 250 = 450
    //   (500 - 200 = 300 remaining)              (pending counter increased)
    //
    // ═══════════════════════════════════════════════════════════════════════════════

    // Dump the state for Sanity check
    let (token_ext_after_transfer, alice_ext_after_transfer, alice_transparent_after_transfer, bob_ext_after_transfer, bob_transparent_after_transfer) = e.as_contract(&token.address, || {
        (read_token_confidential_ext(&e),
         read_account_confidential_ext(&e, alice.clone()),
         read_balance(&e, alice.clone()),
         read_account_confidential_ext(&e, bob.clone()),
         read_balance(&e, bob.clone()))
    });
    std::eprintln!("After confidential transfer from alice to bob");
    std::eprintln!("Token extention: {:?}", token_ext_after_transfer);
    std::eprintln!("Alice extention: {:?}", alice_ext_after_transfer);
    std::eprintln!("Alice (transparent) balance: {:?}", alice_transparent_after_transfer);
    std::eprintln!("Bob extention: {:?}", bob_ext_after_transfer);
    std::eprintln!("Bob (transparent) balance: {:?}", bob_transparent_after_transfer);

    // Step 10: Demonstrate decryption capabilities
    // Alice can decrypt her amount
    let alice_decrypted_amount = ConfidentialAmount::from_env_bytes(&amount_for_alice).decrypt(&alice_secret_key);
    assert_eq!(alice_decrypted_amount as u64, transfer_amount);

    // Bob can decrypt his amount
    let bob_decrypted_amount = ConfidentialAmount::from_env_bytes(&amount_for_bob).decrypt(&bob_secret_key);
    assert_eq!(bob_decrypted_amount as u64, transfer_amount);

    // Auditor can decrypt the auditor amount
    let auditor_decrypted_amount = ConfidentialAmount::from_env_bytes(&amount_for_auditor).decrypt(&auditor_secret_key);
    assert_eq!(auditor_decrypted_amount as u64, transfer_amount);

    // Alice can decrypt her new balance
    let alice_decrypted_balance = ConfidentialBalance::from_env_bytes(&alice_balance_after_transfer).decrypt(&alice_secret_key);
    assert_eq!(alice_decrypted_balance, alice_new_balance_after_transfer);

    // Step 11: Demonstrate that Carol (observer) CANNOT decrypt any amounts
    // let carol_attempt_alice = ConfidentialAmount::from_env_bytes(&amount_for_alice).decrypt(&carol_secret_key);
    // assert_ne!(carol_attempt_alice as u64, transfer_amount); // Carol gets wrong value

    // let carol_attempt_bob = ConfidentialAmount::from_env_bytes(&amount_for_bob).decrypt(&carol_secret_key);
    // assert_ne!(carol_attempt_bob as u64, transfer_amount); // Carol gets wrong value

    // let carol_attempt_auditor = ConfidentialAmount::from_env_bytes(&amount_for_auditor).decrypt(&carol_secret_key);
    // assert_ne!(carol_attempt_auditor as u64, transfer_amount); // Carol gets wrong value

    // Step 12: Bob performs rollover pending balance action  
    let bob_received_amount = transfer_amount as u128;    // 200
    let bob_total_after_rollover = bob_deposit_amount as u128 + bob_received_amount; // 250 + 200 = 450

    let bob_balance_pre_normalization = e.as_contract(&token.address, || {
        let ext = read_account_confidential_ext(&e, bob.clone());
        // Bob's pending: 250 (initial confidential deposit) + 200 (received from Alice) = 450
        // Bob's available: 0 (no previous rollover)
        let balance = ConfidentialBalanceBytes::add_amount(&e, &ext.available_balance, &ext.pending_balance);
        ConfidentialBalance::from_env_bytes(&balance)
    });
    let (bob_rollover_proof, bob_new_balance_bytes) = proof::testutils::prove_normalization(
        &e,
        &bob_secret_key,
        &bob_public_key,
        bob_total_after_rollover,
        &bob_balance_pre_normalization,
    );

    token.rollover_pending_balance(
        &bob,
        &bob_new_balance_bytes,
        &bob_rollover_proof,
    );

    // ═══════════════════════════════════════════════════════════════════════════════
    // STATE AFTER BOB'S ROLLOVER (Pending → Available)
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    //                    ┌─────────────────────────────────┐
    //                    │         TOKEN STATE             │
    //                    │  Total Confidential Supply: 750 │
    //                    └─────────────────────────────────┘
    //
    //   ┌─────────────────────────────┐          ┌─────────────────────────────┐
    //   │           ALICE             │          │            BOB              │
    //   │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │
    //   │ │ Transparent:       500  │ │          │ │ Transparent:       250  │ │
    //   │ │ Available:         300  │ │          │ │ Available:         450  │ │◄──────
    //   │ │ Pending:             0  │ │          │ │ Pending:             0  │ │ Rolled
    //   │ │ Counter:             0  │ │          │ │ Counter:             0  │ │ Over
    //   │ └─────────────────────────┘ │          │ └─────────────────────────┘ │
    //   └─────────────────────────────┘          └─────────────────────────────┘
    //
    //   Alice: 300 confidential ready             Bob: 450 confidential ready
    //          + 500 transparent                         + 250 transparent
    //
    // ═══════════════════════════════════════════════════════════════════════════════

    // Dump the state for Sanity check
    let (bob_ext_after_rollover, bob_transparent_after_rollover) = e.as_contract(&token.address, || {
        (read_account_confidential_ext(&e, bob.clone()),
         read_balance(&e, bob.clone()))
    });
    std::eprintln!("After Bob's rollover");
    std::eprintln!("Bob extention: {:?}", bob_ext_after_rollover);
    std::eprintln!("Bob (transparent) balance: {:?}", bob_transparent_after_rollover);

    // Step 13: Verify Bob's final balance is correct
    let bob_final_decrypted_balance = ConfidentialBalance::from_env_bytes(&bob_new_balance_bytes).decrypt(&bob_secret_key);
    assert_eq!(bob_final_decrypted_balance, bob_total_after_rollover);
    // Bob's transparent balance should be unchanged, but confidential increased
    assert_eq!(token.balance(&bob), bob_initial_amount - bob_deposit_amount as i128);    

    // Step 14: Bob performs a withdrawal of 100, check and verify all bob's balances and the token's total_confidential_supply
    let withdrawal_amount = 100u64;
    let bob_balance_after_withdrawal = bob_total_after_rollover - withdrawal_amount as u128; // 450 - 100 = 350
    
    // Create withdrawal proof
    let (withdrawal_proof, bob_new_balance_after_withdrawal) = proof::testutils::prove_withdrawal(
        &e,
        &bob_secret_key,
        &bob_public_key,
        withdrawal_amount,
        bob_balance_after_withdrawal,
        &ConfidentialBalance::from_env_bytes(&bob_new_balance_bytes),
    );
    
    // Get Bob's transparent balance before withdrawal
    let bob_transparent_before_withdrawal = token.balance(&bob);
    
    // Get token's total confidential supply before withdrawal
    let token_supply_before_withdrawal = e.as_contract(&token.address, || {
        read_token_confidential_ext(&e).total_confidential_supply
    });
    
    // Perform withdrawal
    token.withdraw(
        &bob,
        &withdrawal_amount,
        &bob_new_balance_after_withdrawal,
        &withdrawal_proof,
    );
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // STATE AFTER BOB'S WITHDRAWAL (Confidential → Transparent: 100 tokens)
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    //                    ┌─────────────────────────────────┐
    //                    │         TOKEN STATE             │
    //                    │  Total Confidential Supply: 650 │◄─── Decreased!
    //                    └─────────────────────────────────┘
    //
    //   ┌─────────────────────────────┐          ┌─────────────────────────────┐
    //   │           ALICE             │          │            BOB              │
    //   │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │
    //   │ │ Transparent:       500  │ │          │ │ Transparent:       350  │ │◄──────
    //   │ │ Available:         300  │ │          │ │ Available:         350  │ │ +100
    //   │ │ Pending:             0  │ │          │ │ Pending:             0  │ │ Withdrawn
    //   │ │ Counter:             0  │ │          │ │ Counter:             0  │ │
    //   │ └─────────────────────────┘ │          │ └─────────────────────────┘ │
    //   └─────────────────────────────┘          └─────────────────────────────┘
    //
    //   Alice: Unchanged                          Bob: 100 moved from confidential
    //          300 + 500 = 800 total                   to transparent (350 + 350 = 700)
    //
    //     FINAL ACCOUNTING: Alice(800) + Bob(700) = 1500 total
    //      Confidential: Alice(300) + Bob(350) = 650
    //
    // ═══════════════════════════════════════════════════════════════════════════════

    // Dump the state for Sanity check
    let (token_ext_after_withdrawal, bob_ext_after_withdrawal, bob_transparent_after_withdrawal) = e.as_contract(&token.address, || {
        (read_token_confidential_ext(&e),
         read_account_confidential_ext(&e, bob.clone()),
         read_balance(&e, bob.clone()))
    });
    std::eprintln!("After Bob's withdrawal of {}", withdrawal_amount);
    std::eprintln!("Token extention: {:?}", token_ext_after_withdrawal);
    std::eprintln!("Bob extention: {:?}", bob_ext_after_withdrawal);
    std::eprintln!("Bob (transparent) balance: {:?}", bob_transparent_after_withdrawal);
    
    // Step 15: Verify all balances after withdrawal
    
    // Bob's transparent balance should have increased by withdrawal amount
    let bob_transparent_after_withdrawal = token.balance(&bob);
    assert_eq!(
        bob_transparent_after_withdrawal,
        bob_transparent_before_withdrawal + withdrawal_amount as i128
    );
    
    // Bob's confidential balance should have decreased by withdrawal amount
    let bob_final_confidential_balance = ConfidentialBalance::from_env_bytes(&bob_new_balance_after_withdrawal).decrypt(&bob_secret_key);
    assert_eq!(bob_final_confidential_balance, bob_balance_after_withdrawal);
    
    // Token's total confidential supply should have decreased by withdrawal amount
    let token_supply_after_withdrawal = e.as_contract(&token.address, || {
        read_token_confidential_ext(&e).total_confidential_supply
    });
    assert_eq!(
        token_supply_after_withdrawal,
        token_supply_before_withdrawal - withdrawal_amount as u128
    );
    
    // Final verification: Complete balance accounting
    // Alice: 500 transparent, 300 confidential
    // Bob: 350 transparent (250 original + 100 withdrawn), 350 confidential (450 - 100)
    // Total confidential supply: 650 (300 Alice + 350 Bob)
    
    assert_eq!(token.balance(&alice), alice_initial_amount - alice_deposit_amount as i128); // 500
    assert_eq!(token.balance(&bob), bob_initial_amount - bob_deposit_amount as i128 + withdrawal_amount as i128); // 350
    
    let alice_final_confidential = ConfidentialBalance::from_env_bytes(&alice_balance_after_transfer).decrypt(&alice_secret_key);
    assert_eq!(alice_final_confidential, 300); // 500 - 200 transferred
    assert_eq!(bob_final_confidential_balance, 350); // 450 - 100 withdrawn
    
    let final_total_confidential_supply = e.as_contract(&token.address, || {
        read_token_confidential_ext(&e).total_confidential_supply
    });
    assert_eq!(final_total_confidential_supply, alice_final_confidential + bob_final_confidential_balance);
}


mod confidential_token_contract {
    soroban_sdk::contractimport!(file = "opt/confidential_token.wasm");
}

#[test]
fn test_confidential_transfer_wasm_contract() {
    // setup env and contract client
    let e = Env::default();
    e.mock_all_auths();
    e.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&e);
    let contract_id = e.register(confidential_token_contract::WASM, 
        (
            &admin,
            7_u32,
            String::from_val(&e, &"name"),
            String::from_val(&e, &"symbol"),
        )        
    );
    let client = confidential_token_contract::Client::new(&e, &contract_id);

    // set up accounts, token ext
    let src = Address::generate(&e);
    let des = Address::generate(&e);

    let auditor_secret_key = new_scalar_from_u64(12345);
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);
    let auditor_key = CompressedPubkeyBytes::from_point(&e, &auditor_public_key);

    let src_secret_key = new_scalar_from_u64(54321);
    let src_public_key = pubkey_from_secret_key(&src_secret_key);
    let src_encryption_key = CompressedPubkeyBytes::from_point(&e, &src_public_key);

    let des_secret_key = new_scalar_from_u64(98765);
    let des_public_key = pubkey_from_secret_key(&des_secret_key);
    let des_encryption_key = CompressedPubkeyBytes::from_point(&e, &des_public_key);

    client.register_confidential_token(&confidential_token_contract::CompressedPubkeyBytes(auditor_key.0.clone()));
    client.register_account(
        &src,
        &confidential_token_contract::CompressedPubkeyBytes(src_encryption_key.0),
    );
    client.register_account(
        &des,
        &confidential_token_contract::CompressedPubkeyBytes(des_encryption_key.0),
    );

    // set up initial balances
    client.mint(&src, &1000);
    client.mint(&des, &1000);

    client.deposit(&src, &700); // src balances: clear - 300, pending - 700, available - 0
    e.cost_estimate().budget().print();
    e.cost_estimate().budget().reset_unlimited();

    // Create normalization proof for src's rollover
    let (rollover_proof, new_balance_bytes) = proof::testutils::prove_normalization(
        &e,
        &src_secret_key,
        &src_public_key,
        700,
        &ConfidentialBalance::new_balance_with_no_randomness(700),
    );    
    let new_balance_bytes = confidential_token_contract::ConfidentialBalanceBytes::from_xdr(&e, &new_balance_bytes.to_xdr(&e)).unwrap();
    let proof = confidential_token_contract::NewBalanceProofBytes::from_xdr(&e, &rollover_proof.to_xdr(&e)).unwrap();

    client.rollover_pending_balance(&src, &new_balance_bytes, &proof); // src balances: clear - 300, pending - 0, available - 700
    e.cost_estimate().budget().print();
    e.cost_estimate().budget().reset_unlimited();
    
    // Transfer amount
    let transfer_amount = 200u64;
    let new_src_balance_amount = 500u128; // 700 - 200

    let src_current_balance = e.as_contract(&contract_id, || {
        let src_ext = read_account_confidential_ext(&e, src.clone());
        src_ext.available_balance
    });

    // Generate transfer proof
    let (transfer_proof, src_new_balance, src_amount, des_amount, auditor_amount) =
        proof::testutils::prove_transfer(
            &e,
            &src_secret_key,
            &src_public_key,
            &des_public_key,
            transfer_amount,
            new_src_balance_amount,
            &ConfidentialBalance::from_env_bytes(&src_current_balance),
            &auditor_key.to_point(),
        );
    let amt_src = confidential_token_contract::ConfidentialAmountBytes::from_xdr(&e, &src_amount.to_xdr(&e)).unwrap();
    let amt_des = confidential_token_contract::ConfidentialAmountBytes::from_xdr(&e, &des_amount.to_xdr(&e)).unwrap();
    let amt_auditor = confidential_token_contract::ConfidentialAmountBytes::from_xdr(&e, &auditor_amount.to_xdr(&e)).unwrap();
    let src_new_balance = confidential_token_contract::ConfidentialBalanceBytes::from_xdr(&e, &src_new_balance.to_xdr(&e)).unwrap();
    let proof = confidential_token_contract::TransferProofBytes::from_xdr(&e, &transfer_proof.to_xdr(&e)).unwrap();
    client.confidential_transfer(&src, &des, &amt_src, &amt_des, &amt_auditor, &src_new_balance, &proof);
    e.cost_estimate().budget().print();
    e.cost_estimate().budget().reset_unlimited();
}