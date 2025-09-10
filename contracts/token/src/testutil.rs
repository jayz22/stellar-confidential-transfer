#![cfg(any(test, feature = "testutils"))]

use crate::{
    contract::ConfidentialToken,
    utils::*,
    ConfidentialTokenClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, FromVal, String};
use stellar_confidential_crypto::{
    arith::{new_scalar_from_u64, pubkey_from_secret_key},
    confidential_balance::{
        testutils::{generate_amount_randomness, generate_balance_randomness},
        ConfidentialBalance,
    },
    proof::CompressedPubkeyBytes,
    ConfidentialAmount, RistrettoPoint, Scalar,
};

/// Creates a new confidential token with basic setup
pub fn create_token<'a>(e: &Env, admin: &Address) -> ConfidentialTokenClient<'a> {
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

// Helper function to create a CompressedPubkeyBytes for account encryption key
pub fn create_test_account_key(e: &Env, seed: u64) -> CompressedPubkeyBytes {
    let secret_key = new_scalar_from_u64(seed);
    let public_key = pubkey_from_secret_key(&secret_key);
    CompressedPubkeyBytes::from_point(e, &public_key)
}

// Helper function to setup confidential token for testing
pub fn setup_confidential_token_with_account(e: &Env) -> (ConfidentialTokenClient, Address, Address) {
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

// Helper function to setup confidential token with deposit and return user keys for proof generation
pub fn setup_confidential_token_account_with_balances(
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


// Helper function to setup confidential token with deposit and return user keys for proof generation
pub fn setup_confidential_token_with_deposit(
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

// Helper function to setup confidential token with two accounts for transfer testing
pub fn setup_confidential_token_two_accounts(
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