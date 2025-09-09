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

/// Setup a confidential token with initial mint and account registration
pub fn setup_confidential_token_with_deposit(
    e: &Env,
    initial_balance: i128,
    deposit_amount: u64,
) -> (ConfidentialTokenClient, Address, Address, Scalar, RistrettoPoint) {
    // Generate keys
    let user_secret_key = new_scalar_from_u64(1u64);
    let user_public_key = pubkey_from_secret_key(&user_secret_key);
    let auditor_secret_key = new_scalar_from_u64(999u64);
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);

    // Create addresses
    let admin = Address::generate(e);
    let user = Address::generate(e);

    // Deploy token contract
    let token = create_token(e, &admin);

    // Initialize token
    token.register_confidential_token(
        &CompressedPubkeyBytes::from_point(e, &auditor_public_key),
    );

    // Mint initial balance and register account
    token.mint(&user, &initial_balance);
    token.register_account(
        &user,
        &CompressedPubkeyBytes::from_point(e, &user_public_key),
    );

    // Perform deposit
    token.deposit(&user, &deposit_amount);

    (token, admin, user, user_secret_key, user_public_key)
}

/// Setup a confidential token account with specified available and pending balances
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
    Address,
) {
    // Generate keys for user and auditor
    let user_secret_key = new_scalar_from_u64(1u64);
    let user_public_key = pubkey_from_secret_key(&user_secret_key);
    let auditor_secret_key = new_scalar_from_u64(999u64);
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);

    // Create addresses
    let admin = Address::generate(e);
    let user = Address::generate(e);
    let auditor = Address::generate(e);

    // Deploy token contract
    let token = create_token(e, &admin);

    // Initialize token
    token.register_confidential_token(
        &CompressedPubkeyBytes::from_point(e, &auditor_public_key),
    );

    // Mint initial transparent balance for user
    let initial_transparent_balance = 10000i128;
    token.mint(&user, &initial_transparent_balance);

    // Register user account for confidential operations
    token.register_account(
        &user,
        &CompressedPubkeyBytes::from_point(e, &user_public_key),
    );

    // Create confidential balances with specified amounts
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

    // Set up the account with the specified balances
    e.as_contract(&token.address, || {
        let mut ext = read_account_confidential_ext(e, user.clone());
        ext.available_balance = available_balance.to_env_bytes(e);
        ext.pending_balance = pending_balance.to_env_bytes(e);
        ext.pending_counter = if initial_pending_balance > 0 { 1 } else { 0 };
        write_account_confidential_ext(e, user.clone(), &ext);

        // Update token's total confidential supply
        let mut token_ext = read_token_confidential_ext(e);
        token_ext.total_confidential_supply = (initial_available_balance + initial_pending_balance) as u128;
        write_token_confidential_ext(e, &token_ext);
    });

    (token, admin, user, user_secret_key, user_public_key, available_balance, auditor)
}

/// Setup a confidential token with two accounts
pub fn setup_confidential_token_two_accounts(
    e: &Env,
    src_available_balance: u64,
    src_pending_balance: u64,
    des_available_balance: u64,
    des_pending_balance: u64,
    auditor_key_opt: Option<Scalar>,
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
    Scalar,
) {
    // Generate keys
    let src_secret_key = new_scalar_from_u64(1u64);
    let src_public_key = pubkey_from_secret_key(&src_secret_key);
    let des_secret_key = new_scalar_from_u64(2u64);
    let des_public_key = pubkey_from_secret_key(&des_secret_key);
    let auditor_secret_key = auditor_key_opt.unwrap_or_else(|| new_scalar_from_u64(999u64));
    let auditor_public_key = pubkey_from_secret_key(&auditor_secret_key);

    // Create addresses
    let admin = Address::generate(e);
    let src = Address::generate(e);
    let des = Address::generate(e);

    // Deploy token contract
    let token = create_token(e, &admin);

    // Initialize token
    token.register_confidential_token(
        &CompressedPubkeyBytes::from_point(e, &auditor_public_key),
    );

    // Mint initial transparent balances
    token.mint(&src, &10000i128);
    token.mint(&des, &10000i128);

    // Register accounts
    token.register_account(
        &src,
        &CompressedPubkeyBytes::from_point(e, &src_public_key),
    );
    token.register_account(
        &des,
        &CompressedPubkeyBytes::from_point(e, &des_public_key),
    );

    // Create confidential balances
    let src_available = ConfidentialBalance::new_balance_from_u128(
        src_available_balance as u128,
        &generate_balance_randomness(),
        &src_public_key,
    );
    let des_available = ConfidentialBalance::new_balance_from_u128(
        des_available_balance as u128,
        &generate_balance_randomness(),
        &des_public_key,
    );

    // Set up accounts with balances
    e.as_contract(&token.address, || {
        let mut src_ext = read_account_confidential_ext(e, src.clone());
        src_ext.available_balance = src_available.to_env_bytes(e);
        src_ext.pending_counter = if src_pending_balance > 0 { 1 } else { 0 };
        write_account_confidential_ext(e, src.clone(), &src_ext);

        let mut des_ext = read_account_confidential_ext(e, des.clone());
        des_ext.available_balance = des_available.to_env_bytes(e);
        des_ext.pending_counter = if des_pending_balance > 0 { 1 } else { 0 };
        write_account_confidential_ext(e, des.clone(), &des_ext);

        // Update token's total confidential supply
        let mut token_ext = read_token_confidential_ext(e);
        token_ext.total_confidential_supply = (src_available_balance + src_pending_balance + des_available_balance + des_pending_balance) as u128;
        write_token_confidential_ext(e, &token_ext);
    });

    (
        token, admin, src, des, src_secret_key, src_public_key, des_secret_key, des_public_key,
        src_available, des_available, auditor_secret_key,
    )
}
