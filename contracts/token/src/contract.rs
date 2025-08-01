use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    token::{self, TokenInterface},
    Address, Env, String, Symbol,
};
use soroban_token_sdk::metadata::TokenMetadata;
use soroban_token_sdk::TokenUtils;

use crate::utils::*;
use stellar_confidential_crypto::{
    proof::{
        verify_normalization_proof, verify_transfer_proof, verify_withdrawal_proof,
        CompressedPubkeyBytes, NewBalanceProofBytes, TransferProofBytes,
    },
    ConfidentialAmountBytes, ConfidentialBalanceBytes,
};

pub const MAX_PENDING_BALANCE_COUNTER: u32 = 0x10000;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ConfidentialTokenError {
    ConfidentialTokenNotEnabled = 1,
    ConfidentialAccountNotEnabled = 2,
    PendingBalanceCounterAtMaximum = 3,
    WithdrawalProofVerificationFailed = 4,
    TransferProofVerificationFailed = 5,
    NormalizationProofVerificationFailed = 6,
    Unknown = 99,
}

#[contract]
pub struct ConfidentialToken;

#[contracttype]
#[derive(Debug)]
pub struct TokenConfidentialExt {
    pub enabled_flag: bool, // enable/disable this token's confidential functionalities, controlled by the admin
    pub auditor: CompressedPubkeyBytes,
    pub total_confidential_supply: u128,
}

#[contracttype]
#[derive(Debug)]
pub struct AccountConfidentialExt {
    pub enabled_flag: bool, // enable/disable this account's confidential functionalities, controlled by the admin
    pub encryption_key: CompressedPubkeyBytes,
    pub available_balance: ConfidentialBalanceBytes,
    pub pending_balance: ConfidentialAmountBytes,
    pub pending_counter: u32,
}

// The confidential transfer functionalities
#[contractimpl]
impl ConfidentialToken {
    // Register this token for the confidential extention
    pub fn register_confidential_token(e: &Env, auditor_key: CompressedPubkeyBytes) {
        read_administrator(e).require_auth();
        init_token_confidential_ext(e, auditor_key);
    }

    pub fn register_account(e: &Env, acc: Address, ek: CompressedPubkeyBytes) {
        read_administrator(e).require_auth();
        init_acc_confidential_ext(e, acc, ek);
    }

    pub fn set_token_enabled_flag(e: &Env, flag: bool) {
        read_administrator(e).require_auth();
        let mut ext = read_token_confidential_ext(e);
        ext.enabled_flag = flag;
        write_token_confidential_ext(e, &ext);
    }

    pub fn set_account_enabled_flag(e: &Env, acc: Address, flag: bool) {
        read_administrator(e).require_auth();
        let mut ext = read_account_confidential_ext(e, acc.clone());
        ext.enabled_flag = flag;
        write_account_confidential_ext(e, acc, &ext);
    }

    // Deposit `amt` from `acc`'s transparent balance into its confidential pending balance (`amt` encrypted with zero randomness)
    pub fn deposit(e: &Env, acc: Address, amt: u64) -> Result<(), ConfidentialTokenError> {
        acc.require_auth();

        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let mut token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialTokenNotEnabled);
        }

        // load the `acc`'s confidential extention, fail if doesn't exist or not enabled
        let mut acc_ext = read_account_confidential_ext(e, acc.clone());
        if !acc_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialAccountNotEnabled);
        }

        // check if `acc`'s `pending_balance_counter` has reached MAX_PENDING_BALANCE_COUNTER, if so fail.
        if acc_ext.pending_counter >= MAX_PENDING_BALANCE_COUNTER {
            return Err(ConfidentialTokenError::PendingBalanceCounterAtMaximum);
        }

        // Subtracts `amt` from `acc`'s regular (transparent) `balance`, fail if `balance` is less than `amt`.
        spend_balance(e, acc.clone(), amt as i128);

        // Encrypt the `amt` using zero randomness (`r = 0`) into `encrypted_amt`, add the `encrypted_amt` to the `pending_balance`.
        acc_ext.pending_balance = ConfidentialAmountBytes::add(
            e,
            &acc_ext.pending_balance,
            &ConfidentialAmountBytes::from_u64_with_no_randomness(e, amt),
        );

        // Increment `acc`'s `pending_balance_counter`
        acc_ext.pending_counter += 1;
        write_account_confidential_ext(e, acc.clone(), &acc_ext);

        // Update token's total confidential supply
        token_ext.total_confidential_supply = token_ext
            .total_confidential_supply
            .checked_add(amt as u128)
            .unwrap();
        write_token_confidential_ext(e, &token_ext);

        //  Emits an event
        let topics = (Symbol::new(e, "ConfidentialToken_deposit"), acc);
        e.events().publish(topics, amt);

        Ok(())
    }

    // Withdraw an amount from acc's confidential available balance to its transparent balance
    pub fn withdraw(
        e: &Env,
        acc: Address,
        amt: u64,
        new_balance: ConfidentialBalanceBytes,
        proof: NewBalanceProofBytes,
    ) -> Result<(), ConfidentialTokenError> {
        acc.require_auth();

        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let mut token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialTokenNotEnabled);
        }

        // load the `acc`'s confidential extention, fail if doesn't exist or not enabled
        let mut acc_ext = read_account_confidential_ext(e, acc.clone());
        if !acc_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialAccountNotEnabled);
        }

        // Verifies the WithdrawalProof against current balance, new balance, and amount
        verify_withdrawal_proof(
            &acc_ext.encryption_key,
            amt,
            &acc_ext.available_balance,
            &new_balance,
            &proof,
        )
        .map_err(|_| ConfidentialTokenError::WithdrawalProofVerificationFailed)?;

        // Sets `acc`'s `available_balance` to `new_balance`
        acc_ext.available_balance = new_balance;
        write_account_confidential_ext(e, acc.clone(), &acc_ext);

        // Increase `acc`'s transparent balance by `amt`
        receive_balance(e, acc.clone(), amt as i128);

        // Update token's total confidential supply (decrease)
        token_ext.total_confidential_supply = token_ext
            .total_confidential_supply
            .checked_sub(amt as u128)
            .ok_or(ConfidentialTokenError::Unknown)?;
        write_token_confidential_ext(e, &token_ext);

        // Emits an event
        let topics = (Symbol::new(e, "ConfidentialToken_withdraw"), acc);
        e.events().publish(topics, amt);

        Ok(())
    }

    // Transfers an amount confidentially between two accounts.
    pub fn confidential_transfer(
        e: &Env,
        src: Address,
        des: Address,
        amt_src: ConfidentialAmountBytes,
        amt_des: ConfidentialAmountBytes,
        amt_auditor: ConfidentialAmountBytes,
        src_new_balance: ConfidentialBalanceBytes,
        proof: TransferProofBytes,
    ) -> Result<(), ConfidentialTokenError> {
        src.require_auth();

        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialTokenNotEnabled);
        }

        // load the `src`'s confidential extention, fail if doesn't exist or not enabled
        let mut src_ext = read_account_confidential_ext(e, src.clone());
        if !src_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialAccountNotEnabled);
        }

        // load the `des`'s confidential extention, fail if doesn't exist or not enabled
        let mut des_ext = read_account_confidential_ext(e, des.clone());
        if !des_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialAccountNotEnabled);
        }

        // check if `des`'s `pending_balance_counter` has reached MAX_PENDING_BALANCE_COUNTER, if so fail.
        if des_ext.pending_counter >= MAX_PENDING_BALANCE_COUNTER {
            return Err(ConfidentialTokenError::PendingBalanceCounterAtMaximum);
        }

        // Verifies the transfer proof.
        verify_transfer_proof(
            &src_ext.encryption_key,    // sender_ek
            &des_ext.encryption_key,    // recipient_ek
            &src_ext.available_balance, // current_balance
            &src_new_balance,           // new_balance
            &amt_src,                   // sender_amount
            &amt_des,                   // recipient_amount
            &token_ext.auditor,         // auditor_ek
            &amt_auditor,               // auditor_amount
            &proof,                     // proof
        )
        .map_err(|_| ConfidentialTokenError::TransferProofVerificationFailed)?;

        // Set `src` account's `available_balance` to `src_new_balance`.
        src_ext.available_balance = src_new_balance;
        write_account_confidential_ext(e, src.clone(), &src_ext);

        // Adds `amt_des` to `des` account's `pending_balance`.
        des_ext.pending_balance =
            ConfidentialAmountBytes::add(e, &des_ext.pending_balance, &amt_des);

        // Increase `des`'s `pending_balance_counter`
        des_ext.pending_counter += 1;
        write_account_confidential_ext(e, des.clone(), &des_ext);

        // Emits an event with all relevant input under topic "ConfidentialToken_confidential_transfer"
        let topics = (Symbol::new(e, "ConfidentialToken_transfer"), src, des);
        e.events().publish(topics, (amt_src, amt_des, amt_auditor));

        Ok(())
    }

    // Roll over an account's pending balance into its available balance.
    pub fn rollover_pending_balance(
        e: &Env,
        acc: Address,
        new_balance: ConfidentialBalanceBytes,
        proof: NewBalanceProofBytes,
    ) -> Result<(), ConfidentialTokenError> {
        acc.require_auth();

        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialTokenNotEnabled);
        }

        // load the `acc`'s confidential extention, fail if doesn't exist or not enabled
        let mut acc_ext = read_account_confidential_ext(e, acc.clone());
        if !acc_ext.enabled_flag {
            return Err(ConfidentialTokenError::ConfidentialAccountNotEnabled);
        }

        let balance_pre_normalization = ConfidentialBalanceBytes::add_amount(
            e,
            &acc_ext.available_balance,
            &acc_ext.pending_balance,
        );

        // verifies the NewBalanceProofBytes using verify_normalization_proof
        // The proof should demonstrate that new_balance = current_available_balance + pending_balance
        verify_normalization_proof(
            &acc_ext.encryption_key,
            &balance_pre_normalization,
            &new_balance,
            &proof,
        )
        .map_err(|_| ConfidentialTokenError::NormalizationProofVerificationFailed)?;

        // Sets the `available_balance` to the `new_available_balance`.
        acc_ext.available_balance = new_balance.clone();

        // Sets the `pending_balance` to zero (encrypt `amt=0` with randomness `r=0`).
        acc_ext.pending_balance = ConfidentialAmountBytes::zero(e);

        // Resets the pending balance counter to 0.
        acc_ext.pending_counter = 0;

        write_account_confidential_ext(e, acc.clone(), &acc_ext);

        // Emits an event
        let topics = (Symbol::new(e, "ConfidentialToken_rollover"), acc);
        e.events().publish(topics, new_balance);

        Ok(())
    }
}

#[contractimpl]
impl ConfidentialToken {
    pub fn __constructor(e: Env, admin: Address, decimal: u32, name: String, symbol: String) {
        if decimal > 18 {
            panic!("Decimal must not be greater than 18");
        }
        write_administrator(&e, &admin);
        write_metadata(
            &e,
            TokenMetadata {
                decimal,
                name,
                symbol,
            },
        )
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        check_nonnegative_amount(amount);
        let admin = read_administrator(&e);
        admin.require_auth();

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        receive_balance(&e, to.clone(), amount);
        TokenUtils::new(&e).events().mint(admin, to, amount);
    }

    pub fn set_admin(e: Env, new_admin: Address) {
        let admin = read_administrator(&e);
        admin.require_auth();

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        write_administrator(&e, &new_admin);
        TokenUtils::new(&e).events().set_admin(admin, new_admin);
    }

    pub fn get_allowance(e: Env, from: Address, spender: Address) -> Option<AllowanceValue> {
        let key = DataKey::Allowance(AllowanceDataKey { from, spender });
        let allowance = e.storage().temporary().get::<_, AllowanceValue>(&key);
        allowance
    }
}

#[contractimpl]
impl token::Interface for ConfidentialToken {
    fn allowance(e: Env, from: Address, spender: Address) -> i128 {
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        read_allowance(&e, from, spender).amount
    }

    fn approve(e: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();

        check_nonnegative_amount(amount);

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        write_allowance(&e, from.clone(), spender.clone(), amount, expiration_ledger);
        TokenUtils::new(&e)
            .events()
            .approve(from, spender, amount, expiration_ledger);
    }

    fn balance(e: Env, id: Address) -> i128 {
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        read_balance(&e, id)
    }

    fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        check_nonnegative_amount(amount);

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        spend_balance(&e, from.clone(), amount);
        receive_balance(&e, to.clone(), amount);
        TokenUtils::new(&e).events().transfer(from, to, amount);
    }

    fn transfer_from(e: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();

        check_nonnegative_amount(amount);

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        spend_allowance(&e, from.clone(), spender, amount);
        spend_balance(&e, from.clone(), amount);
        receive_balance(&e, to.clone(), amount);
        TokenUtils::new(&e).events().transfer(from, to, amount)
    }

    fn burn(e: Env, from: Address, amount: i128) {
        from.require_auth();

        check_nonnegative_amount(amount);

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        spend_balance(&e, from.clone(), amount);
        TokenUtils::new(&e).events().burn(from, amount);
    }

    fn burn_from(e: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();

        check_nonnegative_amount(amount);

        e.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        spend_allowance(&e, from.clone(), spender, amount);
        spend_balance(&e, from.clone(), amount);
        TokenUtils::new(&e).events().burn(from, amount)
    }

    fn decimals(e: Env) -> u32 {
        read_decimal(&e)
    }

    fn name(e: Env) -> String {
        read_name(&e)
    }

    fn symbol(e: Env) -> String {
        read_symbol(&e)
    }
}
