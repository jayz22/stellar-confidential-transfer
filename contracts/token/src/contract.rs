#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, events, symbol_short, token::TokenInterface, Address,
    Bytes, BytesN, Env, String, Symbol, Vec,
};

use crate::utils::*;
use stellar_confidential_crypto::{
    proof::{
        verify_withdrawal_proof, CompressedPubkeyBytes, ConfidentialAmount, ConfidentialBalance,
        NormalizationProofBytes, TransferProofBytes, WithdrawalProofBytes,
    },
    ConfidentialAmount,
};

const MAX_PENDING_BALANCE_COUNTER: u32 = 0x10000;

#[contract]
pub struct ConfidentialToken;

#[contracttype]
pub struct TokenConfidentialExt {
    pub enabled_flag: bool, // enable/disable this token's confidential functionalities, controlled by the admin
    pub auditors: Vec<CompressedPubkeyBytes>,
    pub total_confidential_supply: u128,
}

#[contracttype]
pub struct AccountConfidentialExt {
    pub enabled_flag: bool, // enable/disable this account's confidential functionalities, controlled by the admin
    pub encryption_key: CompressedPubkeyBytes,
    pub available_balance: ConfidentialBalance,
    pub pending_balance: ConfidentialAmount,
    pub pending_counter: u32,
}

// The confidential transfer functionalities
#[contractimpl]
impl ConfidentialToken {
    // Register this token for the confidential extention
    pub fn register_confidential_token(e: &Env, auditor_keys: Vec<CompressedPubkeyBytes>) {
        read_administrator(e).require_auth();
        init_token_confidential_ext(e, auditor_keys);
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
        let mut ext = read_account_confidential_ext(e, acc);
        ext.enabled_flag = flag;
        write_account_confidential_ext(e, acc, &ext);
    }

    // Deposit `amt` from `acc`'s transparent balance into its confidential pending balance (`amt` encrypted with zero randomness)
    pub fn deposit(e: &Env, acc: Address, amt: u64) {
        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let mut token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            panic!("token confidential functionality is not enabled");
        }

        // load the `acc`'s confidential extention, fail if doesn't exist or not enabled
        let mut acc_ext = read_account_confidential_ext(e, acc.clone());
        if !acc_ext.enabled_flag {
            panic!("account confidential functionality is not enabled");
        }

        // check if `acc`'s `pending_balance_counter` has reached MAX_PENDING_BALANCE_COUNTER, if so fail.
        if acc_ext.pending_counter >= MAX_PENDING_BALANCE_COUNTER {
            panic!("pending balance counter has reached maximum value");
        }

        // Subtracts `amt` from `acc`'s regular (transparent) `balance`, fail if `balance` is less than `amt`.
        spend_balance(e, acc.clone(), amt as i128);

        // TODO: Encrypt the `amt` using zero randomness (`r = 0`) into `encrypted_amt`, add the `encrypted_amt` to the `pending_balance`.
        acc_ext.pending_balance = ConfidentialAmount::new_amount_with_no_randomness(amt);

        // Increment `acc`'s `pending_balance_counter`
        acc_ext.pending_counter += 1;
        write_account_confidential_ext(e, acc.clone(), &acc_ext);

        // Update token's total confidential supply
        token_ext
            .total_confidential_supply
            .checked_add(amt as u128)
            .unwrap();
        write_token_confidential_ext(e, &token_ext);

        //  Emits an event
        let topics = (Symbol::new(e, "ConfidentialToken::deposit"), acc);
        e.events().publish(topics, amt);
    }

    // Withdraw an amount from acc's confidential available balance to its transparent balance
    pub fn withdraw(
        e: &Env,
        acc: Address,
        amt: u64,
        new_balance: ConfidentialBalance,
        proof: WithdrawalProofBytes,
    ) {
        // check this token's confidential extention, fail if extention doesn't exist or it is not enabled
        let mut token_ext = read_token_confidential_ext(e);
        if !token_ext.enabled_flag {
            panic!("token confidential functionality is not enabled");
        }

        // load the `acc`'s confidential extention, fail if doesn't exist or not enabled
        let mut acc_ext = read_account_confidential_ext(e, acc.clone());
        if !acc_ext.enabled_flag {
            panic!("account confidential functionality is not enabled");
        }

        // Verifies the WithdrawalProof against current balance, new balance, and amount
        verify_withdrawal_proof(
            &acc_ext.encryption_key,
            amt,
            &acc_ext.available_balance,
            &new_balance,
            &proof,
        )
        .map_err(|_| panic!("withdrawal proof verification failed"));

        // Sets `acc`'s `available_balance` to `new_balance`
        acc_ext.available_balance = new_balance;
        write_account_confidential_ext(e, acc.clone(), &acc_ext);

        // Update token's total confidential supply (decrease)
        token_ext.total_confidential_supply = token_ext
            .total_confidential_supply
            .checked_sub(amt as u128)
            .unwrap_or_else(|| panic!("insufficient total confidential supply"));
        write_token_confidential_ext(e, &token_ext);

        // Emits an event
        let topics = (Symbol::new(e, "ConfidentialToken::withdraw"), acc);
        e.events().publish(topics, amt);
    }

    // Transfers an amount confidentially between two accounts.
    //     - Loads confidential extensions from `src` and `des` addresses, fail if either extension does not exist.
    //     - If `des`'s `pending_balance_counter` is at max (`2^16`), fail.
    //     - Verifies the transfer proof.
    //         - equality proof: `amt_src`, `amt_des`, `amt_auditors` all encrypt the same amount
    //         - ...
    //     - Set `src` account's `available_balance` to `src_new_balance`.
    //     - (homomorphically) Adds `des_amt` to `des` account's `pending_balance`.
    //     - Increment `des`'s `pending_balance_counter`
    //     - Emits an event TBD
    pub fn confidential_transfer(
        e: &Env,
        src: Address,
        des: Address,
        amt_src: ConfidentialAmount,
        amt_des: ConfidentialAmount,
        auditor_keys: Vec<CompressedPubkeyBytes>,
        amt_auditors: Vec<ConfidentialAmount>,
        src_new_balance: ConfidentialBalance,
        proof: TransferProofBytes,
    ) {
        todo!()
    }

    // Roll over an account's pending balance into its available balance.
    //     - Loads the confidential extension from `src`, fail if not exist.
    //     - Loads the `pending_balance` and `available_balance`.
    //     - Verifies the `proof`, against `new_available_balance`.
    //     - Sets the `available_balance` to the `new_available_balance`.
    //     - Sets the `pending_balance` to zero (encrypt `amt=0` with randomness `r=0`).
    //     - Resets the pending balance counter to 0.
    //     - Emits an event TBD
    pub fn rollover_pending_balance(
        e: &Env,
        src: Address,
        src_new_balance: ConfidentialBalance,
        proof: NormalizationProofBytes,
    ) {
        todo!()
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

    #[cfg(test)]
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
