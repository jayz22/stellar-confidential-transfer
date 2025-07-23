#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token::TokenInterface, Address, Bytes, BytesN, Env,
    String, Vec,
};

use crate::utils::*;
use stellar_confidential_crypto::proof::{
    CompressedPubkey, ConfidentialAmount, ConfidentialBalance, NormalizationProof, TransferProof,
    WithdrawalProof,
};

#[contract]
pub struct ConfidentialToken;

#[contracttype]
pub struct TokenConfidentialExt {
    pub enabled_flag: bool, // enable/disable this token's confidential functionalities, controlled by the admin
    pub auditors: Vec<CompressedPubkey>,
    pub total_confidential_supply: u128,
}

#[contracttype]
pub struct AccountConfidentialExt {
    pub enabled_flag: bool, // enable/disable this account's confidential functionalities, controlled by the admin
    pub encryption_key: CompressedPubkey,
    pub available_balance: ConfidentialBalance,
    pub pending_balance: ConfidentialAmount,
    pub pending_counter: u32,
}

// The confidential transfer functionalities
#[contractimpl]
impl ConfidentialToken {
    // Register this token for the confidential extention
    pub fn register_confidential_token(e: &Env, auditor_keys: Vec<ElGamalPublicKey>) {
        read_administrator(e).require_auth();
        init_token_confidential_ext(e, auditor_keys);
    }

    pub fn register_account(e: &Env, acc: Address, ek: CompressedPubkey) {
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

    // Deposit a token amount into the confidential balance of an account. src and des can be the same account
    //     - Loads the confidential extension from `src` and `des`, fail if either does not exist.
    //     - If `des`'s `pending_balance_counter` is at max (`2^16`), fail.
    //     - Subtracts `amt` from `src`'s regular (transparent) `balance`, fail if `balance` is less than `amt`.
    //     - Loads the `pending_balance` from `des`.
    //     - Encrypt the `amt` using zero randomness (`r = 0`) into `encrypted_amt`, add the `encrypted_amt` to the `pending_balance`.
    //     - Increment `des`'s `pending_balance_counter`
    //     - Emits an event TBD
    pub fn deposit(e: &Env, acc: Address, amt: u64) {
        todo!()
    }

    // Withdraw an amount from srcount's confidential balance to its transparent balance
    //     - Loads `src`'s confidential extension, fail if not exist.
    //     - Verifies the WithdrawalProof.
    //         - ...
    //     - Encrypt the `amt` with zero randomness (`r=0`) to get `encrypted_amt`.
    //     - Adds `amt` to `src`'s (transparent) balance.
    //     - Sets `src`'s `available_balance` to `src_new_balance`.
    //     - Emits an event TBD
    pub fn withdraw(
        e: &Env,
        acc: Address,
        amt: u64,
        new_balance: ConfidentialBalance,
        proof: WithdrawalProof,
    ) {
        todo!()
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
        auditor_keys: Vec<ElGamalPublicKey>,
        amt_auditors: Vec<ConfidentialAmount>,
        src_new_balance: ConfidentialBalance,
        proof: TransferProof,
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
        proof: NormalizationProof,
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
