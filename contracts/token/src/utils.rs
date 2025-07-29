use soroban_sdk::{contracttype, Address, BytesN, Env};

use crate::contract::{AccountConfidentialExt, TokenConfidentialExt};
use stellar_confidential_crypto::proof::{
    CompressedPubkeyBytes, CompressedRistretto, ConfidentialAmount, ConfidentialBalance, EncryptedChunk,
};

pub(crate) const DAY_IN_LEDGERS: u32 = 17280;
pub(crate) const INSTANCE_BUMP_AMOUNT: u32 = 7 * DAY_IN_LEDGERS;
pub(crate) const INSTANCE_LIFETIME_THRESHOLD: u32 = INSTANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;

pub(crate) const BALANCE_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
pub(crate) const BALANCE_LIFETIME_THRESHOLD: u32 = BALANCE_BUMP_AMOUNT - DAY_IN_LEDGERS;

// storage types

#[derive(Clone)]
#[contracttype]
pub struct AllowanceDataKey {
    pub from: Address,
    pub spender: Address,
}

#[contracttype]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(Address),
    Admin,
    TokenConfidentialExt,
    AccountConfidentialExt(Address),
}

// admin

pub fn read_administrator(e: &Env) -> Address {
    let key = DataKey::Admin;
    e.storage().instance().get(&key).unwrap()
}

pub fn write_administrator(e: &Env, id: &Address) {
    let key = DataKey::Admin;
    e.storage().instance().set(&key, id);
}

// allowance

pub fn read_allowance(e: &Env, from: Address, spender: Address) -> AllowanceValue {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    if let Some(allowance) = e.storage().temporary().get::<_, AllowanceValue>(&key) {
        if allowance.expiration_ledger < e.ledger().sequence() {
            AllowanceValue {
                amount: 0,
                expiration_ledger: allowance.expiration_ledger,
            }
        } else {
            allowance
        }
    } else {
        AllowanceValue {
            amount: 0,
            expiration_ledger: 0,
        }
    }
}

pub fn write_allowance(
    e: &Env,
    from: Address,
    spender: Address,
    amount: i128,
    expiration_ledger: u32,
) {
    let allowance = AllowanceValue {
        amount,
        expiration_ledger,
    };

    if amount > 0 && expiration_ledger < e.ledger().sequence() {
        panic!("expiration_ledger is less than ledger seq when amount > 0")
    }

    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    e.storage().temporary().set(&key.clone(), &allowance);

    if amount > 0 {
        let live_for = expiration_ledger
            .checked_sub(e.ledger().sequence())
            .unwrap();

        e.storage().temporary().extend_ttl(&key, live_for, live_for)
    }
}

pub fn spend_allowance(e: &Env, from: Address, spender: Address, amount: i128) {
    let allowance = read_allowance(e, from.clone(), spender.clone());
    if allowance.amount < amount {
        panic!("insufficient allowance");
    }
    if amount > 0 {
        write_allowance(
            e,
            from,
            spender,
            allowance.amount - amount,
            allowance.expiration_ledger,
        );
    }
}

// balance

pub fn read_balance(e: &Env, addr: Address) -> i128 {
    let key = DataKey::Balance(addr);
    if let Some(balance) = e.storage().persistent().get::<DataKey, i128>(&key) {
        e.storage()
            .persistent()
            .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
        balance
    } else {
        0
    }
}

fn write_balance(e: &Env, addr: Address, amount: i128) {
    let key = DataKey::Balance(addr);
    e.storage().persistent().set(&key, &amount);
    e.storage()
        .persistent()
        .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
}

pub fn receive_balance(e: &Env, addr: Address, amount: i128) {
    let balance = read_balance(e, addr.clone());
    write_balance(e, addr, balance + amount);
}

pub fn spend_balance(e: &Env, addr: Address, amount: i128) {
    let balance = read_balance(e, addr.clone());
    if balance < amount {
        panic!("insufficient balance");
    }
    write_balance(e, addr, balance - amount);
}

// meta data

pub fn read_decimal(e: &Env) -> u32 {
    let util = TokenUtils::new(e);
    util.metadata().get_metadata().decimal
}

pub fn read_name(e: &Env) -> String {
    let util = TokenUtils::new(e);
    util.metadata().get_metadata().name
}

pub fn read_symbol(e: &Env) -> String {
    let util = TokenUtils::new(e);
    util.metadata().get_metadata().symbol
}

pub fn write_metadata(e: &Env, metadata: TokenMetadata) {
    let util = TokenUtils::new(e);
    util.metadata().set_metadata(&metadata);
}

// misc

pub fn check_nonnegative_amount(amount: i128) {
    if amount < 0 {
        panic!("negative amount is not allowed: {}", amount)
    }
}

// confidential ext
pub fn init_token_confidential_ext(e: &Env, auditor_keys: Vec<CompressedPubkeyBytes>) {
    let key = DataKey::TokenConfidentialExt;
    if e.storage().instance().has(&key) {
        panic!("confidential token extention already initialized")
    }
    let ext = TokenConfidentialExt {
        enabled_flag: true,
        auditors: auditor_keys,
        total_confidential_supply: 0,
    };
    e.storage().instance().set(&key, &ext);
}

pub fn init_acc_confidential_ext(e: &Env, acc: Address, ek: CompressedPubkeyBytes) {
    let key = DataKey::AccountConfidentialExt(acc);
    if e.storage().persistent().has(&key) {
        panic!("account confidential extension already initialized")
    }
    let ext = AccountConfidentialExt {
        enabled_flag: true,
        encryption_key: ek,
        available_balance: ConfidentialBalance::zero(), // Initialize with zero balance
        pending_balance: ConfidentialAmount::zero(),    // Initialize with zero pending balance
        pending_counter: 0,
    };
    e.storage().persistent().set(&key, &ext);
    e.storage()
        .persistent()
        .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
}

// confidential ext helper functions
pub fn read_token_confidential_ext(e: &Env) -> TokenConfidentialExt {
    let key = DataKey::TokenConfidentialExt;
    e.storage().instance().get(&key).unwrap()
}

pub fn write_token_confidential_ext(e: &Env, ext: &TokenConfidentialExt) {
    let key = DataKey::TokenConfidentialExt;
    e.storage().instance().set(&key, ext);
}

pub fn read_account_confidential_ext(e: &Env, acc: Address) -> AccountConfidentialExt {
    let key = DataKey::AccountConfidentialExt(acc);
    if let Some(ext) = e
        .storage()
        .persistent()
        .get::<DataKey, AccountConfidentialExt>(&key)
    {
        e.storage()
            .persistent()
            .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
        ext
    } else {
        panic!("account confidential extension not found")
    }
}

pub fn write_account_confidential_ext(e: &Env, acc: Address, ext: &AccountConfidentialExt) {
    let key = DataKey::AccountConfidentialExt(acc);
    e.storage().persistent().set(&key, ext);
    e.storage()
        .persistent()
        .extend_ttl(&key, BALANCE_LIFETIME_THRESHOLD, BALANCE_BUMP_AMOUNT);
}
