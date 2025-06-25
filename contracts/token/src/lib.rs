#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token::TokenInterface, Address, BytesN, Env, String,
    Vec,
};

#[contracttype]
pub struct ElGamalEncryptionKey(BytesN<32>);

// The quantities (amount and balance) are initially divided into fixed-length (16-bit) chunks
// and encrypted individually. Additional of quantities occur on each chunk individually, therefore
// the chunk can grow to be larger than 16-bits, but not exceeding 32-bits if the max addition
// counter is 2^16.
#[contracttype]
pub struct EncryptedChunk(BytesN<32>);
#[contracttype]
pub struct DecryptionHandle(BytesN<32>);

#[contracttype]
pub struct EncryptedAmount {
    pub amount: Vec<EncryptedChunk>,
    pub handle: DecryptionHandle,
}

#[contracttype]
pub struct ConfidentialTokenMetaData {
    // list of auditors, must be specified when the token is instantiated.
    // all token transfer amounts will be additionally encrypted by each auditor key.
    pub auditors: Vec<ElGamalEncryptionKey>,
}

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

#[contracttype]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(Address),
    Admin,
    ConfidentialAccountExt(Address), // extention for confidential token, identified by the normal Stellar address
}

#[contracttype]
pub struct ConfidentialAccountExt {
    pub encryption_key: ElGamalEncryptionKey,
    pub encrypted_available_balance: EncryptedAmount,
    pub encrypted_pending_balance: EncryptedAmount,
    pub pending_increment_counter: u32,
    pub enabled: bool
}

#[contract]
pub struct ConfidentialToken;

// Confidential token implements the standard token interface, with all relevant
// logic applied to the transparent balance
impl TokenInterface for ConfidentialToken {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        todo!()
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        todo!()
    }

    fn balance(env: Env, id: Address) -> i128 {
        todo!()
    }

    fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        todo!()
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        todo!()
    }

    fn burn(env: Env, from: Address, amount: i128) {
        todo!()
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        todo!()
    }

    fn decimals(env: Env) -> u32 {
        todo!()
    }

    fn name(env: Env) -> String {
        todo!()
    }

    fn symbol(env: Env) -> String {
        todo!()
    }
}

// The confidential transfer functionalities
#[contractimpl]
impl ConfidentialToken {
    // deposit `amt` from `balance` to `encrypted_pending_balance`
    // `amt` must be <= the existing `balance`
    // Proofs: none required
    // Errors: 1. if `acc` does not have confidential token extention 2. if amt is greater than the balance 
    // events: todo
    pub fn deposit_to_confidential(acc: Address, amt: i64) {
        // 1. load the ConfidentialAccountExt(acc), fail if doesn't exist
        // 2. check and sub acc's balance by amt
        // 3. encrypt amt with acc's encryption key, store it in the extention
        // 4. TODO: emit event
        todo!()
    }

    // move `encrypted_pending_balance` into `encrypted_available_balance`.
    // after the call `encrypted_pending_balance` is zero.
    // Proofs: none required
    // Errors: if `acc` does not have confidential token extention 
    // events: todo
    pub fn apply_pending_balance(acc: Address) {
        // 0. try load the ConfidentialAccountExt or fail
        // normalize the pending balance such that all chunks encode non-overflowing i16 again
        // apply the pending balance to the available balance
        // set the pending balance to 0
        // reset the counter to 0
        // TODO: events
        todo!()
    }

    // confidentially transfer `encrypted_amt` from `from`'s available balance to `to`'s pending balance. 
    // `from`'s encrypted balance must be >=  to the amt. 
    // Proofs required: 1. equality proof. encrypted amt is the same amt under different encryption keys 2. range proof. `from`'s `encrypted_available_balance` is >=0 after the transfer. 3. equality proof (see notes below) 4. ciphertext validity proof
    // events: todo
    pub fn transfer_confidential(from: Address, to: Address, enc_amt: Vec<EncryptedChunk>) {
        todo!()
    }

    // withdraws `amt` from `encrypted_available_balance` into the transparent balance
    // proofs required: range proof on new balance amount 
    // TODO: do we require normalization proof??
    // probably just a equality proof is enough
    // events: todo
    pub fn withdraw_from_confidential(from: Address, amt: i64, proof: ??) {
        // 0. try load the ConfidentialAccountExt or fail
        // 
        todo!()
    }


    // secondary features:
    pub fn rollover_pending_balance_and_freeze() {
        // normalize pending balance
        // roll over pending balance
        // freeze the account
        // replace the key, unfreeze the account 
        todo!()
    }
    pub fn rotate_encryption_key_and_unfreeze () 
    {
        // assert the account is frozen status
    }
    fn normalize();
    // allow/disallow list
    // enable/disable token
    // set auditor
    // confidential_asset_balance Returns the circulating supply of the confidential asset.
}


mod test;
