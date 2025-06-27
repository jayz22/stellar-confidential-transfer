#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token::TokenInterface, Address, Bytes, BytesN, Env, String, Vec
};

#[contracttype]
pub struct ElGamalPublicKey(BytesN<32>);

// The quantities (amount and balance) are initially divided into fixed-length (16-bit) chunks
// and encrypted individually. Additional of quantities occur on each chunk individually, therefore
// the chunk can grow to be larger than 16-bits, but not exceeding 32-bits if the max addition
// counter is 2^16.
#[contracttype]
pub struct EncryptedChunk(BytesN<32>);
#[contracttype]
pub struct DecryptionHandle(BytesN<32>);

#[contracttype]
pub struct EncryptedQuantity {
    pub amount: Vec<EncryptedChunk>,
    pub handle: DecryptionHandle,
}

#[contracttype]
pub struct ConfidentialTokenMetaData {
    // list of auditors, must be specified when the token is instantiated.
    // all token transfer amounts will be additionally encrypted by each auditor key.
    pub auditors: Vec<ElGamalPublicKey>,
}

#[contracttype]
pub struct NormalizationProof(Bytes);

#[contracttype]
pub struct WithdrawProof(Bytes);
#[contracttype]
pub struct TransferProof(Bytes);

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
    pub encryption_key: ElGamalPublicKey,
    pub encrypted_available_balance: EncryptedQuantity,
    pub encrypted_pending_balance: EncryptedQuantity,
    pub pending_increment_counter: u32,
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
    // Deposit a token amount into the confidential balance of an account
    //     - Loads the confidential extension from `src` and `des`, fail if either does not exist.  
    //     - If `des`'s `pending_balance_counter` is at max (`10^16`), fail.
    //     - Subtracts `amt` from `src`'s regular (transparent) `balance`, fail if `balance` is less than `amt`.
    //     - Loads the `pending_balance` from `des`. 
    //     - Encrypt the `amt` using zero randomness (`r = 0`) into `encrypted_amt`, add the `encrypted_amt` to the `pending_balance`. 
    //     - Increment `des`'s `pending_balance_counter`
    //     - Emits an event TBD
    pub fn deposit_to_confidential(src: Address, des: Address, amt: u64) {
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
    pub fn rollover_pending_balance(src: Address, new_available_balance: EncryptedQuantity, proof: NormalizationProof) {
        todo!()
    }

    // Withdraw an amount from srcount's confidential balance to its transparent balance
    //     - Loads `src`'s confidential extension, fail if not exist.
    //     - Verifies the WithdrawProof. 
    //         - ...
    //     - Encrypt the `amt` with zero randomness (`r=0`) to get `encrypted_amt`.
    //     - Adds `amt` to `src`'s (transparent) balance.
    //     - Sets `src`'s `available_balance` to `src_new_balance`. 
    //     - Emits an event TBD
    pub fn withdraw_from_confidential(src: Address, amt: u64, src_new_balance: EncryptedQuantity, proof: WithdrawProof) {
        todo!()
    }

    // Transfers an amount confidentially between two accounts.
    //     - Loads confidential extensions from `src` and `des` addresses, fail if either extension does not exist.
    //     - If `des`'s `pending_balance_counter` is at max (`10^16`), fail.
    //     - Verifies the transfer proof.
    //         - equality proof: `amt_src`, `amt_des`, `amt_auditors` all encrypt the same amount
    //         - ...
    //     - Set `src` account's `available_balance` to `src_new_balance`.
    //     - (homomorphically) Adds `des_amt` to `des` account's `pending_balance`.
    //     - Increment `des`'s `pending_balance_counter`
    //     - Emits an event TBD
    pub fn transfer_confidential(src: Address, des: Address, amt_src: EncryptedQuantity, amt_des: EncryptedQuantity, auditor_keys: Vec<ElGamalPublicKey>, amt_auditors: Vec<EncryptedQuantity>, src_new_balance: EncryptedQuantity, proof: TransferProof) {
        todo!()
    }
}


mod test;
