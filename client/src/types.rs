use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountKeys {
    pub alice: KeyPair,
    pub bob: KeyPair,
    pub auditor: KeyPair,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub proof_hex: String,
    pub new_balance_hex: String,
    pub amount_alice_hex: Option<String>,
    pub amount_bob_hex: Option<String>,
    pub amount_auditor_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub transfer_amount: u64,
    pub alice_new_balance: u64,
    pub proof: ProofData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalData {
    pub withdrawal_amount: u64,
    pub new_balance: u64,
    pub proof: ProofData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloverData {
    pub balance_amount: u64,
    pub proof: ProofData,
}