use crate::types::{ProofData, TransactionData, WithdrawalData, RolloverData};
use soroban_sdk::{Env, xdr::{ToXdr, FromXdr}};
use stellar_confidential_crypto::{
    confidential_balance::ConfidentialBalance,
    proof,
    Scalar, RistrettoPoint,
};

pub struct ProofGenerator {
    pub env: Env,
}

impl ProofGenerator {
    pub fn new() -> Self {
        Self {
            env: Env::default(),
        }
    }

    /// Generate rollover proof using existing testutils
    pub fn generate_rollover_proof(
        &self,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        balance_amount: u128,
        balance_pre_normalization: &ConfidentialBalance,
    ) -> Result<RolloverData, String> {
        // Use existing testutils function
        let (proof, new_balance_bytes) = proof::testutils::prove_normalization(
            &self.env,
            secret_key,
            public_key,
            balance_amount,
            balance_pre_normalization,
        );

        let proof_bytes = proof.to_xdr(&self.env);
        let new_balance_xdr = new_balance_bytes.to_xdr(&self.env);
        let proof_hex = hex::encode(proof_bytes.iter().collect::<Vec<u8>>());
        let new_balance_hex = hex::encode(new_balance_xdr.iter().collect::<Vec<u8>>());

        Ok(RolloverData {
            balance_amount: balance_amount as u64,
            proof: ProofData {
                proof_hex,
                new_balance_hex,
                amount_alice_hex: None,
                amount_bob_hex: None,
                amount_auditor_hex: None,
            },
        })
    }

    /// Generate transfer proof using existing testutils
    pub fn generate_transfer_proof(
        &self,
        src_secret_key: &Scalar,
        src_public_key: &RistrettoPoint,
        dest_public_key: &RistrettoPoint,
        transfer_amount: u64,
        new_balance_amount: u128,
        current_balance: &ConfidentialBalance,
        auditor_public_key: &RistrettoPoint,
    ) -> Result<TransactionData, String> {
        // Use existing testutils function
        let (transfer_proof, src_new_balance, src_amount, dest_amount, auditor_amount) =
            proof::testutils::prove_transfer(
                &self.env,
                src_secret_key,
                src_public_key,
                dest_public_key,
                transfer_amount,
                new_balance_amount,
                current_balance,
                auditor_public_key,
            );

        let proof_hex = hex::encode(transfer_proof.to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let new_balance_hex = hex::encode(src_new_balance.to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let amount_alice_hex = hex::encode(src_amount.to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let amount_bob_hex = hex::encode(dest_amount.to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let amount_auditor_hex = hex::encode(auditor_amount.to_xdr(&self.env).iter().collect::<Vec<u8>>());

        Ok(TransactionData {
            transfer_amount,
            alice_new_balance: new_balance_amount as u64,
            proof: ProofData {
                proof_hex,
                new_balance_hex,
                amount_alice_hex: Some(amount_alice_hex),
                amount_bob_hex: Some(amount_bob_hex),
                amount_auditor_hex: Some(amount_auditor_hex),
            },
        })
    }

    /// Generate withdrawal proof using existing testutils
    pub fn generate_withdrawal_proof(
        &self,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        withdrawal_amount: u64,
        new_balance_amount: u128,
        current_balance: &ConfidentialBalance,
    ) -> Result<WithdrawalData, String> {
        // Use existing testutils function
        let (withdrawal_proof, new_balance_bytes) = proof::testutils::prove_withdrawal(
            &self.env,
            secret_key,
            public_key,
            withdrawal_amount,
            new_balance_amount,
            current_balance,
        );

        let proof_hex = hex::encode(withdrawal_proof.to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let new_balance_hex = hex::encode(new_balance_bytes.to_xdr(&self.env).iter().collect::<Vec<u8>>());

        Ok(WithdrawalData {
            withdrawal_amount,
            new_balance: new_balance_amount as u64,
            proof: ProofData {
                proof_hex,
                new_balance_hex,
                amount_alice_hex: None,
                amount_bob_hex: None,
                amount_auditor_hex: None,
            },
        })
    }

    /// Create a balance with no randomness (for rollover base)
    pub fn create_balance_with_no_randomness(&self, amount: u128) -> ConfidentialBalance {
        ConfidentialBalance::new_balance_with_no_randomness(amount)
    }

    /// Create balance from environment bytes (for parsing stored balances)
    pub fn balance_from_hex(&self, hex_str: &str) -> Result<ConfidentialBalance, String> {
        let _bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
        // This would need a way to convert bytes back to ConfidentialBalance
        // For now, we'll return an error as this requires access to the environment
        Err("Cannot deserialize balance from hex without environment context".to_string())
    }

    /// Decrypt a confidential balance
    pub fn decrypt_available_balance(&self, secret_key: &Scalar, ciphertext_hex: &str) -> Result<u64, String> {
        let bytes = hex::decode(ciphertext_hex).map_err(|e| format!("Invalid hex: {}", e))?;
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        
        let balance_bytes = stellar_confidential_crypto::ConfidentialBalanceBytes::from_xdr(&self.env, &soroban_bytes)
            .map_err(|_| "Failed to parse as ConfidentialBalance".to_string())?;
        let balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&balance_bytes);
        let value = balance.decrypt(secret_key);
        Ok(value as u64)
    }
    
    /// Decrypt a transfer amount
    pub fn decrypt_transfer_amount(&self, secret_key: &Scalar, ciphertext_hex: &str) -> Result<u64, String> {
        let bytes = hex::decode(ciphertext_hex).map_err(|e| format!("Invalid hex: {}", e))?;
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        
        let amount_bytes = stellar_confidential_crypto::ConfidentialAmountBytes::from_xdr(&self.env, &soroban_bytes)
            .map_err(|_| "Failed to parse as ConfidentialAmount".to_string())?;
        let amount = stellar_confidential_crypto::ConfidentialAmount::from_env_bytes(&amount_bytes);
        let value = amount.decrypt(secret_key);
        Ok(value as u64)
    }
}