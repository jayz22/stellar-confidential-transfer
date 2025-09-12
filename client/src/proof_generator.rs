use crate::{CliConfidentialAmountBytes, CliConfidentialBalanceBytes, CliNewBalanceProofBytes, CliTransferProofBytes};
use soroban_sdk::{Env, xdr::FromXdr};
use stellar_confidential_crypto::{
    confidential_balance::ConfidentialBalance,
    Scalar, RistrettoPoint, proof::testutils::{prove_normalization, prove_withdrawal, prove_transfer}
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
    ) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        // Use existing testutils function
        let (proof, new_balance_bytes) = prove_normalization(
            &self.env,
            secret_key,
            public_key,
            balance_amount,
            balance_pre_normalization,
        );

        // Convert to CLI-compatible types
        let cli_proof = CliNewBalanceProofBytes::from_crypto_type(&self.env, &proof);
        let cli_balance = CliConfidentialBalanceBytes::from_crypto_type(&self.env, &new_balance_bytes);
        
        Ok((cli_proof, cli_balance))

    }

    /// Generate withdrawal proof using existing testutils
    pub fn generate_withdrawal_proof(
        &self,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        withdrawal_amount: u64,
        new_balance_amount: u128,
        current_balance: &ConfidentialBalance,
    ) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        // Use existing testutils function
        let (withdrawal_proof, new_balance_bytes) = prove_withdrawal(
            &self.env,
            secret_key,
            public_key,
            withdrawal_amount,
            new_balance_amount,
            current_balance,
        );

        // Convert to CLI-compatible types
        let cli_proof = CliNewBalanceProofBytes::from_crypto_type(&self.env, &withdrawal_proof);
        let cli_balance = CliConfidentialBalanceBytes::from_crypto_type(&self.env, &new_balance_bytes);
        
        Ok((cli_proof, cli_balance))
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
    ) -> Result<(CliTransferProofBytes, CliConfidentialBalanceBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes), String> {
        // Use existing testutils function
        let (transfer_proof, src_new_balance, src_amount, dest_amount, auditor_amount) =
            prove_transfer(
                &self.env,
                src_secret_key,
                src_public_key,
                dest_public_key,
                transfer_amount,
                new_balance_amount,
                current_balance,
                auditor_public_key,
            );

        // Convert to CLI-compatible types
        let cli_transfer_proof = CliTransferProofBytes::from_crypto_type(&self.env, &transfer_proof);
        let cli_src_new_balance = CliConfidentialBalanceBytes::from_crypto_type(&self.env, &src_new_balance);
        let cli_src_amount = CliConfidentialAmountBytes::from_crypto_type(&self.env, &src_amount);
        let cli_dest_amount = CliConfidentialAmountBytes::from_crypto_type(&self.env, &dest_amount);
        let cli_auditor_amount = CliConfidentialAmountBytes::from_crypto_type(&self.env, &auditor_amount);
        
        Ok((cli_transfer_proof, cli_src_new_balance, cli_src_amount, cli_dest_amount, cli_auditor_amount))
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