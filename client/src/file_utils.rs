use crate::types::*;
use crate::json_converter::*;
use std::fs;
use std::path::Path;
use serde_json;

pub struct FileManager {
    base_path: String,
}

impl FileManager {
    pub fn new(base_path: &str) -> Self {
        Self {
            base_path: base_path.to_string(),
        }
    }

    pub fn ensure_directory(&self) -> Result<(), String> {
        let path = Path::new(&self.base_path);
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        Ok(())
    }

    /// Save a single key pair to JSON file
    pub fn save_key_pair(&self, name: &str, key_pair: &KeyPair) -> Result<(), String> {
        self.ensure_directory()?;
        let json = serde_json::to_string_pretty(key_pair)
            .map_err(|e| format!("Failed to serialize key pair: {}", e))?;
        let path = format!("{}/{}_key.json", self.base_path, name);
        fs::write(&path, json).map_err(|e| format!("Failed to write key file: {}", e))?;
        println!("Key pair saved to {}", path);
        Ok(())
    }

    /// Load a single key pair from JSON file
    pub fn load_key_pair(&self, name: &str) -> Result<KeyPair, String> {
        let path = format!("{}/{}_key.json", self.base_path, name);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read key file {}: {}", path, e))?;
        let key_pair: KeyPair = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse key file: {}", e))?;
        Ok(key_pair)
    }

    /// Save account keys to JSON file (for backward compatibility)
    pub fn save_keys(&self, keys: &AccountKeys) -> Result<(), String> {
        self.ensure_directory()?;
        let json = serde_json::to_string_pretty(keys)
            .map_err(|e| format!("Failed to serialize keys: {}", e))?;
        let path = format!("{}/keys.json", self.base_path);
        fs::write(&path, json).map_err(|e| format!("Failed to write keys file: {}", e))?;
        println!("Keys saved to {}", path);
        Ok(())
    }

    /// Load account keys from JSON file (for backward compatibility)
    pub fn load_keys(&self) -> Result<AccountKeys, String> {
        let path = format!("{}/keys.json", self.base_path);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read keys file {}: {}", path, e))?;
        let keys: AccountKeys = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse keys file: {}", e))?;
        Ok(keys)
    }


    /// Save rollover data
    pub fn save_rollover_data(&self, user: &str, data: &RolloverData) -> Result<(), String> {
        self.ensure_directory()?;
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize rollover data: {}", e))?;
        let path = format!("{}/{}_rollover.json", self.base_path, user);
        fs::write(&path, json).map_err(|e| format!("Failed to write rollover file: {}", e))?;
        println!("Rollover data saved to {}", path);
        Ok(())
    }

    /// Load rollover data
    pub fn load_rollover_data(&self, user: &str) -> Result<RolloverData, String> {
        let path = format!("{}/{}_rollover.json", self.base_path, user);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read rollover file {}: {}", path, e))?;
        let data: RolloverData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse rollover file: {}", e))?;
        Ok(data)
    }

    /// Save transaction data
    pub fn save_transaction_data(&self, data: &TransactionData) -> Result<(), String> {
        self.ensure_directory()?;
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize transaction data: {}", e))?;
        let path = format!("{}/transfer.json", self.base_path);
        fs::write(&path, json).map_err(|e| format!("Failed to write transfer file: {}", e))?;
        println!("Transfer data saved to {}", path);
        Ok(())
    }

    /// Load transaction data
    pub fn load_transaction_data(&self) -> Result<TransactionData, String> {
        let path = format!("{}/transfer.json", self.base_path);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read transfer file {}: {}", path, e))?;
        let data: TransactionData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse transfer file: {}", e))?;
        Ok(data)
    }

    /// Save withdrawal data
    pub fn save_withdrawal_data(&self, user: &str, data: &WithdrawalData) -> Result<(), String> {
        self.ensure_directory()?;
        let json = serde_json::to_string_pretty(data)
            .map_err(|e| format!("Failed to serialize withdrawal data: {}", e))?;
        let path = format!("{}/{}_withdrawal.json", self.base_path, user);
        fs::write(&path, json).map_err(|e| format!("Failed to write withdrawal file: {}", e))?;
        println!("Withdrawal data saved to {}", path);
        Ok(())
    }

    /// Load withdrawal data
    pub fn load_withdrawal_data(&self, user: &str) -> Result<WithdrawalData, String> {
        let path = format!("{}/{}_withdrawal.json", self.base_path, user);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read withdrawal file {}: {}", path, e))?;
        let data: WithdrawalData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse withdrawal file: {}", e))?;
        Ok(data)
    }

    /// List all files in the data directory
    pub fn list_files(&self) -> Result<Vec<String>, String> {
        let path = Path::new(&self.base_path);
        if !path.exists() {
            return Ok(vec![]);
        }
        
        let entries = fs::read_dir(path)
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
            if let Some(name) = entry.file_name().to_str() {
                files.push(name.to_string());
            }
        }
        
        files.sort();
        Ok(files)
    }
    
    /// Save CLI-compatible rollover data using existing ProofData
    pub fn save_rollover_cli_data(&self, user: &str, data: &RolloverData) -> Result<(), String> {
        self.ensure_directory()?;
        
        // Convert existing XDR hex to CLI JSON format
        let cli_data = serde_json::json!({
            "balance_amount": data.balance_amount,
            "proof": proof_xdr_to_cli_json(&data.proof.proof_hex, "NewBalanceProof")?,
            "new_balance": balance_xdr_to_cli_json(&data.proof.new_balance_hex)?
        });
        
        let json = serde_json::to_string_pretty(&cli_data)
            .map_err(|e| format!("Failed to serialize CLI rollover data: {}", e))?;
        let path = format!("{}/{}_rollover_cli.json", self.base_path, user);
        fs::write(&path, json).map_err(|e| format!("Failed to write CLI rollover file: {}", e))?;
        println!("CLI-compatible rollover data saved to {}", path);
        Ok(())
    }
    
    /// Save CLI-compatible transaction data using existing ProofData
    pub fn save_transaction_cli_data(&self, data: &TransactionData) -> Result<(), String> {
        self.ensure_directory()?;
        
        // Convert existing XDR hex to CLI JSON format
        let cli_data = serde_json::json!({
            "transfer_amount": data.transfer_amount,
            "alice_new_balance": data.alice_new_balance,
            "proof": proof_xdr_to_cli_json(&data.proof.proof_hex, "TransferProof")?,
            "new_balance": balance_xdr_to_cli_json(&data.proof.new_balance_hex)?,
            "amount_alice": data.proof.amount_alice_hex.as_ref()
                .map(|h| amount_xdr_to_cli_json(h))
                .transpose()?,
            "amount_bob": data.proof.amount_bob_hex.as_ref()
                .map(|h| amount_xdr_to_cli_json(h))
                .transpose()?,
            "amount_auditor": data.proof.amount_auditor_hex.as_ref()
                .map(|h| amount_xdr_to_cli_json(h))
                .transpose()?
        });
        
        let json = serde_json::to_string_pretty(&cli_data)
            .map_err(|e| format!("Failed to serialize CLI transaction data: {}", e))?;
        let path = format!("{}/transfer_cli.json", self.base_path);
        fs::write(&path, json).map_err(|e| format!("Failed to write CLI transfer file: {}", e))?;
        println!("CLI-compatible transfer data saved to {}", path);
        Ok(())
    }
    
    /// Save CLI-compatible withdrawal data using existing ProofData
    pub fn save_withdrawal_cli_data(&self, user: &str, data: &WithdrawalData) -> Result<(), String> {
        self.ensure_directory()?;
        
        // Convert existing XDR hex to CLI JSON format
        let cli_data = serde_json::json!({
            "withdrawal_amount": data.withdrawal_amount,
            "new_balance": data.new_balance,
            "proof": proof_xdr_to_cli_json(&data.proof.proof_hex, "NewBalanceProof")?,
            "new_balance_bytes": balance_xdr_to_cli_json(&data.proof.new_balance_hex)?
        });
        
        let json = serde_json::to_string_pretty(&cli_data)
            .map_err(|e| format!("Failed to serialize CLI withdrawal data: {}", e))?;
        let path = format!("{}/{}_withdrawal_cli.json", self.base_path, user);
        fs::write(&path, json).map_err(|e| format!("Failed to write CLI withdrawal file: {}", e))?;
        println!("CLI-compatible withdrawal data saved to {}", path);
        Ok(())
    }
    
    /// Save public key in CLI-compatible format
    pub fn save_pubkey_cli(&self, name: &str, pubkey_hex: &str) -> Result<(), String> {
        self.ensure_directory()?;
        
        let cli_pubkey = pubkey_to_cli_json(pubkey_hex)?;
        let json = serde_json::to_string_pretty(&cli_pubkey)
            .map_err(|e| format!("Failed to serialize CLI pubkey: {}", e))?;
        let path = format!("{}/{}_pubkey_cli.json", self.base_path, name);
        fs::write(&path, json).map_err(|e| format!("Failed to write CLI pubkey file: {}", e))?;
        println!("CLI-compatible public key saved to {}", path);
        Ok(())
    }
}