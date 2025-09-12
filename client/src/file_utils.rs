use crate::types::*;
use std::fs;
use std::path::Path;

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

    /// Save both key pair and encryption public key from crypto types (efficient version)
    pub fn save_key_pair_and_encryption_pubkey(&self, name: &str, key_pair: &KeyPairHex) -> Result<(), String> {
        self.ensure_directory()?;
        
        // Save the key pair
        let key_pair_json = serde_json::to_string_pretty(key_pair)
            .map_err(|e| format!("Failed to serialize key pair: {}", e))?;
        let key_pair_path = format!("{}/{}_key_pair.json", self.base_path, name);
        fs::write(&key_pair_path, key_pair_json).map_err(|e| format!("Failed to write key pair file: {}", e))?;
        println!("Key pair saved to {}", key_pair_path);

        // Save the encryption public key directly from RistrettoPoint
        let cli_pubkey = CliCompressedPubkeyBytes{bytes: key_pair.public_key.clone()};
        let pubkey_json = serde_json::to_string_pretty(&cli_pubkey)
            .map_err(|e| format!("Failed to serialize encryption pubkey: {}", e))?;
        let pubkey_path = format!("{}/{}_encryption_pubkey.json", self.base_path, name);
        fs::write(&pubkey_path, pubkey_json).map_err(|e| format!("Failed to write encryption pubkey file: {}", e))?;
        println!("Encryption public key saved to {}", pubkey_path);

        Ok(())
    }

    /// Load encryption public key from JSON file
    pub fn load_encryption_pubkey(&self, name: &str) -> Result<CliCompressedPubkeyBytes, String> {
        let path = format!("{}/{}_encryption_pubkey.json", self.base_path, name);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read encryption pubkey file {}: {}", path, e))?;
        let pubkey: CliCompressedPubkeyBytes = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse encryption pubkey file: {}", e))?;
        Ok(pubkey)
    }

    /// Load a single key pair from JSON file
    pub fn load_key_pair(&self, name: &str) -> Result<KeyPairHex, String> {
        let path = format!("{}/{}_key_pair.json", self.base_path, name);
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read key file {}: {}", path, e))?;
        let key_pair: KeyPairHex = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse key file: {}", e))?;
        Ok(key_pair)
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

    /// Ensure a specific proof type directory exists
    fn ensure_proof_directory(&self, proof_type: &str) -> Result<String, String> {
        let proof_dir = format!("{}/{}", self.base_path, proof_type);
        let path = Path::new(&proof_dir);
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        Ok(proof_dir)
    }

    /// Save rollover proof data in structured format
    pub fn save_rollover_proof_data(
        &self,
        proof: &CliNewBalanceProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
    ) -> Result<(), String> {
        let proof_dir = self.ensure_proof_directory("rollover")?;
        
        // Save new balance proof
        let proof_json = serde_json::to_string_pretty(proof)
            .map_err(|e| format!("Failed to serialize proof: {}", e))?;
        let proof_path = format!("{}/new_balance_proof.json", proof_dir);
        fs::write(&proof_path, proof_json)
            .map_err(|e| format!("Failed to write proof file: {}", e))?;
        println!("Rollover proof saved to {}", proof_path);

        // Save encrypted new balance
        let balance_json = serde_json::to_string_pretty(encrypted_balance)
            .map_err(|e| format!("Failed to serialize balance: {}", e))?;
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        fs::write(&balance_path, balance_json)
            .map_err(|e| format!("Failed to write balance file: {}", e))?;
        println!("Encrypted balance saved to {}", balance_path);

        Ok(())
    }

    /// Save withdrawal proof data in structured format
    pub fn save_withdrawal_proof_data(
        &self,
        proof: &CliNewBalanceProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
    ) -> Result<(), String> {
        let proof_dir = self.ensure_proof_directory("withdrawal")?;
        
        // Save new balance proof
        let proof_json = serde_json::to_string_pretty(proof)
            .map_err(|e| format!("Failed to serialize proof: {}", e))?;
        let proof_path = format!("{}/new_balance_proof.json", proof_dir);
        fs::write(&proof_path, proof_json)
            .map_err(|e| format!("Failed to write proof file: {}", e))?;
        println!("Withdrawal proof saved to {}", proof_path);

        // Save encrypted new balance
        let balance_json = serde_json::to_string_pretty(encrypted_balance)
            .map_err(|e| format!("Failed to serialize balance: {}", e))?;
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        fs::write(&balance_path, balance_json)
            .map_err(|e| format!("Failed to write balance file: {}", e))?;
        println!("Encrypted balance saved to {}", balance_path);

        Ok(())
    }

    /// Save transfer proof data in structured format
    pub fn save_transfer_proof_data(
        &self,
        proof: &CliTransferProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
        encrypted_src_amount: &CliConfidentialAmountBytes,
        encrypted_dest_amount: &CliConfidentialAmountBytes,
        encrypted_auditor_amount: &CliConfidentialAmountBytes,
    ) -> Result<(), String> {
        let proof_dir = self.ensure_proof_directory("transfer")?;
        
        // Save transfer proof
        let proof_json = serde_json::to_string_pretty(proof)
            .map_err(|e| format!("Failed to serialize proof: {}", e))?;
        let proof_path = format!("{}/transfer_proof.json", proof_dir);
        fs::write(&proof_path, proof_json)
            .map_err(|e| format!("Failed to write proof file: {}", e))?;
        println!("Transfer proof saved to {}", proof_path);

        // Save encrypted new balance
        let balance_json = serde_json::to_string_pretty(encrypted_balance)
            .map_err(|e| format!("Failed to serialize balance: {}", e))?;
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        fs::write(&balance_path, balance_json)
            .map_err(|e| format!("Failed to write balance file: {}", e))?;
        println!("Encrypted new balance saved to {}", balance_path);

        // Save encrypted source amount
        let src_amount_json = serde_json::to_string_pretty(encrypted_src_amount)
            .map_err(|e| format!("Failed to serialize src amount: {}", e))?;
        let src_amount_path = format!("{}/encrypted_src_amount.json", proof_dir);
        fs::write(&src_amount_path, src_amount_json)
            .map_err(|e| format!("Failed to write src amount file: {}", e))?;
        println!("Encrypted source amount saved to {}", src_amount_path);

        // Save encrypted destination amount
        let dest_amount_json = serde_json::to_string_pretty(encrypted_dest_amount)
            .map_err(|e| format!("Failed to serialize dest amount: {}", e))?;
        let dest_amount_path = format!("{}/encrypted_dest_amount.json", proof_dir);
        fs::write(&dest_amount_path, dest_amount_json)
            .map_err(|e| format!("Failed to write dest amount file: {}", e))?;
        println!("Encrypted destination amount saved to {}", dest_amount_path);

        // Save encrypted auditor amount
        let auditor_amount_json = serde_json::to_string_pretty(encrypted_auditor_amount)
            .map_err(|e| format!("Failed to serialize auditor amount: {}", e))?;
        let auditor_amount_path = format!("{}/encrypted_auditor_amount.json", proof_dir);
        fs::write(&auditor_amount_path, auditor_amount_json)
            .map_err(|e| format!("Failed to write auditor amount file: {}", e))?;
        println!("Encrypted auditor amount saved to {}", auditor_amount_path);

        Ok(())
    }

    /// Load rollover proof data
    pub fn load_rollover_proof_data(&self) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        let proof_dir = format!("{}/rollover", self.base_path);
        
        // Load proof
        let proof_path = format!("{}/new_balance_proof.json", proof_dir);
        let proof_content = fs::read_to_string(&proof_path)
            .map_err(|e| format!("Failed to read proof file {}: {}", proof_path, e))?;
        let proof: CliNewBalanceProofBytes = serde_json::from_str(&proof_content)
            .map_err(|e| format!("Failed to parse proof file: {}", e))?;

        // Load encrypted balance
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        let balance_content = fs::read_to_string(&balance_path)
            .map_err(|e| format!("Failed to read balance file {}: {}", balance_path, e))?;
        let balance: CliConfidentialBalanceBytes = serde_json::from_str(&balance_content)
            .map_err(|e| format!("Failed to parse balance file: {}", e))?;

        Ok((proof, balance))
    }

    /// Load withdrawal proof data
    pub fn load_withdrawal_proof_data(&self) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        let proof_dir = format!("{}/withdrawal", self.base_path);
        
        // Load proof
        let proof_path = format!("{}/new_balance_proof.json", proof_dir);
        let proof_content = fs::read_to_string(&proof_path)
            .map_err(|e| format!("Failed to read proof file {}: {}", proof_path, e))?;
        let proof: CliNewBalanceProofBytes = serde_json::from_str(&proof_content)
            .map_err(|e| format!("Failed to parse proof file: {}", e))?;

        // Load encrypted balance
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        let balance_content = fs::read_to_string(&balance_path)
            .map_err(|e| format!("Failed to read balance file {}: {}", balance_path, e))?;
        let balance: CliConfidentialBalanceBytes = serde_json::from_str(&balance_content)
            .map_err(|e| format!("Failed to parse balance file: {}", e))?;

        Ok((proof, balance))
    }

    /// Load transfer proof data
    pub fn load_transfer_proof_data(&self) -> Result<(CliTransferProofBytes, CliConfidentialBalanceBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes), String> {
        let proof_dir = format!("{}/transfer", self.base_path);
        
        // Load proof
        let proof_path = format!("{}/transfer_proof.json", proof_dir);
        let proof_content = fs::read_to_string(&proof_path)
            .map_err(|e| format!("Failed to read proof file {}: {}", proof_path, e))?;
        let proof: CliTransferProofBytes = serde_json::from_str(&proof_content)
            .map_err(|e| format!("Failed to parse proof file: {}", e))?;

        // Load encrypted balance
        let balance_path = format!("{}/encrypted_new_balance.json", proof_dir);
        let balance_content = fs::read_to_string(&balance_path)
            .map_err(|e| format!("Failed to read balance file {}: {}", balance_path, e))?;
        let balance: CliConfidentialBalanceBytes = serde_json::from_str(&balance_content)
            .map_err(|e| format!("Failed to parse balance file: {}", e))?;

        // Load encrypted source amount
        let src_amount_path = format!("{}/encrypted_src_amount.json", proof_dir);
        let src_amount_content = fs::read_to_string(&src_amount_path)
            .map_err(|e| format!("Failed to read src amount file {}: {}", src_amount_path, e))?;
        let src_amount: CliConfidentialAmountBytes = serde_json::from_str(&src_amount_content)
            .map_err(|e| format!("Failed to parse src amount file: {}", e))?;

        // Load encrypted destination amount
        let dest_amount_path = format!("{}/encrypted_dest_amount.json", proof_dir);
        let dest_amount_content = fs::read_to_string(&dest_amount_path)
            .map_err(|e| format!("Failed to read dest amount file {}: {}", dest_amount_path, e))?;
        let dest_amount: CliConfidentialAmountBytes = serde_json::from_str(&dest_amount_content)
            .map_err(|e| format!("Failed to parse dest amount file: {}", e))?;

        // Load encrypted auditor amount
        let auditor_amount_path = format!("{}/encrypted_auditor_amount.json", proof_dir);
        let auditor_amount_content = fs::read_to_string(&auditor_amount_path)
            .map_err(|e| format!("Failed to read auditor amount file {}: {}", auditor_amount_path, e))?;
        let auditor_amount: CliConfidentialAmountBytes = serde_json::from_str(&auditor_amount_content)
            .map_err(|e| format!("Failed to parse auditor amount file: {}", e))?;

        Ok((proof, balance, src_amount, dest_amount, auditor_amount))
    }
}