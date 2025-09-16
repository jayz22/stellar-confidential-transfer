use crate::types::*;
use std::fs;
use std::path::Path;
use std::io::{self, Write};
use std::process::Command;
use chrono::Local;

pub struct IOManager;

impl IOManager {
    pub fn new() -> Self {
        Self
    }

    pub fn pause(&self) {
        print!("\n[Press Enter to continue...]");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
    }

    pub fn read_user_input(&self, prompt: &str) -> String {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }

    pub fn read_file_path(&self, prompt: &str, default_path: &str) -> String {
        let input = self.read_user_input(&format!("{} [default: {}]", prompt, default_path));
        if input.is_empty() {
            default_path.to_string()
        } else {
            input
        }
    }

    pub fn read_u64(&self, prompt: &str, default: u64) -> u64 {
        let input = self.read_user_input(&format!("{} [default: {}]", prompt, default));
        if input.is_empty() {
            default
        } else {
            input.parse().unwrap_or_else(|_| {
                println!("Invalid number, using default: {}", default);
                default
            })
        }
    }

    pub fn read_u32(&self, prompt: &str, default: u32) -> u32 {
        let input = self.read_user_input(&format!("{} [default: {}]", prompt, default));
        if input.is_empty() {
            default
        } else {
            input.parse().unwrap_or_else(|_| {
                println!("Invalid number, using default: {}", default);
                default
            })
        }
    }
}


pub struct FileManager {
    base_path: String,
}

impl FileManager {
    pub fn new(base_path: &str) -> Result<Self, String> {
        let path = Path::new(&base_path);
        if !path.exists() {
            fs::create_dir_all(path).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        Ok(Self {
            base_path: base_path.to_string(),
        })
    }

    pub fn base_path(&self) -> &str {
        self.base_path.as_str()
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

        // Show file details with ls -la
        let _ = Command::new("ls")
            .args(&["-la", &key_pair_path])
            .status();

        // Save the encryption public key directly from RistrettoPoint
        let cli_pubkey = CliCompressedPubkeyBytes{bytes: key_pair.public_key.clone()};
        let pubkey_json = serde_json::to_string_pretty(&cli_pubkey)
            .map_err(|e| format!("Failed to serialize encryption pubkey: {}", e))?;
        let pubkey_path = format!("{}/{}_encryption_pubkey.json", self.base_path, name);
        fs::write(&pubkey_path, pubkey_json).map_err(|e| format!("Failed to write encryption pubkey file: {}", e))?;

        // Show file details with ls -la
        let _ = Command::new("ls")
            .args(&["-la", &pubkey_path])
            .status();

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

    /// Load rollover proof data from a file (filename only, uses base path)
    pub fn load_rollover_proof_data(&self, filename: &str) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        let file_path = format!("{}/{}", self.base_path, filename);
        let content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read rollover data file {}: {}", file_path, e))?;
        let data: RolloverProofData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse rollover data file: {}", e))?;

        Ok((data.proof, data.encrypted_new_balance))
    }

    /// Load withdrawal proof data from a file (filename only, uses base path)
    pub fn load_withdrawal_proof_data(&self, filename: &str) -> Result<(CliNewBalanceProofBytes, CliConfidentialBalanceBytes), String> {
        let file_path = format!("{}/{}", self.base_path, filename);
        let content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read withdrawal data file {}: {}", file_path, e))?;
        let data: WithdrawalProofData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse withdrawal data file: {}", e))?;

        Ok((data.proof, data.encrypted_new_balance))
    }

    /// Load transfer proof data from a file (filename only, uses base path)
    pub fn load_transfer_proof_data(&self, filename: &str) -> Result<(CliTransferProofBytes, CliConfidentialBalanceBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes, CliConfidentialAmountBytes), String> {
        let file_path = format!("{}/{}", self.base_path, filename);
        let content = fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read transfer data file {}: {}", file_path, e))?;
        let data: TransferProofData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse transfer data file: {}", e))?;

        Ok((
            data.proof,
            data.encrypted_new_balance,
            data.encrypted_src_amount,
            data.encrypted_dest_amount,
            data.encrypted_auditor_amount,
        ))
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

    /// Generate a timestamp string in HH-MM-SS format
    fn get_timestamp(&self) -> String {
        Local::now().format("%H-%M-%S").to_string()
    }

    /// Save rollover proof data in structured format
    pub fn save_rollover_proof_data(
        &self,
        key_name: &str,
        proof: &CliNewBalanceProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
    ) -> Result<String, String> {
        self.ensure_directory()?;

        // Create aggregate data
        let rollover_data = RolloverProofData {
            proof: proof.clone(),
            encrypted_new_balance: encrypted_balance.clone(),
        };

        // Save as single file with timestamp
        let timestamp = self.get_timestamp();
        let filename = format!("{}_rollover_{}.json", key_name, timestamp);
        let data_path = format!("{}/{}", self.base_path, filename);

        let data_json = serde_json::to_string_pretty(&rollover_data)
            .map_err(|e| format!("Failed to serialize rollover data: {}", e))?;
        fs::write(&data_path, data_json)
            .map_err(|e| format!("Failed to write rollover data file: {}", e))?;

        // Show file details with ls -la
        let _ = Command::new("ls")
            .args(&["-la", &data_path])
            .status();

        Ok(data_path)
    }

    /// Save withdrawal proof data in structured format
    pub fn save_withdrawal_proof_data(
        &self,
        key_name: &str,
        proof: &CliNewBalanceProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
    ) -> Result<String, String> {
        self.ensure_directory()?;

        // Create aggregate data
        let withdrawal_data = WithdrawalProofData {
            proof: proof.clone(),
            encrypted_new_balance: encrypted_balance.clone(),
        };

        // Save as single file with timestamp
        let timestamp = self.get_timestamp();
        let filename = format!("{}_withdrawal_{}.json", key_name, timestamp);
        let data_path = format!("{}/{}", self.base_path, filename);

        let data_json = serde_json::to_string_pretty(&withdrawal_data)
            .map_err(|e| format!("Failed to serialize withdrawal data: {}", e))?;
        fs::write(&data_path, data_json)
            .map_err(|e| format!("Failed to write withdrawal data file: {}", e))?;

        // Show file details with ls -la
        let _ = Command::new("ls")
            .args(&["-la", &data_path])
            .status();

        Ok(data_path)
    }

    /// Save transfer proof data in structured format
    pub fn save_transfer_proof_data(
        &self,
        from_key: &str,
        to_key: &str,
        proof: &CliTransferProofBytes,
        encrypted_balance: &CliConfidentialBalanceBytes,
        encrypted_src_amount: &CliConfidentialAmountBytes,
        encrypted_dest_amount: &CliConfidentialAmountBytes,
        encrypted_auditor_amount: &CliConfidentialAmountBytes,
    ) -> Result<String, String> {
        self.ensure_directory()?;

        // Create aggregate data
        let transfer_data = TransferProofData {
            proof: proof.clone(),
            encrypted_new_balance: encrypted_balance.clone(),
            encrypted_src_amount: encrypted_src_amount.clone(),
            encrypted_dest_amount: encrypted_dest_amount.clone(),
            encrypted_auditor_amount: encrypted_auditor_amount.clone(),
        };

        // Save as single file with timestamp, using from_key-to_key format
        let timestamp = self.get_timestamp();
        let filename = format!("{}-{}_transfer_{}.json", from_key, to_key, timestamp);
        let data_path = format!("{}/{}", self.base_path, filename);

        let data_json = serde_json::to_string_pretty(&transfer_data)
            .map_err(|e| format!("Failed to serialize transfer data: {}", e))?;
        fs::write(&data_path, data_json)
            .map_err(|e| format!("Failed to write transfer data file: {}", e))?;

        // Show file details with ls -la
        let _ = Command::new("ls")
            .args(&["-la", &data_path])
            .status();

        Ok(data_path)
    }
}