use clap::{Parser, Subcommand};
use token_client::*;
use soroban_sdk::xdr::FromXdr;

#[derive(Parser)]
#[command(name = "confidential-client")]
#[command(about = "Generic client for confidential cryptographic operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(long, default_value = ".keys")]
    data_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a cryptographic key pair from a seed
    KeyGen {
        #[arg(long)]
        seed: u64,
        #[arg(long)]
        name: String,
    },
    
    /// Generate rollover proof for moving pending balance to available
    GenerateRollover {
        #[arg(long)]
        key_name: String,
        #[arg(long)]
        available_balance: String,
        #[arg(long)]
        pending_balance: String,
    },
    
    /// Generate transfer proof for confidential transfer
    GenerateTransfer {
        #[arg(long)]
        from_key: String,
        #[arg(long)]
        to_key: String,
        #[arg(long)]
        auditor_key: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        current_encrypted_balance: String,
    },
    
    /// Generate withdrawal proof for moving confidential to transparent
    GenerateWithdrawal {
        #[arg(long)]
        key_name: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        current_encrypted_balance: String,
    },
    
    /// List all generated keys and files
    List,
    
    /// Show public key for a named key
    ShowPublicKey {
        #[arg(long)]
        name: String,
    },
    
    /// Show all public keys
    ListPublicKeys,
    
    /// Decrypt a confidential balance using a secret key
    DecryptAvailableBalance {
        #[arg(long)]
        key_name: String,
        #[arg(long)]
        ciphertext_hex: String,
    },
    
    /// Decrypt a transfer amount using a secret key
    DecryptTransferAmount {
        #[arg(long)]
        key_name: String,
        #[arg(long)]
        ciphertext_hex: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let file_manager = FileManager::new(&cli.data_dir);
    
    match cli.command {
        Commands::KeyGen { seed, name } => {
            println!("🔑 Generating key pair for '{}'...", name);
            
            let key_manager = KeyManager::new();
            let key_pair = key_manager.generate_key_pair(seed);
            
            file_manager.save_key_pair(&name, &key_pair)?;
            
            println!("\n✅ Key pair generated successfully!");
            println!("   Name: {}", name);
            println!("   Seed: {}", seed);
            println!("   Public key: {}", key_pair.public_key_hex);
        }
        
        Commands::GenerateRollover { key_name, available_balance, pending_balance } => {
            println!("🔄 Generating rollover proof for '{}'...", key_name);
            
            let key_pair = file_manager.load_key_pair(&key_name)
                .map_err(|e| format!("Failed to load key '{}'. Run 'key-gen' first: {}", key_name, e))?;
            
            let key_manager = KeyManager::new();
            let secret_key = key_manager.hex_to_scalar(&key_pair.secret_key_hex)?;
            let public_key = key_manager.hex_to_point(&key_pair.public_key_hex)?;
            
            let proof_generator = ProofGenerator::new();
            
            // Parse available balance from hex
            let available_bytes = hex::decode(&available_balance)
                .map_err(|e| format!("Invalid available balance hex: {}", e))?;
            let available_soroban_bytes = soroban_sdk::Bytes::from_slice(&proof_generator.env, &available_bytes);
            let available_balance_bytes = stellar_confidential_crypto::ConfidentialBalanceBytes::from_xdr(&proof_generator.env, &available_soroban_bytes)
                .map_err(|_| "Failed to parse available balance bytes".to_string())?;
            
            // Parse pending balance from hex
            let pending_bytes = hex::decode(&pending_balance)
                .map_err(|e| format!("Invalid pending balance hex: {}", e))?;
            let pending_soroban_bytes = soroban_sdk::Bytes::from_slice(&proof_generator.env, &pending_bytes);
            let pending_balance_bytes = stellar_confidential_crypto::ConfidentialAmountBytes::from_xdr(&proof_generator.env, &pending_soroban_bytes)
                .map_err(|_| "Failed to parse pending balance bytes".to_string())?;
            
            // Add available and pending balances to get pre-normalization balance
            let balance_pre_normalization_bytes = stellar_confidential_crypto::ConfidentialBalanceBytes::add_amount(&proof_generator.env, &available_balance_bytes, &pending_balance_bytes);
            let balance_pre_normalization = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&balance_pre_normalization_bytes);
            
            // Decrypt the combined balance to get the total amount
            let total_balance_amount = balance_pre_normalization.decrypt(&secret_key) as u64;
            println!("🔓 Decrypted total balance: {} tokens", total_balance_amount);
            
            let rollover_data = proof_generator.generate_rollover_proof(
                &secret_key,
                &public_key,
                total_balance_amount as u128,
                &balance_pre_normalization,
            )?;
            
            file_manager.save_rollover_data(&key_name, &rollover_data)?;
            
            println!("\n✅ Rollover proof generated for '{}'!", key_name);
            println!("   Total balance amount: {}", total_balance_amount);
        }
        
        Commands::GenerateTransfer { from_key, to_key, auditor_key, amount, current_encrypted_balance } => {
            println!("💸 Generating transfer proof: {} → {} (amount: {})...", from_key, to_key, amount);
            
            let from_keypair = file_manager.load_key_pair(&from_key)
                .map_err(|e| format!("Failed to load from_key '{}': {}", from_key, e))?;
            let to_keypair = file_manager.load_key_pair(&to_key)
                .map_err(|e| format!("Failed to load to_key '{}': {}", to_key, e))?;
            let auditor_keypair = file_manager.load_key_pair(&auditor_key)
                .map_err(|e| format!("Failed to load auditor_key '{}': {}", auditor_key, e))?;
            
            let key_manager = KeyManager::new();
            let from_secret = key_manager.hex_to_scalar(&from_keypair.secret_key_hex)?;
            let from_public = key_manager.hex_to_point(&from_keypair.public_key_hex)?;
            let to_public = key_manager.hex_to_point(&to_keypair.public_key_hex)?;
            let auditor_public = key_manager.hex_to_point(&auditor_keypair.public_key_hex)?;
            
            let proof_generator = ProofGenerator::new();
            
            // Parse the encrypted balance from hex
            let balance_bytes = hex::decode(&current_encrypted_balance)
                .map_err(|e| format!("Invalid balance hex: {}", e))?;
            let soroban_bytes = soroban_sdk::Bytes::from_slice(&proof_generator.env, &balance_bytes);
            let balance_bytes_obj = stellar_confidential_crypto::ConfidentialBalanceBytes::from_xdr(&proof_generator.env, &soroban_bytes)
                .map_err(|_| "Failed to parse balance bytes".to_string())?;
            let balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&balance_bytes_obj);
            
            // Decrypt the balance to get the current transparent balance amount
            let current_balance_amount = balance.decrypt(&from_secret) as u64;
            println!("🔓 Decrypted current balance: {} tokens", current_balance_amount);
            
            if amount > current_balance_amount {
                return Err(format!("Insufficient balance: trying to transfer {} but only have {}", amount, current_balance_amount).into());
            }
            
            let new_balance_amount = current_balance_amount - amount;
            
            let transfer_data = proof_generator.generate_transfer_proof(
                &from_secret,
                &from_public,
                &to_public,
                amount,
                new_balance_amount as u128,
                &balance,
                &auditor_public,
            )?;
            
            file_manager.save_transaction_data(&transfer_data)?;
            
            println!("\n✅ Transfer proof generated!");
            println!("   From: {}", from_key);
            println!("   To: {}", to_key);
            println!("   Amount: {}", amount);
            println!("   Current balance: {}", current_balance_amount);
            println!("   New balance: {}", new_balance_amount);
        }
        
        Commands::GenerateWithdrawal { key_name, amount, current_encrypted_balance } => {
            println!("💵 Generating withdrawal proof for '{}' (amount: {})...", key_name, amount);
            
            let key_pair = file_manager.load_key_pair(&key_name)
                .map_err(|e| format!("Failed to load key '{}': {}", key_name, e))?;
            
            let key_manager = KeyManager::new();
            let secret_key = key_manager.hex_to_scalar(&key_pair.secret_key_hex)?;
            let public_key = key_manager.hex_to_point(&key_pair.public_key_hex)?;
            
            let proof_generator = ProofGenerator::new();
            
            // Parse the encrypted balance from hex
            let balance_bytes = hex::decode(&current_encrypted_balance)
                .map_err(|e| format!("Invalid balance hex: {}", e))?;
            let soroban_bytes = soroban_sdk::Bytes::from_slice(&proof_generator.env, &balance_bytes);
            let balance_bytes_obj = stellar_confidential_crypto::ConfidentialBalanceBytes::from_xdr(&proof_generator.env, &soroban_bytes)
                .map_err(|_| "Failed to parse balance bytes".to_string())?;
            let balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&balance_bytes_obj);
            
            // Decrypt the balance to get the current transparent balance amount
            let current_balance_amount = balance.decrypt(&secret_key) as u64;
            println!("🔓 Decrypted current balance: {} tokens", current_balance_amount);
            
            if amount > current_balance_amount {
                return Err(format!("Insufficient balance: trying to withdraw {} but only have {}", amount, current_balance_amount).into());
            }
            
            let new_balance_amount = current_balance_amount - amount;
            
            let withdrawal_data = proof_generator.generate_withdrawal_proof(
                &secret_key,
                &public_key,
                amount,
                new_balance_amount as u128,
                &balance,
            )?;
            
            file_manager.save_withdrawal_data(&key_name, &withdrawal_data)?;
            
            println!("\n✅ Withdrawal proof generated for '{}'!", key_name);
            println!("   Withdrawal amount: {}", amount);
            println!("   Current balance: {}", current_balance_amount);
            println!("   New balance: {}", new_balance_amount);
        }
        
        Commands::List => {
            println!("📁 Keys and files in {}:", cli.data_dir);
            let files = file_manager.list_files()?;
            if files.is_empty() {
                println!("   (no files found)");
            } else {
                for file in files {
                    println!("   {}", file);
                }
            }
        }
        
        Commands::ShowPublicKey { name } => {
            let key_pair = file_manager.load_key_pair(&name)
                .map_err(|e| format!("Failed to load key '{}': {}", name, e))?;
            
            println!("📋 Public Key for '{}':", name);
            println!("   {}", key_pair.public_key_hex);
        }
        
        Commands::ListPublicKeys => {
            println!("📋 All Public Keys:");
            let files = file_manager.list_files()?;
            let key_files: Vec<_> = files.iter()
                .filter(|f| f.ends_with("_key.json"))
                .collect();
                
            if key_files.is_empty() {
                println!("   (no keys found)");
            } else {
                for file in key_files {
                    let name = file.strip_suffix("_key.json").unwrap();
                    match file_manager.load_key_pair(name) {
                        Ok(key_pair) => {
                            println!("   {}: {}", name, key_pair.public_key_hex);
                        }
                        Err(_) => {
                            println!("   {}: (error loading key)", name);
                        }
                    }
                }
            }
        }
        
        Commands::DecryptAvailableBalance { key_name, ciphertext_hex } => {
            println!("🔓 Decrypting available balance for '{}'...", key_name);
            
            let key_pair = file_manager.load_key_pair(&key_name)
                .map_err(|e| format!("Failed to load key '{}': {}", key_name, e))?;
            
            let key_manager = KeyManager::new();
            let secret_key = key_manager.hex_to_scalar(&key_pair.secret_key_hex)?;
            
            let proof_generator = ProofGenerator::new();
            
            match proof_generator.decrypt_available_balance(&secret_key, &ciphertext_hex) {
                Ok(value) => {
                    println!("\n✅ Decryption successful!");
                    println!("   Key: {}", key_name);
                    println!("   Type: ConfidentialBalance");
                    println!("   Available Balance: {}", value);
                }
                Err(e) => {
                    println!("❌ Decryption failed: {}", e);
                    println!("   This key may not be authorized to decrypt this balance");
                }
            }
        }
        
        Commands::DecryptTransferAmount { key_name, ciphertext_hex } => {
            println!("🔓 Decrypting transfer amount for '{}'...", key_name);
            
            let key_pair = file_manager.load_key_pair(&key_name)
                .map_err(|e| format!("Failed to load key '{}': {}", key_name, e))?;
            
            let key_manager = KeyManager::new();
            let secret_key = key_manager.hex_to_scalar(&key_pair.secret_key_hex)?;
            
            let proof_generator = ProofGenerator::new();
            
            match proof_generator.decrypt_transfer_amount(&secret_key, &ciphertext_hex) {
                Ok(value) => {
                    println!("\n✅ Decryption successful!");
                    println!("   Key: {}", key_name);
                    println!("   Type: ConfidentialAmount");
                    println!("   Transfer Amount: {}", value);
                }
                Err(e) => {
                    println!("❌ Decryption failed: {}", e);
                    println!("   This key may not be authorized to decrypt this amount");
                }
            }
        }
    }
    
    Ok(())
}