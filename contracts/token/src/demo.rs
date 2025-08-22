#![cfg(feature = "demo")]
extern crate std;

use crate::{
    contract::ConfidentialToken,
    utils::read_account_confidential_ext,
    ConfidentialTokenClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String, xdr::{FromXdr, ToXdr}};
use stellar_confidential_crypto::{
    proof::CompressedPubkeyBytes,
    ConfidentialAmountBytes, ConfidentialBalanceBytes, RistrettoPoint, Scalar,
};
use std::io::{self, Write};
use std::fs;
use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key_hex: std::string::String,
    pub public_key_hex: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub proof_hex: std::string::String,
    pub new_balance_hex: std::string::String,
    pub amount_alice_hex: Option<std::string::String>,
    pub amount_bob_hex: Option<std::string::String>,
    pub amount_auditor_hex: Option<std::string::String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloverData {
    pub balance_amount: u64,
    pub proof: ProofData,
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

pub struct DemoState {
    env: Env,
    token: Option<ConfidentialTokenClient<'static>>,
    admin: Option<Address>,
    alice: Option<Address>,
    bob: Option<Address>,
    alice_secret_key: Option<Scalar>,
    alice_public_key: Option<RistrettoPoint>,
    bob_secret_key: Option<Scalar>,
    bob_public_key: Option<RistrettoPoint>,
    auditor_secret_key: Option<Scalar>,
    auditor_public_key: Option<RistrettoPoint>,
}

impl DemoState {
    pub fn new() -> Self {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     STELLAR CONFIDENTIAL TOKEN - INTERACTIVE DEMO                 ║");
        println!("║                                                                    ║");
        println!("║   🖥️  Terminal 1: Run client for key generation & proof creation  ║");
        println!("║   🖥️  Terminal 2: Run demo contract (locally)                     ║");
        println!("║                                                                    ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");
        
        Self {
            env: Env::default(),
            token: None,
            admin: None,
            alice: None,
            bob: None,
            alice_secret_key: None,
            alice_public_key: None,
            bob_secret_key: None,
            bob_public_key: None,
            auditor_secret_key: None,
            auditor_public_key: None,
        }
    }

    fn load_key_pair_from_file(&self, file_path: &str) -> Option<KeyPair> {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Failed to read key file {}: {}", file_path, e);
                return None;
            }
        };
        match serde_json::from_str(&content) {
            Ok(key_pair) => Some(key_pair),
            Err(e) => {
                println!("❌ Failed to parse key file: {}", e);
                None
            }
        }
    }

    fn load_proof_from_file<T: serde::de::DeserializeOwned>(&self, file_path: &str) -> Option<T> {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Failed to read file {}: {}", file_path, e);
                return None;
            }
        };
        match serde_json::from_str(&content) {
            Ok(data) => Some(data),
            Err(e) => {
                println!("❌ Failed to parse file: {}", e);
                None
            }
        }
    }

    fn pause(&self) {
        print!("\n[Press Enter to continue...]");
        io::stdout().flush().unwrap();
        let mut input = std::string::String::new();
        io::stdin().read_line(&mut input).unwrap();
    }
    
    fn read_user_input(&self, prompt: &str) -> std::string::String {
        print!("{}: ", prompt);
        io::stdout().flush().unwrap();
        let mut input = std::string::String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }
    
    fn read_file_path(&self, prompt: &str, default_path: &str) -> std::string::String {
        let input = self.read_user_input(&format!("{} [default: {}]", prompt, default_path));
        if input.is_empty() {
            default_path.to_string()
        } else {
            input
        }
    }
    
    fn read_u64(&self, prompt: &str, default: u64) -> u64 {
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
    
    fn read_u32(&self, prompt: &str, default: u32) -> u32 {
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
    
    
    
    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect("Invalid hex string")
    }
    
    fn hex_to_scalar(&self, hex_str: &str) -> Scalar {
        let bytes = Self::hex_to_bytes(hex_str);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        Scalar::from_bytes_mod_order(array)
    }
    
    fn hex_to_point(&self, hex_str: &str) -> RistrettoPoint {
        let bytes = Self::hex_to_bytes(hex_str);
        let compressed = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&bytes[..32])
            .expect("Invalid compressed point");
        compressed.decompress().expect("Invalid point")
    }

    fn hex_to_transfer_proof(&self, hex_str: &str) -> stellar_confidential_crypto::proof::TransferProofBytes {
        let bytes = Self::hex_to_bytes(hex_str);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        stellar_confidential_crypto::proof::TransferProofBytes::from_xdr(&self.env, &soroban_bytes).unwrap()
    }

    fn hex_to_rollover_proof(&self, hex_str: &str) -> stellar_confidential_crypto::proof::NewBalanceProofBytes {
        let bytes = Self::hex_to_bytes(hex_str);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        stellar_confidential_crypto::proof::NewBalanceProofBytes::from_xdr(&self.env, &soroban_bytes).unwrap()
    }

    fn hex_to_balance_bytes(&self, hex_str: &str) -> ConfidentialBalanceBytes {
        let bytes = Self::hex_to_bytes(hex_str);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        ConfidentialBalanceBytes::from_xdr(&self.env, &soroban_bytes).unwrap()
    }

    fn hex_to_amount_bytes(&self, hex_str: &str) -> ConfidentialAmountBytes {
        let bytes = Self::hex_to_bytes(hex_str);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        ConfidentialAmountBytes::from_xdr(&self.env, &soroban_bytes).unwrap()
    }

    fn hex_to_withdrawal_proof(&self, hex_str: &str) -> stellar_confidential_crypto::proof::NewBalanceProofBytes {
        let bytes = Self::hex_to_bytes(hex_str);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&self.env, &bytes);
        stellar_confidential_crypto::proof::NewBalanceProofBytes::from_xdr(&self.env, &soroban_bytes).unwrap()
    }

    fn print_separator(&self) {
        println!("\n═══════════════════════════════════════════════════════════════════");
    }
    
    fn time_operation<F, R>(&self, operation_name: &str, operation: F) -> R 
    where F: FnOnce() -> R
    {
        println!("⏱️  Executing {}...", operation_name);
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();
        println!("✅ {} completed in {:.2?}", operation_name, duration);
        result
    }
    

    fn print_state_diagram(&self, title: &str, alice_transparent: i128, alice_available: u128, alice_pending: u128, alice_counter: u32, bob_transparent: i128, bob_available: u128, bob_pending: u128, bob_counter: u32, total_confidential: u128) {
        self.print_separator();
        println!(" {}", title);
        self.print_separator();
        println!();
        println!("                   ┌─────────────────────────────────┐");
        println!("                   │         TOKEN STATE             │");
        println!("                   │  Total Confidential Supply: {:>3} │", total_confidential);
        println!("                   └─────────────────────────────────┘");
        println!();
        println!("  ┌─────────────────────────────┐          ┌─────────────────────────────┐");
        println!("  │           ALICE             │          │            BOB              │");
        println!("  │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │");
        println!("  │ │ Transparent: {:>10} │ │          │ │ Transparent: {:>10} │ │", alice_transparent, bob_transparent);
        println!("  │ │ Available:   {:>10} │ │          │ │ Available:   {:>10} │ │", alice_available, bob_available);
        println!("  │ │ Pending:     {:>10} │ │          │ │ Pending:     {:>10} │ │", alice_pending, bob_pending);
        println!("  │ │ Counter:     {:>10} │ │          │ │ Counter:     {:>10} │ │", alice_counter, bob_counter);
        println!("  │ └─────────────────────────┘ │          │ └─────────────────────────┘ │");
        println!("  └─────────────────────────────┘          └─────────────────────────────┘");
        self.print_separator();
    }

    pub fn step_1_create_token(&mut self) {
        println!("\n📋 STEP 1: Create Token and Admin");
        println!("Creating a new confidential token with admin account...\n");
        
        // Get user input for token parameters
        let name = self.read_user_input("Enter token name [default: Confidential Demo Token]");
        let name = if name.is_empty() { "Confidential Demo Token" } else { &name };
        
        let symbol = self.read_user_input("Enter token symbol [default: CDT]");
        let symbol = if symbol.is_empty() { "CDT" } else { &symbol };
        
        let decimals = self.read_u32("Enter token decimals", 7);

        self.env.mock_all_auths();
        self.admin = Some(Address::generate(&self.env));
        
        let token_contract = self.env.register(
            ConfidentialToken,
            (
                self.admin.as_ref().unwrap(),
                decimals,
                String::from_str(&self.env, name),
                String::from_str(&self.env, symbol),
            ),
        );
        self.token = Some(ConfidentialTokenClient::new(&self.env, &token_contract));

        println!("\n✅ Token created successfully!");
        println!("   Name: {}", name);
        println!("   Symbol: {}", symbol);
        println!("   Decimals: {}", decimals);
        println!("   Admin: {:?}", self.admin.as_ref().unwrap());
        
        self.pause();
    }

    pub fn step_2_create_accounts(&mut self) {
        println!("\n👥 STEP 2: Create User Accounts");
        println!("Creating accounts for Alice and Bob...\n");

        self.alice = Some(Address::generate(&self.env));
        self.bob = Some(Address::generate(&self.env));

        println!("✅ Accounts created:");
        println!("   Alice: {:?}", self.alice.as_ref().unwrap());
        println!("   Bob:   {:?}", self.bob.as_ref().unwrap());
        
        self.pause();
    }

    pub fn step_3_load_keys(&mut self) {
        println!("\n🔑 STEP 3: Load Cryptographic Keys");
        println!("Loading encryption keys from client-generated files...\n");
        
        println!("📋 Generate keys first using client:");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 12345 --name alice");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 67890 --name bob");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 99999 --name auditor");
        println!();

        // Load Alice's keys
        let alice_file = self.read_file_path("Enter path to Alice's key file", ".keys/alice_key.json");
        if let Some(alice_keys) = self.load_key_pair_from_file(&alice_file) {
            self.alice_secret_key = Some(self.hex_to_scalar(&alice_keys.secret_key_hex));
            self.alice_public_key = Some(self.hex_to_point(&alice_keys.public_key_hex));
            println!("✅ Alice's keys loaded from: {}", alice_file);
            println!("   Public Key: {}", alice_keys.public_key_hex);
        } else {
            println!("❌ Failed to load Alice's keys. Please check the file and restart.");
            return;
        }

        // Load Bob's keys
        let bob_file = self.read_file_path("Enter path to Bob's key file", ".keys/bob_key.json");
        if let Some(bob_keys) = self.load_key_pair_from_file(&bob_file) {
            self.bob_secret_key = Some(self.hex_to_scalar(&bob_keys.secret_key_hex));
            self.bob_public_key = Some(self.hex_to_point(&bob_keys.public_key_hex));
            println!("✅ Bob's keys loaded from: {}", bob_file);
            println!("   Public Key: {}", bob_keys.public_key_hex);
        } else {
            println!("❌ Failed to load Bob's keys. Please check the file and restart.");
            return;
        }

        // Load Auditor's keys
        let auditor_file = self.read_file_path("Enter path to Auditor's key file", ".keys/auditor_key.json");
        if let Some(auditor_keys) = self.load_key_pair_from_file(&auditor_file) {
            self.auditor_secret_key = Some(self.hex_to_scalar(&auditor_keys.secret_key_hex));
            self.auditor_public_key = Some(self.hex_to_point(&auditor_keys.public_key_hex));
            println!("✅ Auditor's keys loaded from: {}", auditor_file);
            println!("   Public Key: {}", auditor_keys.public_key_hex);
        } else {
            println!("❌ Failed to load Auditor's keys. Please check the file and restart.");
            return;
        }
        
        println!("\n📝 Note: All keys successfully loaded!");
        println!("   Off-chain: Keys generated by client");
        println!("   On-chain: Keys loaded by demo contract");
        
        self.pause();
    }

    pub fn step_4_register_token(&mut self) {
        println!("\n🔐 STEP 4: Register Confidential Token Extension");
        println!("Registering the token for confidential transfers with auditor...\n");
        
        // Get auditor public key from user input
        let auditor_pk_hex = self.read_user_input("Enter auditor public key (hex) or press Enter to use generated key");
        
        let auditor_compressed_pk = if auditor_pk_hex.is_empty() {
            // Use the generated key
            CompressedPubkeyBytes::from_point(&self.env, self.auditor_public_key.as_ref().unwrap())
        } else {
            // Parse the hex input
            let auditor_point = self.hex_to_point(&auditor_pk_hex);
            CompressedPubkeyBytes::from_point(&self.env, &auditor_point)
        };
        
        self.token.as_ref().unwrap().register_confidential_token(&auditor_compressed_pk);

        println!("\n✅ Token registered for confidential transfers!");
        println!("   Auditor public key registered");
        println!("   Confidential extension enabled");
        println!("\n📝 Note: The auditor can decrypt all transfer amounts");
        println!("   for regulatory compliance");
        
        self.pause();
    }

    pub fn step_5_register_accounts(&mut self) {
        println!("\n👤 STEP 5: Register User Accounts for Confidential Transfers");
        println!("Registering Alice and Bob's accounts...\n");
        
        // Get Alice's public key from user input
        let alice_pk_hex = self.read_user_input("Enter Alice's public key (hex) or press Enter to use generated key");
        let alice_compressed_pk = if alice_pk_hex.is_empty() {
            CompressedPubkeyBytes::from_point(&self.env, self.alice_public_key.as_ref().unwrap())
        } else {
            let alice_point = self.hex_to_point(&alice_pk_hex);
            CompressedPubkeyBytes::from_point(&self.env, &alice_point)
        };
        
        // Get Bob's public key from user input
        let bob_pk_hex = self.read_user_input("Enter Bob's public key (hex) or press Enter to use generated key");
        let bob_compressed_pk = if bob_pk_hex.is_empty() {
            CompressedPubkeyBytes::from_point(&self.env, self.bob_public_key.as_ref().unwrap())
        } else {
            let bob_point = self.hex_to_point(&bob_pk_hex);
            CompressedPubkeyBytes::from_point(&self.env, &bob_point)
        };

        self.token.as_ref().unwrap().register_account(self.alice.as_ref().unwrap(), &alice_compressed_pk);
        self.token.as_ref().unwrap().register_account(self.bob.as_ref().unwrap(), &bob_compressed_pk);

        println!("\n✅ Accounts registered:");
        println!("   - Alice's encryption key registered");
        println!("   - Bob's encryption key registered");
        println!("   Both can now receive confidential transfers");
        
        self.pause();
    }

    pub fn step_6_mint_tokens(&mut self) {
        println!("\n💰 STEP 6: Mint Tokens (Transparent Balance)");
        println!("Minting initial tokens to Alice and Bob...\n");
        
        // Get mint amounts from user input
        let alice_amount = self.read_u64("Enter amount to mint for Alice", 1000) as i128;
        let bob_amount = self.read_u64("Enter amount to mint for Bob", 500) as i128;

        self.token.as_ref().unwrap().mint(self.alice.as_ref().unwrap(), &alice_amount);
        self.token.as_ref().unwrap().mint(self.bob.as_ref().unwrap(), &bob_amount);

        println!("✅ Tokens minted:");
        println!("   Alice: {} CDT (transparent)", alice_amount);
        println!("   Bob:   {} CDT (transparent)", bob_amount);
        println!("\n📝 Note: These are regular transparent tokens,");
        println!("   visible on the blockchain");

        self.print_state_diagram(
            "STATE AFTER MINTING",
            alice_amount,
            0,
            0,
            0,
            bob_amount,
            0,
            0,
            0,
            0,
        );
        
        self.pause();
    }

    pub fn step_7_deposit_confidential(&mut self) -> (u64, u64) {
        println!("\n🔒 STEP 7: Deposit to Confidential Balance");
        println!("Moving tokens from transparent to confidential pending balance...\n");
        
        // Get deposit amounts from user input
        let alice_deposit = self.read_u64("Enter amount for Alice to deposit to confidential", 500);
        let bob_deposit = self.read_u64("Enter amount for Bob to deposit to confidential", 250);

        println!("Alice deposits {} CDT to confidential", alice_deposit);
        self.token.as_ref().unwrap().deposit(self.alice.as_ref().unwrap(), &alice_deposit);
        
        println!("Bob deposits {} CDT to confidential", bob_deposit);
        self.token.as_ref().unwrap().deposit(self.bob.as_ref().unwrap(), &bob_deposit);

        println!("\n✅ Deposits completed!");
        println!("   Tokens moved to pending confidential balance");
        println!("   (Need rollover to make them available for transfer)");

        // Calculate remaining transparent balances after deposits
        let alice_transparent_after = self.token.as_ref().unwrap().balance(self.alice.as_ref().unwrap());
        let bob_transparent_after = self.token.as_ref().unwrap().balance(self.bob.as_ref().unwrap());
        
        self.print_state_diagram(
            "STATE AFTER DEPOSITS",
            alice_transparent_after,
            0,
            alice_deposit as u128,
            1,
            bob_transparent_after,
            0,
            bob_deposit as u128,
            1,
            (alice_deposit + bob_deposit) as u128,
        );
        
        self.pause();
        (alice_deposit, bob_deposit)
    }

    pub fn step_8_alice_rollover(&mut self, _alice_deposit: u64, bob_deposit: u64) -> ConfidentialBalanceBytes {
        println!("\n🔄 STEP 8: Alice Rollover (Pending → Available)");
        println!("Alice moves her pending balance to available balance...\n");

        // Get Alice's current available and pending balances from the contract
        let alice_available_balance = self.env.as_contract(&self.token.as_ref().unwrap().address, || {
            let ext = read_account_confidential_ext(&self.env, self.alice.as_ref().unwrap().clone());
            ext.available_balance
        });
        let alice_pending_balance = self.env.as_contract(&self.token.as_ref().unwrap().address, || {
            let ext = read_account_confidential_ext(&self.env, self.alice.as_ref().unwrap().clone());
            ext.pending_balance
        });

        // Convert to hex for the client command
        let available_balance_hex = hex::encode(alice_available_balance.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let pending_balance_hex = hex::encode(alice_pending_balance.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());

        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-rollover --key-name alice --available-balance {} --pending-balance {}", available_balance_hex, pending_balance_hex);
        println!();

        // Get rollover proof file path
        let rollover_file = self.read_file_path("Enter path to Alice's rollover proof file", ".keys/alice_rollover.json");
        
        // Load Alice's rollover data
        let alice_rollover: RolloverData = if let Some(data) = self.load_proof_from_file(&rollover_file) {
            println!("✅ Loaded Alice's rollover proof from: {}", rollover_file);
            data
        } else {
            println!("❌ Failed to load rollover proof. Please check the file and restart.");
            return ConfidentialBalanceBytes::zero(&self.env);
        };

        // Convert hex data to contract types
        let alice_rollover_proof = self.hex_to_rollover_proof(&alice_rollover.proof.proof_hex);
        let alice_new_balance_bytes = self.hex_to_balance_bytes(&alice_rollover.proof.new_balance_hex);

        // Execute rollover with timing
        self.time_operation("rollover_pending_balance", || {
            self.token.as_ref().unwrap().rollover_pending_balance(
                self.alice.as_ref().unwrap(),
                &alice_new_balance_bytes,
                &alice_rollover_proof,
            );
        });

        println!("\n✅ Rollover completed!");
        println!("   Alice's {} CDT now available for confidential transfers", alice_rollover.balance_amount);
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        let alice_transparent = self.token.as_ref().unwrap().balance(self.alice.as_ref().unwrap());
        let bob_transparent = self.token.as_ref().unwrap().balance(self.bob.as_ref().unwrap());
        
        self.print_state_diagram(
            "STATE AFTER ALICE'S ROLLOVER",
            alice_transparent,
            alice_rollover.balance_amount as u128,
            0,
            0,
            bob_transparent,
            0,
            bob_deposit as u128,
            1,
            (alice_rollover.balance_amount + bob_deposit) as u128,
        );
        
        self.pause();
        alice_new_balance_bytes
    }

    pub fn step_9_confidential_transfer(&mut self, alice_balance_bytes: ConfidentialBalanceBytes, alice_available: u64, alice_deposit: u64, bob_deposit: u64) -> (u64, ConfidentialBalanceBytes, ConfidentialAmountBytes, ConfidentialAmountBytes, ConfidentialAmountBytes) {
        println!("\n💸 STEP 9: Confidential Transfer (Alice → Bob)");
        println!("Alice sends tokens to Bob confidentially...\n");
        println!("Alice's available balance: {} CDT", alice_available);
        
        // Convert alice_balance_bytes to hex for the client command
        let alice_balance_hex = hex::encode(alice_balance_bytes.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        
        println!("📋 Generate transfer proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-transfer --from-key alice --to-key bob --auditor-key auditor --amount 100 --current-encrypted-balance {}", alice_balance_hex);
        println!();

        // Get transfer proof file path
        let transfer_file = self.read_file_path("Enter path to transfer proof file", ".keys/transfer.json");

        // Load transfer data
        let transfer_data: TransactionData = if let Some(data) = self.load_proof_from_file(&transfer_file) {
            println!("✅ Loaded transfer proof from: {}", transfer_file);
            data
        } else {
            println!("❌ Failed to load transfer proof. Aborting step.");
            return (0, ConfidentialBalanceBytes::zero(&self.env), ConfidentialAmountBytes::zero(&self.env), ConfidentialAmountBytes::zero(&self.env), ConfidentialAmountBytes::zero(&self.env));
        };

        // Convert hex data to contract types
        let transfer_proof = self.hex_to_transfer_proof(&transfer_data.proof.proof_hex);
        let alice_balance_after_transfer = self.hex_to_balance_bytes(&transfer_data.proof.new_balance_hex);
        let amount_for_alice = self.hex_to_amount_bytes(&transfer_data.proof.amount_alice_hex.as_ref().unwrap());
        let amount_for_bob = self.hex_to_amount_bytes(&transfer_data.proof.amount_bob_hex.as_ref().unwrap());
        let amount_for_auditor = self.hex_to_amount_bytes(&transfer_data.proof.amount_auditor_hex.as_ref().unwrap());

        println!("📤 Executing confidential transfer using client-generated proof...");
        self.token.as_ref().unwrap().confidential_transfer(
            self.alice.as_ref().unwrap(),
            self.bob.as_ref().unwrap(),
            &amount_for_alice,
            &amount_for_bob,
            &amount_for_auditor,
            &alice_balance_after_transfer,
            &transfer_proof,
        );

        println!("\n✅ Transfer completed!");
        println!("   Amount: {} CDT", transfer_data.transfer_amount);
        println!("   From: Alice ({} CDT remaining)", transfer_data.alice_new_balance);
        println!("   To: Bob (now has {} CDT pending)", bob_deposit + transfer_data.transfer_amount);
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        let alice_transparent = self.token.as_ref().unwrap().balance(self.alice.as_ref().unwrap());
        let bob_transparent = self.token.as_ref().unwrap().balance(self.bob.as_ref().unwrap());
        
        self.print_state_diagram(
            "STATE AFTER CONFIDENTIAL TRANSFER",
            alice_transparent,
            transfer_data.alice_new_balance as u128,
            0,
            0,
            bob_transparent,
            0,
            (bob_deposit + transfer_data.transfer_amount) as u128,
            2,
            (alice_deposit + bob_deposit) as u128,
        );
        
        self.pause();
        (transfer_data.transfer_amount, alice_balance_after_transfer, amount_for_alice, amount_for_bob, amount_for_auditor)
    }

    pub fn step_10_decrypt_amounts(&mut self, _transfer_amount: u64, amount_for_alice: &ConfidentialAmountBytes, amount_for_bob: &ConfidentialAmountBytes, amount_for_auditor: &ConfidentialAmountBytes, alice_balance_after_transfer: &ConfidentialBalanceBytes) {
        println!("\n🔓 STEP 10: Decrypt Transfer Amounts (Off-chain)");
        println!("Demonstrating that only authorized parties can decrypt...\n");

        // Convert to hex for the client commands
        let alice_amount_hex = hex::encode(amount_for_alice.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let bob_amount_hex = hex::encode(amount_for_bob.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let auditor_amount_hex = hex::encode(amount_for_auditor.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let alice_balance_hex = hex::encode(alice_balance_after_transfer.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());

        println!("📋 Use the client to decrypt the confidential amounts:");
        println!("   Off-chain decryption preserves privacy - only authorized parties can decrypt");
        println!();
        
        println!("🔓 Alice can decrypt her amount:");
        println!("   Terminal 1: cargo run --bin client -- decrypt-transfer-amount --key-name alice --ciphertext-hex {}", alice_amount_hex);
        println!();
        
        println!("🔓 Bob can decrypt his amount:");
        println!("   Terminal 1: cargo run --bin client -- decrypt-transfer-amount --key-name bob --ciphertext-hex {}", bob_amount_hex);
        println!();
        
        println!("🔓 Auditor can decrypt the transfer amount:");
        println!("   Terminal 1: cargo run --bin client -- decrypt-transfer-amount --key-name auditor --ciphertext-hex {}", auditor_amount_hex);
        println!();
        
        println!("🔓 Alice can decrypt her new balance:");
        println!("   Terminal 1: cargo run --bin client -- decrypt-available-balance --key-name alice --ciphertext-hex {}", alice_balance_hex);
        println!();

        println!("📝 Note: Carol (observer) cannot decrypt any of these values!");
        println!("   Without the secret key, the amounts remain confidential");
        println!("   Decryption happens off-chain to maintain privacy");
        
        self.pause();
    }

    pub fn step_11_bob_rollover(&mut self, bob_deposit: u64, transfer_amount: u64, alice_deposit: u64) -> ConfidentialBalanceBytes {
        println!("\n🔄 STEP 11: Bob Rollover (Pending → Available)");
        println!("Bob moves his total pending balance to available...\n");

        let bob_total = bob_deposit + transfer_amount;
        println!("Bob's total pending balance: {} CDT", bob_total);

        // Get Bob's current available and pending balances from the contract
        let bob_available_balance = self.env.as_contract(&self.token.as_ref().unwrap().address, || {
            let ext = read_account_confidential_ext(&self.env, self.bob.as_ref().unwrap().clone());
            ext.available_balance
        });
        let bob_pending_balance = self.env.as_contract(&self.token.as_ref().unwrap().address, || {
            let ext = read_account_confidential_ext(&self.env, self.bob.as_ref().unwrap().clone());
            ext.pending_balance
        });

        // Convert to hex for the client command
        let available_balance_hex = hex::encode(bob_available_balance.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());
        let pending_balance_hex = hex::encode(bob_pending_balance.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());

        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-rollover --key-name bob --available-balance {} --pending-balance {}", available_balance_hex, pending_balance_hex);
        println!();

        // Get rollover proof file path
        let rollover_file = self.read_file_path("Enter path to Bob's rollover proof file", ".keys/bob_rollover.json");
        
        // Load Bob's rollover data
        let bob_rollover: RolloverData = if let Some(data) = self.load_proof_from_file(&rollover_file) {
            println!("✅ Loaded Bob's rollover proof from: {}", rollover_file);
            data
        } else {
            println!("❌ Failed to load rollover proof. Please check the file and restart.");
            return ConfidentialBalanceBytes::zero(&self.env);
        };

        // Convert hex data to contract types
        let bob_rollover_proof = self.hex_to_rollover_proof(&bob_rollover.proof.proof_hex);
        let bob_new_balance_bytes = self.hex_to_balance_bytes(&bob_rollover.proof.new_balance_hex);

        // Execute rollover with timing
        self.time_operation("rollover_pending_balance", || {
            self.token.as_ref().unwrap().rollover_pending_balance(
                self.bob.as_ref().unwrap(),
                &bob_new_balance_bytes,
                &bob_rollover_proof,
            );
        });

        println!("\n✅ Rollover completed!");
        println!("   Bob's {} CDT now available for confidential transfers", bob_rollover.balance_amount);
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        let alice_transparent = self.token.as_ref().unwrap().balance(self.alice.as_ref().unwrap());
        let bob_transparent = self.token.as_ref().unwrap().balance(self.bob.as_ref().unwrap());
        
        self.print_state_diagram(
            "STATE AFTER BOB'S ROLLOVER",
            alice_transparent,
            (alice_deposit - transfer_amount) as u128,  // Alice's remaining confidential
            0,
            0,
            bob_transparent,
            bob_rollover.balance_amount as u128,
            0,
            0,
            (alice_deposit + bob_deposit) as u128,  // Total confidential supply unchanged
        );
        
        self.pause();
        bob_new_balance_bytes
    }

    pub fn step_12_withdraw(&mut self, bob_balance_bytes: ConfidentialBalanceBytes, bob_available: u64, alice_deposit: u64, transfer_amount: u64) {
        println!("\n💵 STEP 12: Withdraw (Confidential → Transparent)");
        println!("Bob withdraws from confidential to transparent...\n");
        println!("Bob's available balance: {} CDT", bob_available);
        
        // Get withdrawal amount from user input
        let withdrawal_amount = self.read_u64("Enter amount for Bob to withdraw", 100);

        // Convert bob_balance_bytes to hex for the client command
        let bob_balance_hex = hex::encode(bob_balance_bytes.clone().to_xdr(&self.env).iter().collect::<Vec<u8>>());

        println!("\n📋 Generate withdrawal proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-withdrawal --key-name bob --amount {} --current-encrypted-balance {}", withdrawal_amount, bob_balance_hex);
        println!();

        // Get withdrawal proof file path
        let withdrawal_file = self.read_file_path("Enter path to Bob's withdrawal proof file", ".keys/bob_withdrawal.json");
        
        // Load withdrawal data
        let withdrawal_data: WithdrawalData = if let Some(data) = self.load_proof_from_file(&withdrawal_file) {
            println!("✅ Loaded withdrawal proof from: {}", withdrawal_file);
            data
        } else {
            println!("❌ Failed to load withdrawal proof. Please check the file and restart.");
            return;
        };

        // Convert hex data to contract types
        let withdrawal_proof = self.hex_to_withdrawal_proof(&withdrawal_data.proof.proof_hex);
        let bob_new_balance_after_withdrawal = self.hex_to_balance_bytes(&withdrawal_data.proof.new_balance_hex);

        // Execute withdrawal with timing
        self.time_operation("withdraw", || {
            self.token.as_ref().unwrap().withdraw(
                self.bob.as_ref().unwrap(),
                &withdrawal_data.withdrawal_amount,
                &bob_new_balance_after_withdrawal,
                &withdrawal_proof,
            );
        });

        println!("\n✅ Withdrawal completed!");
        println!("   {} CDT moved from confidential to transparent", withdrawal_data.withdrawal_amount);
        println!("   Bob's new confidential balance: {} CDT", withdrawal_data.new_balance);
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        let alice_transparent = self.token.as_ref().unwrap().balance(self.alice.as_ref().unwrap());
        let bob_transparent_final = self.token.as_ref().unwrap().balance(self.bob.as_ref().unwrap());
        
        self.print_state_diagram(
            "FINAL STATE AFTER WITHDRAWAL",
            alice_transparent,
            (alice_deposit - transfer_amount) as u128,  // Alice's remaining confidential
            0,
            0,
            bob_transparent_final,
            withdrawal_data.new_balance as u128,
            0,
            0,
            (alice_deposit - transfer_amount) as u128 + withdrawal_data.new_balance as u128,
        );

        println!("\n📊 FINAL ACCOUNTING:");
        println!("   Alice: {} transparent + {} confidential = {} total", alice_transparent, alice_deposit - transfer_amount, alice_transparent + (alice_deposit - transfer_amount) as i128);
        println!("   Bob:   {} transparent + {} confidential = {} total", bob_transparent_final, withdrawal_data.new_balance, bob_transparent_final + withdrawal_data.new_balance as i128);
        println!("   Total: {} CDT (original mint amount preserved)", alice_transparent + bob_transparent_final + (alice_deposit - transfer_amount) as i128 + withdrawal_data.new_balance as i128);
        println!("   Confidential Supply: {} CDT", (alice_deposit - transfer_amount) + withdrawal_data.new_balance);
        
        self.pause();
    }

    pub fn run_full_demo(&mut self) {
        self.step_1_create_token();
        self.step_2_create_accounts();
        self.step_3_load_keys();
        self.step_4_register_token();
        self.step_5_register_accounts();
        self.step_6_mint_tokens();
        let (alice_deposit, bob_deposit) = self.step_7_deposit_confidential();
        let alice_balance = self.step_8_alice_rollover(alice_deposit, bob_deposit);
        let (transfer_amount, alice_new_balance, amount_alice, amount_bob, amount_auditor) = 
            self.step_9_confidential_transfer(alice_balance, alice_deposit, alice_deposit, bob_deposit);
        self.step_10_decrypt_amounts(transfer_amount, &amount_alice, &amount_bob, &amount_auditor, &alice_new_balance);
        let bob_balance = self.step_11_bob_rollover(bob_deposit, transfer_amount, alice_deposit);
        self.step_12_withdraw(bob_balance, bob_deposit + transfer_amount, alice_deposit, transfer_amount);

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    DEMO COMPLETED SUCCESSFULLY!                   ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!("\nYou've successfully demonstrated:");
        println!("  ✅ Token creation and registration");
        println!("  ✅ Account setup with encryption keys (loaded from client)");
        println!("  ✅ Transparent to confidential deposits");
        println!("  ✅ Pending balance rollovers (using client-generated proofs)");
        println!("  ✅ Confidential transfers with zero-knowledge proofs (client-generated)");
        println!("  ✅ Amount decryption by authorized parties (off-chain)");
        println!("  ✅ Confidential to transparent withdrawals");
        println!("Thank you for exploring Stellar Confidential Transfers! 🚀\n");
    }
}