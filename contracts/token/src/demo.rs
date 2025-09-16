#![cfg(feature = "demo")]
extern crate std;

use crate::{
    contract::ConfidentialToken,
    utils::{read_account_confidential_ext, read_token_confidential_ext},
    ConfidentialTokenClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, IntoVal};
use stellar_confidential_crypto::{
    proof::CompressedPubkeyBytes,
    ConfidentialAmountBytes, ConfidentialBalanceBytes,
};
use std::{process::abort, time::Instant};
use token_client::{
    FileManager, IOManager
};
use serde::Serialize;
use chrono::Local;

#[derive(Serialize)]
struct ObserverState {
    pub timestamp: String,
    pub total_confidential_supply: u128,
    pub alice_transparent: i128,
    #[serde(skip)]
    pub alice_available: ConfidentialBalanceBytes,
    pub alice_available_hex: String,
    #[serde(skip)]
    pub alice_pending: ConfidentialAmountBytes,
    pub alice_pending_hex: String,
    pub alice_counter: u32,
    pub bob_transparent: i128,
    #[serde(skip)]
    pub bob_available: ConfidentialBalanceBytes,
    pub bob_available_hex: String,
    #[serde(skip)]
    pub bob_pending: ConfidentialAmountBytes,
    pub bob_pending_hex: String,
    pub bob_counter: u32,
    #[serde(skip)]
    pub observation_file: String,
}

impl ObserverState {
    pub fn new(env: &Env, data_dir: &str) -> Self {
        // Initialize observation file path in the same directory as file_manager
        let observation_file = format!("{}/observation_state.json", data_dir);

        let state = Self {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            total_confidential_supply: 0,
            alice_transparent: 0,
            alice_available: ConfidentialBalanceBytes::zero(env),
            alice_available_hex: "0x0".to_string(),
            alice_pending: ConfidentialAmountBytes::zero(env),
            alice_pending_hex: "0x0".to_string(),
            alice_counter: 0,
            bob_transparent: 0,
            bob_available: ConfidentialBalanceBytes::zero(env),
            bob_available_hex: "0x0".to_string(),
            bob_pending: ConfidentialAmountBytes::zero(env),
            bob_pending_hex: "0x0".to_string(),
            bob_counter: 0,
            observation_file,
        };

        // Save initial state
        state.save_to_file();
        state
    }

    fn save_to_file(&self) {
        if let Ok(json_str) = serde_json::to_string_pretty(&self) {
            if let Err(e) = std::fs::write(&self.observation_file, json_str) {
                println!("⚠️  Failed to save observation: {}", e);
            } else {
                println!("💾 Observation saved to: {}", self.observation_file);
            }
        }
    }
}

impl ObserverState {
    pub fn print_state_diagram(&self, _env: &Env, title: &str) {
        println!("\n═══════════════════════════════════════════════════════════════════════════════════════");
        println!(" {:^87}", title);
        println!("═══════════════════════════════════════════════════════════════════════════════════════");
        println!();
        println!("                       ┌───────────────────────────────────────┐");
        println!("                       │               TOKEN STATE             │");
        println!("                       │  Total Confidential supply:  {:>8} │", self.total_confidential_supply);
        println!("                       └───────────────────────────────────────┘");
        println!();
        println!("  ┌───────────────────────────────────┐          ┌───────────────────────────────────┐");
        println!("  │               ALICE               │          │                  BOB              │");
        println!("  │ ┌───────────────────────────────┐ │          │ ┌───────────────────────────────┐ │");
        println!("  │ │ Transparent: {:>16} │ │          │ │ Transparent: {:>16} │ │", self.alice_transparent, self.bob_transparent);
        println!("  │ │ Available:   {:>#16.12} │ │          │ │ Available:   {:>#16.12} │ │", self.alice_available, self.bob_available);
        println!("  │ │ Pending:     {:>#16.12} │ │          │ │ Pending:     {:>#16.12} │ │", self.alice_pending, self.bob_pending);
        println!("  │ │ Counter:     {:>16} │ │          │ │ Counter:     {:>16} │ │", self.alice_counter, self.bob_counter);
        println!("  │ └───────────────────────────────┘ │          │ └───────────────────────────────┘ │");
        println!("  └───────────────────────────────────┘          └───────────────────────────────────┘");
        println!("═══════════════════════════════════════════════════════════════════════════════════════");

        // Print events
        // println!("\n📅 EVENTS:");
        // println!("───────────────────────────────────────────────────────────────────────────────────────");
        // let events = env.events().all();
        // if events.is_empty() {
        //     println!("  No events recorded");
        // } else {
        //     for (i, event) in events.iter().enumerate() {
        //         println!("  {}. {:?}", i + 1, event);
        //     }
        // }
        // println!("═══════════════════════════════════════════════════════════════════════════════════════");
    }
}

#[test]
fn test_diagram() {
    let env = Env::default();
    let os = ObserverState::new(&env, ".data");
    os.print_state_diagram(&env, "TEST PRINT");
}

#[test]
fn test_events_capture() {
    let env = Env::default();
    env.mock_all_auths();

    // Create a token and perform some operations
    let admin = Address::generate(&env);
    let alice = Address::generate(&env);

    let token_contract = env.register(
        ConfidentialToken,
        (&admin, 7u32, soroban_sdk::String::from_str(&env, "Test Token"), soroban_sdk::String::from_str(&env, "TEST"))
    );

    let token = ConfidentialTokenClient::new(&env, &token_contract);

    // Perform a mint operation to generate an event
    token.mint(&alice, &1000i128);

    // Check events
    println!("Testing event capture...");
    let events = env.events().all();
    println!("Number of events captured: {}", events.len());
    for (i, event) in events.iter().enumerate() {
        println!("Event {}: {:?}", i + 1, event);
    }

    let os = ObserverState::new(&env, ".data");
    os.print_state_diagram(&env, "TEST WITH EVENTS");
}

pub struct DemoState {
    env: Env,
    token: ConfidentialTokenClient<'static>,
    _admin: Address,
    alice: Address,
    bob: Address,
    alice_encryption_key: Option<CompressedPubkeyBytes>,
    bob_encryption_key: Option<CompressedPubkeyBytes>,
    auditor_encryption_key: Option<CompressedPubkeyBytes>,
    file_manager: FileManager,
    io_manager: IOManager,
    observer_state: ObserverState
}

// mod confidential_token_contract {
//     soroban_sdk::contractimport!(file = "opt/confidential_token.wasm");
// }

impl DemoState {
    pub fn new(data_dir: &str) -> Self {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║     STELLAR CONFIDENTIAL TOKEN - INTERACTIVE DEMO                 ║");
        println!("║                                                                    ║");
        println!("║   🖥️  Terminal 1: Run client for key generation & proof creation  ║");
        println!("║   🖥️  Terminal 2: Run demo contract (locally)                     ║");
        println!("║                                                                    ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        println!("Creating a confidential token and accounts (admin, alice, bob)...\n");

        let file_manager = FileManager::new(data_dir).unwrap();
        let io_manager = IOManager::new();

        // Get user input for token parameters
        let name_input = io_manager.read_user_input("Enter token name [default: Confidential Demo Token]");
        let name = if name_input.is_empty() { "Confidential Demo Token" } else { &name_input };

        let symbol_input = io_manager.read_user_input("Enter token symbol [default: CDT]");
        let symbol = if symbol_input.is_empty() { "CDT" } else { &symbol_input };

        let decimals = io_manager.read_u32("Enter token decimals", 7);

        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);

        // TODO: swap with confidential_token_contract::Client to run Wasm contract
        let token_contract = env.register(
            ConfidentialToken,
            (
                &admin,
                decimals,
                soroban_sdk::String::from_str(&env, name),
                soroban_sdk::String::from_str(&env, symbol),
            ),
        );
        let token = ConfidentialTokenClient::new(&env, &token_contract);
        println!("\n✅ Token created successfully!");
        println!("   Name: {}", name);
        println!("   Symbol: {}", symbol);
        println!("   Decimals: {}", decimals);
        println!("   Admin: {:?}", admin);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        println!("✅ Accounts created:");
        println!("   Alice: {:?}", alice);
        println!("   Bob:   {:?}", bob);

        Self {
            env: env.clone(),
            token,
            _admin: admin,
            alice,
            bob,
            alice_encryption_key: None,
            bob_encryption_key: None,
            auditor_encryption_key: None,
            file_manager,
            io_manager,
            observer_state: ObserverState::new(&env, data_dir)
        }
    }

    pub fn update_observation(&mut self) {
        // Update timestamp
        self.observer_state.timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // Update transparent balances
        self.observer_state.alice_transparent = self.token.balance(&self.alice);
        self.observer_state.bob_transparent = self.token.balance(&self.bob);

        // Update confidential balances and counters from contract storage in one call
        self.env.as_contract(&self.token.address, || {
            let alice_ext = read_account_confidential_ext(&self.env, self.alice.clone());
            let bob_ext = read_account_confidential_ext(&self.env, self.bob.clone());

            self.observer_state.alice_available_hex = format!("{}", alice_ext.available_balance);
            self.observer_state.alice_pending_hex = format!("{}", alice_ext.pending_balance);
            self.observer_state.bob_available_hex = format!("{}", bob_ext.available_balance);
            self.observer_state.bob_pending_hex = format!("{}", bob_ext.pending_balance);

            self.observer_state.alice_available = alice_ext.available_balance;
            self.observer_state.alice_pending = alice_ext.pending_balance;
            self.observer_state.alice_counter = alice_ext.pending_counter;

            self.observer_state.bob_available = bob_ext.available_balance;
            self.observer_state.bob_pending = bob_ext.pending_balance;
            self.observer_state.bob_counter = bob_ext.pending_counter;

            // Read total confidential supply from token extension
            let token_ext = read_token_confidential_ext(&self.env);
            self.observer_state.total_confidential_supply = token_ext.total_confidential_supply;
        });

        // Save updated observation to the same file
        self.observer_state.save_to_file();
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

    pub fn step_1_setup(&mut self) {
        println!("\n🔑 STEP 1: Setup Keys and Confidential Token Extension");
        println!("Setting up encryption keys and registering token/accounts...\n");

        println!("📋 Generate all keys (alice, bob, auditor) first using client (in Terminal 1):");
        println!("───────────────────────────────────────────────────────────────────────────────");
        println!("conf-token-client key-gen --seed 12345 --name alice && \\");
        println!("conf-token-client key-gen --seed 67890 --name bob && \\");
        println!("conf-token-client key-gen --seed 99999 --name auditor");
        println!("───────────────────────────────────────────────────────────────────────────────");
        println!();

        println!("\n🔐 Loading encryption keys (alice, bob, auditor)...");
        self.io_manager.pause();

        // Load Alice's encryption key
        match self.file_manager.load_encryption_pubkey("alice") {
            Ok(alice_key) => {
                self.alice_encryption_key = Some(alice_key.into_val(&self.env));
                println!("✅ Alice's encryption key loaded");
            }
            Err(e) => {
                println!("❌ Failed to load Alice's encryption key: {}", e);
                println!("   Make sure you've run the key generation commands above!");
                abort();
            }
        }

        // Load Bob's encryption key
        match self.file_manager.load_encryption_pubkey("bob") {
            Ok(bob_key) => {
                self.bob_encryption_key = Some(bob_key.into_val(&self.env));
                println!("✅ Bob's encryption key loaded");
            }
            Err(e) => {
                println!("❌ Failed to load Bob's encryption key: {}", e);
                println!("   Make sure you've run the key generation commands above!");
                abort();
            }
        }

        // Load Auditor's encryption key
        match self.file_manager.load_encryption_pubkey("auditor") {
            Ok(auditor_key) => {
                self.auditor_encryption_key = Some(auditor_key.into_val(&self.env));
                println!("✅ Auditor's encryption key loaded");
            }
            Err(e) => {
                println!("❌ Failed to load Auditor's encryption key: {}", e);
                println!("   Make sure you've run the key generation commands above!");
                abort();
            }
        }

        println!("\n🔐 Registering Confidential Token Extension");
        self.token.register_confidential_token(self.auditor_encryption_key.as_ref().unwrap());

        println!("👤 Registering user accounts...");
        self.token.register_account(&self.alice, self.alice_encryption_key.as_ref().unwrap());
        self.token.register_account(&self.bob, self.bob_encryption_key.as_ref().unwrap());

        self.io_manager.pause();

        println!("\n✅ Setup completed successfully!");
        println!("   - Keys loaded from client-generated files");
        println!("   - Token registered with auditor key: {}", self.auditor_encryption_key.as_ref().unwrap());
        println!("   - 📝 Note: The auditor can decrypt all transfer amounts for regulatory compliance");
        println!("   - Token authorized Alice as a user. Alice's encryption key: {}", self.alice_encryption_key.as_ref().unwrap());
        println!("   - Token authorized Bob as a user. Bob's encryption key: {}", self.bob_encryption_key.as_ref().unwrap());

        self.io_manager.pause();
    }

    pub fn step_2_mint_tokens(&mut self) {
        println!("\n💰 STEP 2: Mint Tokens (Transparent Balance)");
        println!("Minting initial tokens to Alice and Bob...\n");
        
        // Get mint amounts from user input
        let alice_amount = self.io_manager.read_u64("Enter amount to mint for Alice", 1000) as i128;
        let bob_amount = self.io_manager.read_u64("Enter amount to mint for Bob", 500) as i128;

        self.token.mint(&self.alice, &alice_amount);
        self.token.mint(&self.bob, &bob_amount);

        println!("✅ Tokens minted:");
        println!("   Alice: {} CDT (transparent)", alice_amount);
        println!("   Bob:   {} CDT (transparent)", bob_amount);
        println!("\n📝 Note: These are regular transparent tokens,");
        println!("   visible on the blockchain");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "STATE AFTER MINTING");
        
        self.io_manager.pause();
    }

    pub fn step_3_deposit_confidential(&mut self) {
        println!("\n🔒 STEP 3: Deposit to Confidential Balance");
        println!("Moving tokens from transparent to confidential pending balance...\n");

        // Get deposit amounts from user input
        let alice_deposit = self.io_manager.read_u64("Enter amount for Alice to deposit to confidential", 500);
        let bob_deposit = self.io_manager.read_u64("Enter amount for Bob to deposit to confidential", 250);

        println!("Alice deposits {} CDT to confidential", alice_deposit);
        self.token.deposit(&self.alice, &alice_deposit);

        println!("Bob deposits {} CDT to confidential", bob_deposit);
        self.token.deposit(&self.bob, &bob_deposit);

        println!("\n✅ Deposits completed!");
        println!("   Tokens moved to pending confidential balance");
        println!("   (Need rollover to make them available for transfer)");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "STATE AFTER DEPOSITS");
        
        self.io_manager.pause();
    }

    pub fn step_4_alice_rollover(&mut self) {
        println!("\n🔄 STEP 4: Alice Rollover (Pending → Available)");
        println!("Alice moves her pending balance to available balance...\n");

        // Get Alice's current available and pending balances from the contract
        let alice_ext = self.token.get_account_confidential_ext(&self.alice);
        let alice_available_balance = alice_ext.available_balance;
        let alice_pending_balance = alice_ext.pending_balance;

        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: conf-token-client generate-rollover --key-name alice --available-balance {} --pending-balance {}", alice_available_balance, alice_pending_balance);
        println!();

        // Get rollover proof filename
        let rollover_file = self.io_manager.read_file_path("Enter Alice's rollover proof filename", "alice_rollover_HH-MM-SS.json");

        // Load Alice's rollover data (returns tuple of proof and balance)
        let (alice_rollover_proof_cli, alice_new_balance_cli) = match self.file_manager.load_rollover_proof_data(&rollover_file) {
            Ok(data) => {
                println!("✅ Loaded Alice's rollover proof from: {}", rollover_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load rollover proof: {}", e);
                return;
            }
        };

        // Convert CLI types to contract types
        let alice_rollover_proof = alice_rollover_proof_cli.into_val(&self.env);
        let alice_new_balance_bytes = alice_new_balance_cli.into_val(&self.env);

        // Execute rollover with timing
        self.time_operation("rollover_pending_balance", || {
            self.token.rollover_pending_balance(
                &self.alice,
                &alice_new_balance_bytes,
                &alice_rollover_proof,
            );
        });

        println!("\n✅ Rollover completed!");
        println!("   Alice's pending balance now available for confidential transfers");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "STATE AFTER ALICE'S ROLLOVER");
        
        self.io_manager.pause();
    }

    pub fn step_5_confidential_transfer(&mut self) {
        println!("\n💸 STEP 5: Confidential Transfer (Alice → Bob)");
        println!("Alice transfers tokens to Bob confidentially...\n");

        let alice_available_balance = self.token.get_account_confidential_ext(&self.alice).available_balance;
        println!("📋 Generate transfer proof first using client (replace $AMT with the actual amount):");
        println!("   Terminal 1: conf-token-client generate-transfer --from-key alice --to-key bob --auditor-key auditor --amount $AMT --current-encrypted-balance {}", alice_available_balance);
        println!();

        // Get transfer proof filename
        let transfer_file = self.io_manager.read_file_path("Enter transfer proof filename", "alice-bob_transfer_HH-MM-SS.json");

        // Load transfer data (returns tuple)
        let (transfer_proof_cli, alice_balance_after_transfer_cli, amount_for_alice_cli, amount_for_bob_cli, amount_for_auditor_cli) =
            match self.file_manager.load_transfer_proof_data(&transfer_file) {
                Ok(data) => {
                    println!("✅ Loaded transfer proof from: {}", transfer_file);
                    data
                }
                Err(e) => {
                    println!("❌ Failed to load transfer proof: {}", e);
                    abort();
                }
            };

        // Convert CLI types to contract types
        let transfer_proof = transfer_proof_cli.into_val(&self.env);
        let alice_balance_after_transfer = alice_balance_after_transfer_cli.into_val(&self.env);
        let amount_for_alice = amount_for_alice_cli.into_val(&self.env);
        let amount_for_bob = amount_for_bob_cli.into_val(&self.env);
        let amount_for_auditor = amount_for_auditor_cli.into_val(&self.env);

        println!("📤 Executing confidential transfer using client-generated proof...");
        self.token.confidential_transfer(
            &self.alice,
            &self.bob,
            &amount_for_alice,
            &amount_for_bob,
            &amount_for_auditor,
            &alice_balance_after_transfer,
            &transfer_proof,
        );

        println!("\n✅ Transfer completed!");
        println!("   Transfer executed successfully");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "STATE AFTER CONFIDENTIAL TRANSFER");
        
        self.io_manager.pause();
    }

    pub fn step_6_bob_rollover(&mut self) {
        println!("\n🔄 STEP 6: Bob Rollover (Pending → Available)");
        println!("Bob moves his total pending balance to available...\n");

        println!("Processing Bob's rollover...");

        // Get Bob's current available and pending balances from the contract
        let bob_ext = self.token.get_account_confidential_ext(&self.bob);
        let bob_available_balance = bob_ext.available_balance;
        let bob_pending_balance = bob_ext.pending_balance;
        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: conf-token-client generate-rollover --key-name bob --available-balance {} --pending-balance {}", bob_available_balance, bob_pending_balance);
        println!();

        // Get rollover proof filename
        let rollover_file = self.io_manager.read_file_path("Enter Bob's rollover proof filename", "bob_rollover_HH-MM-SS.json");

        // Load Bob's rollover data (returns tuple)
        let (bob_rollover_proof_cli, bob_new_balance_cli) = match self.file_manager.load_rollover_proof_data(&rollover_file) {
            Ok(data) => {
                println!("✅ Loaded Bob's rollover proof from: {}", rollover_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load rollover proof: {}", e);
                abort();
            }
        };

        // Convert CLI types to contract types
        let bob_rollover_proof = bob_rollover_proof_cli.into_val(&self.env);
        let bob_new_balance_bytes = bob_new_balance_cli.into_val(&self.env);

        // Execute rollover with timing
        self.time_operation("rollover_pending_balance", || {
            self.token.rollover_pending_balance(
                &self.bob,
                &bob_new_balance_bytes,
                &bob_rollover_proof,
            );
        });

        println!("\n✅ Rollover completed!");
        println!("   Bob's pending balance now available for confidential transfers");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "STATE AFTER BOB'S ROLLOVER");
        
        self.io_manager.pause();
    }

    pub fn step_7_withdraw(&mut self) {
        println!("\n💵 STEP 7: Withdraw (Confidential → Transparent)");
        println!("Bob withdraws from confidential to transparent...\n");
        
        // Get withdrawal amount from user input
        let withdrawal_amount = self.io_manager.read_u64("Enter amount for Bob to withdraw", 100);
        let bob_available_balance = self.token.get_account_confidential_ext(&self.bob).available_balance;
        println!("\n📋 Generate withdrawal proof first using client:");
        println!("   Terminal 1: conf-token-client generate-withdrawal --key-name bob --amount {} --current-encrypted-balance {}", withdrawal_amount, bob_available_balance);
        println!();

        // Get withdrawal proof filename
        let withdrawal_file = self.io_manager.read_file_path("Enter Bob's withdrawal proof filename", "bob_withdrawal_HH-MM-SS.json");

        // Load withdrawal data (returns tuple)
        let (withdrawal_proof_cli, bob_new_balance_after_withdrawal_cli) = match self.file_manager.load_withdrawal_proof_data(&withdrawal_file) {
            Ok(data) => {
                println!("✅ Loaded withdrawal proof from: {}", withdrawal_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load withdrawal proof: {}", e);
                abort();
            }
        };

        // Convert CLI types to contract types
        let withdrawal_proof = withdrawal_proof_cli.into_val(&self.env);
        let bob_new_balance_after_withdrawal = bob_new_balance_after_withdrawal_cli.into_val(&self.env);

        // Execute withdrawal with timing
        self.time_operation("withdraw", || {
            self.token.withdraw(
                &self.bob,
                &withdrawal_amount,  // Using the input amount directly
                &bob_new_balance_after_withdrawal,
                &withdrawal_proof,
            );
        });

        println!("\n✅ Withdrawal completed!");
        println!("   {} CDT moved from confidential to transparent", withdrawal_amount);
        println!("   Withdrawal processed successfully");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram(&self.env, "FINAL STATE AFTER WITHDRAWAL");

        println!("\n📊 FINAL ACCOUNTING:");
        println!("   All balances are shown in the state diagram above");
        println!("   Transparent balances are exact values");
        println!("   Confidential balances are encrypted and shown as hex truncations");
        
        self.io_manager.pause();
    }

    pub fn run_full_demo(&mut self) {
        self.step_1_setup();
        self.step_2_mint_tokens();
        self.step_3_deposit_confidential();
        self.step_4_alice_rollover();
        self.step_5_confidential_transfer();
        self.step_6_bob_rollover();
        self.step_7_withdraw();

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    DEMO COMPLETED SUCCESSFULLY!                   ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!("\nYou've successfully demonstrated:");
        println!("  ✅ Token creation and registration");
        println!("  ✅ Account setup with encryption keys (loaded from client)");
        println!("  ✅ Deposits (transparent → pending)");
        println!("  ✅ Pending balance rollovers (pending → available)");
        println!("  ✅ Confidential transfers with zero-knowledge proofs");
        println!("  ✅ Amount decryption by authorized parties (off-chain)");
        println!("  ✅ Withdrawals (available → transparent)");
        println!("Thank you for exploring Stellar Confidential Transfers! 🚀\n");
    }
}