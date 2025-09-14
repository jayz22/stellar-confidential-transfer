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
use std::time::Instant;
use token_client::{
    FileManager, IOManager
};
// Helper functions to display encrypted types as truncated hex
fn display_compressed_pubkey(pubkey: &CompressedPubkeyBytes, max_len: Option<usize>) -> String {
    let hex = hex::encode(pubkey.0.to_array());
    match max_len {
        Some(len) if hex.len() > len => format!("{}...", &hex[..len]),
        _ => hex,
    }
}

fn display_confidential_balance(balance: &ConfidentialBalanceBytes, max_len: Option<usize>) -> String {
    let hex = hex::encode(balance.0.to_array());
    match max_len {
        Some(len) if hex.len() > len => format!("{}...", &hex[..len]),
        _ => hex,
    }
}

fn display_confidential_amount(amount: &ConfidentialAmountBytes, max_len: Option<usize>) -> String {
    let hex = hex::encode(amount.0.to_array());
    match max_len {
        Some(len) if hex.len() > len => format!("{}...", &hex[..len]),
        _ => hex,
    }
}

struct ObserverState {
    pub total_confidential_supply: u128,
    pub alice_transparent: i128,
    pub alice_available: ConfidentialBalanceBytes,
    pub alice_pending: ConfidentialAmountBytes,
    pub alice_counter: u32,
    pub bob_transparent: i128,
    pub bob_available: ConfidentialBalanceBytes,
    pub bob_pending: ConfidentialAmountBytes,
    pub bob_counter: u32,
}

impl Default for ObserverState {
    fn default() -> Self {
        let env = Env::default();
        Self {
            total_confidential_supply: 0,
            alice_transparent: 0,
            alice_available: ConfidentialBalanceBytes::zero(&env),
            alice_pending: ConfidentialAmountBytes::zero(&env),
            alice_counter: 0,
            bob_transparent: 0,
            bob_available: ConfidentialBalanceBytes::zero(&env),
            bob_pending: ConfidentialAmountBytes::zero(&env),
            bob_counter: 0,
        }
    }
}

impl ObserverState {

    pub fn print_state_diagram(&self, title: &str) {
        println!("\n═══════════════════════════════════════════════════════════════════");
        println!(" {}", title);
        println!("═══════════════════════════════════════════════════════════════════");
        println!();
        println!("                   ┌─────────────────────────────────┐");
        println!("                   │         TOKEN STATE             │");
        println!("                   │  Total Confidential supply:  {:>8} │", self.total_confidential_supply);
        println!("                   └─────────────────────────────────┘");
        println!();
        println!("  ┌─────────────────────────────┐          ┌─────────────────────────────┐");
        println!("  │           ALICE             │          │            BOB              │");
        println!("  │ ┌─────────────────────────┐ │          │ ┌─────────────────────────┐ │");
        println!("  │ │ Transparent: {:>15} │ │          │ │ Transparent: {:>15} │ │", self.alice_transparent, self.bob_transparent);
        println!("  │ │ Available:   {:>15} │ │          │ │ Available:   {:>15} │ │", display_confidential_balance(&self.alice_available, Some(12)), display_confidential_balance(&self.bob_available, Some(12)));
        println!("  │ │ Pending:     {:>15} │ │          │ │ Pending:     {:>15} │ │", display_confidential_amount(&self.alice_pending, Some(12)), display_confidential_amount(&self.bob_pending, Some(12)));
        println!("  │ │ Counter:     {:>15} │ │          │ │ Counter:     {:>15} │ │", self.alice_counter, self.bob_counter);
        println!("  │ └─────────────────────────┘ │          │ └─────────────────────────┘ │");
        println!("  └─────────────────────────────┘          └─────────────────────────────┘");
        println!("═══════════════════════════════════════════════════════════════════");
    }
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
            file_manager: FileManager::new(data_dir),
            io_manager,
            observer_state: ObserverState::default()
        }
    }

    pub fn update_observation(&mut self) {
        // Update transparent balances
        self.observer_state.alice_transparent = self.token.balance(&self.alice);
        self.observer_state.bob_transparent = self.token.balance(&self.bob);

        // Update confidential balances and counters from contract storage in one call
        self.env.as_contract(&self.token.address, || {
            let alice_ext = read_account_confidential_ext(&self.env, self.alice.clone());
            let bob_ext = read_account_confidential_ext(&self.env, self.bob.clone());

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

    pub fn step_1_load_keys(&mut self) {
        println!("\n🔑 STEP 1: Load Cryptographic Keys");
        println!("Loading encryption keys from client-generated files...\n");

        println!("📋 Generate keys first using client:");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 12345 --name alice");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 67890 --name bob");
        println!("   Terminal 1: cargo run --bin client -- key-gen --seed 99999 --name auditor");
        println!();

        // Load Alice's encryption key
        let alice_file = self.io_manager.read_file_path("Enter Alice's key file name", "alice");
        match self.file_manager.load_encryption_pubkey(&alice_file) {
            Ok(alice_key) => {
                self.alice_encryption_key = Some(alice_key.into_val(&self.env));
                println!("✅ Alice's encryption key loaded from: {}_encryption_pubkey.json", alice_file);
            }
            Err(e) => {
                println!("❌ Failed to load Alice's encryption key: {}", e);
                return;
            }
        }

        // Load Bob's encryption key
        let bob_file = self.io_manager.read_file_path("Enter Bob's key file name", "bob");
        match self.file_manager.load_encryption_pubkey(&bob_file) {
            Ok(bob_key) => {
                self.bob_encryption_key = Some(bob_key.into_val(&self.env));
                println!("✅ Bob's encryption key loaded from: {}_encryption_pubkey.json", bob_file);
            }
            Err(e) => {
                println!("❌ Failed to load Bob's encryption key: {}", e);
                return;
            }
        }

        // Load Auditor's encryption key
        let auditor_file = self.io_manager.read_file_path("Enter Auditor's key file name", "auditor");
        match self.file_manager.load_encryption_pubkey(&auditor_file) {
            Ok(auditor_key) => {
                self.auditor_encryption_key = Some(auditor_key.into_val(&self.env));
                println!("✅ Auditor's encryption key loaded from: {}_encryption_pubkey.json", auditor_file);
            }
            Err(e) => {
                println!("❌ Failed to load Auditor's encryption key: {}", e);
                return;
            }
        }
        
        println!("\n📝 Note: All keys successfully loaded!");
        println!("   Off-chain: Keys generated by client");
        println!("   On-chain: Keys loaded by demo contract");
        
        self.io_manager.pause();
    }

    pub fn step_2_register_token(&mut self) {
        println!("\n🔐 STEP 4: Register Confidential Token Extension");
        println!("Registering the token for confidential transfers with auditor...\n");
        self.token.register_confidential_token(self.auditor_encryption_key.as_ref().unwrap());

        println!("\n✅ Token registered for confidential transfers!");
        println!("   Auditor public key registered {}", display_compressed_pubkey(self.auditor_encryption_key.as_ref().unwrap(), None));
        println!("   Confidential extension enabled");
        println!("\n📝 Note: The auditor can decrypt all transfer amounts");
        println!("   for regulatory compliance");
        
        self.io_manager.pause();
    }

    pub fn step_5_register_accounts(&mut self) {
        println!("\n👤 STEP 5: Register User Accounts for Confidential Transfers");
        println!("Registering Alice and Bob's accounts...\n");

        self.token.register_account(&self.alice, self.alice_encryption_key.as_ref().unwrap());
        self.token.register_account(&self.bob, self.bob_encryption_key.as_ref().unwrap());

        println!("\n✅ Accounts registered:");
        println!("   - Alice's encryption key registered");
        println!("   - Bob's encryption key registered");
        println!("   Both can now receive confidential transfers");
        
        self.io_manager.pause();
    }

    pub fn step_6_mint_tokens(&mut self) {
        println!("\n💰 STEP 6: Mint Tokens (Transparent Balance)");
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
        self.observer_state.print_state_diagram("STATE AFTER MINTING");
        
        self.io_manager.pause();
    }

    pub fn step_7_deposit_confidential(&mut self) -> (u64, u64) {
        println!("\n🔒 STEP 7: Deposit to Confidential Balance");
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
        self.observer_state.print_state_diagram("STATE AFTER DEPOSITS");
        
        self.io_manager.pause();
        (alice_deposit, bob_deposit)
    }

    pub fn step_8_alice_rollover(&mut self) -> ConfidentialBalanceBytes {
        println!("\n🔄 STEP 8: Alice Rollover (Pending → Available)");
        println!("Alice moves her pending balance to available balance...\n");

        // Get Alice's current available and pending balances from the contract
        let alice_available_balance = self.env.as_contract(&self.token.address, || {
            let ext = read_account_confidential_ext(&self.env, self.alice.clone());
            ext.available_balance
        });
        let alice_pending_balance = self.env.as_contract(&self.token.address, || {
            let ext = read_account_confidential_ext(&self.env, self.alice.clone());
            ext.pending_balance
        });

        // Convert to hex for the client command
        let available_balance_hex = display_confidential_balance(&alice_available_balance, None);
        let pending_balance_hex = display_confidential_amount(&alice_pending_balance, None);

        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-rollover --key-name alice --available-balance {} --pending-balance {}", available_balance_hex, pending_balance_hex);
        println!();

        // Get rollover proof file path
        let rollover_file = self.io_manager.read_file_path("Enter path to Alice's rollover proof file", ".data/alice_rollover_HH-MM-SS.json");

        // Load Alice's rollover data (returns tuple of proof and balance)
        let (alice_rollover_proof_cli, alice_new_balance_cli) = match self.file_manager.load_rollover_proof_data(&rollover_file) {
            Ok(data) => {
                println!("✅ Loaded Alice's rollover proof from: {}", rollover_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load rollover proof: {}", e);
                return ConfidentialBalanceBytes::zero(&self.env);
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
        // TODO: Figure out the proper balance amount from the proof data
        println!("   Alice's pending balance now available for confidential transfers");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram("STATE AFTER ALICE'S ROLLOVER");
        
        self.io_manager.pause();
        alice_new_balance_bytes
    }

    pub fn step_9_confidential_transfer(&mut self, alice_balance_bytes: ConfidentialBalanceBytes, alice_available: u64) -> (u64, ConfidentialBalanceBytes, ConfidentialAmountBytes, ConfidentialAmountBytes, ConfidentialAmountBytes) {
        println!("\n💸 STEP 9: Confidential Transfer (Alice → Bob)");
        println!("Alice sends tokens to Bob confidentially...\n");
        println!("Alice's available balance: {} CDT", alice_available);
        
        // Convert alice_balance_bytes to hex for the client command
        let alice_balance_hex = display_confidential_balance(&alice_balance_bytes, None);
        
        println!("📋 Generate transfer proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-transfer --from-key alice --to-key bob --auditor-key auditor --amount 100 --current-encrypted-balance {}", alice_balance_hex);
        println!();

        // Get transfer proof file path
        let transfer_file = self.io_manager.read_file_path("Enter path to transfer proof file", ".data/alice-bob_transfer_HH-MM-SS.json");

        // Load transfer data (returns tuple)
        let (transfer_proof_cli, alice_balance_after_transfer_cli, amount_for_alice_cli, amount_for_bob_cli, amount_for_auditor_cli) =
            match self.file_manager.load_transfer_proof_data(&transfer_file) {
                Ok(data) => {
                    println!("✅ Loaded transfer proof from: {}", transfer_file);
                    data
                }
                Err(e) => {
                    println!("❌ Failed to load transfer proof: {}", e);
                    return (0, ConfidentialBalanceBytes::zero(&self.env), ConfidentialAmountBytes::zero(&self.env),
                           ConfidentialAmountBytes::zero(&self.env), ConfidentialAmountBytes::zero(&self.env));
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
        // println!("   Amount: {} CDT", transfer_data.transfer_amount);
        // println!("   From: Alice ({} CDT remaining)", transfer_data.alice_new_balance);
        // println!("   To: Bob (now has {} CDT pending)", bob_deposit + transfer_data.transfer_amount);
        // TODO: Figure out transfer amount and balances from proof data
        println!("   Transfer executed successfully");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram("STATE AFTER CONFIDENTIAL TRANSFER");
        
        self.io_manager.pause();
        // (transfer_data.transfer_amount, alice_balance_after_transfer, amount_for_alice, amount_for_bob, amount_for_auditor)
        (100, alice_balance_after_transfer, amount_for_alice, amount_for_bob, amount_for_auditor)  // TODO: Figure out actual transfer amount
    }

    pub fn step_11_bob_rollover(&mut self) -> ConfidentialBalanceBytes {
        println!("\n🔄 STEP 11: Bob Rollover (Pending → Available)");
        println!("Bob moves his total pending balance to available...\n");

        // let bob_total = bob_deposit + transfer_amount;
        // println!("Bob's total pending balance: {} CDT", bob_total);
        println!("Processing Bob's rollover...");

        // Get Bob's current available and pending balances from the contract
        let bob_available_balance = self.env.as_contract(&self.token.address, || {
            let ext = read_account_confidential_ext(&self.env, self.bob.clone());
            ext.available_balance
        });
        let bob_pending_balance = self.env.as_contract(&self.token.address, || {
            let ext = read_account_confidential_ext(&self.env, self.bob.clone());
            ext.pending_balance
        });

        // Convert to hex for the client command
        let available_balance_hex = display_confidential_balance(&bob_available_balance, None);
        let pending_balance_hex = display_confidential_amount(&bob_pending_balance, None);

        println!("📋 Generate rollover proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-rollover --key-name bob --available-balance {} --pending-balance {}", available_balance_hex, pending_balance_hex);
        println!();

        // Get rollover proof file path
        let rollover_file = self.io_manager.read_file_path("Enter path to Bob's rollover proof file", ".data/bob_rollover_HH-MM-SS.json");

        // Load Bob's rollover data (returns tuple)
        let (bob_rollover_proof_cli, bob_new_balance_cli) = match self.file_manager.load_rollover_proof_data(&rollover_file) {
            Ok(data) => {
                println!("✅ Loaded Bob's rollover proof from: {}", rollover_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load rollover proof: {}", e);
                return ConfidentialBalanceBytes::zero(&self.env);
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
        // println!("   Bob's {} CDT now available for confidential transfers", bob_rollover.balance_amount);
        // TODO: Figure out the proper balance amount from proof data
        println!("   Bob's pending balance now available for confidential transfers");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram("STATE AFTER BOB'S ROLLOVER");
        
        self.io_manager.pause();
        bob_new_balance_bytes
    }

    pub fn step_12_withdraw(&mut self, bob_balance_bytes: ConfidentialBalanceBytes, bob_available: u64) {
        println!("\n💵 STEP 12: Withdraw (Confidential → Transparent)");
        println!("Bob withdraws from confidential to transparent...\n");
        println!("Bob's available balance: {} CDT", bob_available);
        
        // Get withdrawal amount from user input
        let withdrawal_amount = self.io_manager.read_u64("Enter amount for Bob to withdraw", 100);

        // Convert bob_balance_bytes to hex for the client command
        let bob_balance_hex = display_confidential_balance(&bob_balance_bytes, None);

        println!("\n📋 Generate withdrawal proof first using client:");
        println!("   Terminal 1: cargo run --bin client -- generate-withdrawal --key-name bob --amount {} --current-encrypted-balance {}", withdrawal_amount, bob_balance_hex);
        println!();

        // Get withdrawal proof file path
        let withdrawal_file = self.io_manager.read_file_path("Enter path to Bob's withdrawal proof file", ".data/bob_withdrawal_HH-MM-SS.json");

        // Load withdrawal data (returns tuple)
        let (withdrawal_proof_cli, bob_new_balance_after_withdrawal_cli) = match self.file_manager.load_withdrawal_proof_data(&withdrawal_file) {
            Ok(data) => {
                println!("✅ Loaded withdrawal proof from: {}", withdrawal_file);
                data
            }
            Err(e) => {
                println!("❌ Failed to load withdrawal proof: {}", e);
                return;
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
        // println!("   Bob's new confidential balance: {} CDT", withdrawal_data.new_balance);
        // TODO: Figure out the new balance from proof data
        println!("   Withdrawal processed successfully");
        println!("   Off-chain: Proof generated by client");
        println!("   On-chain: Proof verified and executed by contract");

        // Update observer state
        self.update_observation();
        self.observer_state.print_state_diagram("FINAL STATE AFTER WITHDRAWAL");

        println!("\n📊 FINAL ACCOUNTING:");
        println!("   All balances are shown in the state diagram above");
        println!("   Transparent balances are exact values");
        println!("   Confidential balances are encrypted and shown as hex truncations");
        
        self.io_manager.pause();
    }

    pub fn run_full_demo(&mut self) {
        self.step_1_load_keys();
        self.step_2_register_token();
        self.step_5_register_accounts();
        self.step_6_mint_tokens();
        let (alice_deposit, bob_deposit) = self.step_7_deposit_confidential();
        let alice_balance = self.step_8_alice_rollover();
        let (transfer_amount, alice_new_balance, amount_alice, amount_bob, amount_auditor) =
            self.step_9_confidential_transfer(alice_balance, alice_deposit);
        let bob_balance = self.step_11_bob_rollover();
        self.step_12_withdraw(bob_balance, bob_deposit + transfer_amount);

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