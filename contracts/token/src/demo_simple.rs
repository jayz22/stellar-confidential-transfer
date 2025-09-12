#![cfg(feature = "demo")]
extern crate std;

use crate::{
    contract::ConfidentialToken,
    utils::read_account_confidential_ext,
    ConfidentialTokenClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String, BytesN, xdr::{FromXdr, ToXdr}};
use stellar_confidential_crypto::{
    proof::{
        CompressedPubkeyBytes, NewBalanceProofBytes, TransferProofBytes,
        NewBalanceSigmaProofBytes, TransferSigmaProofBytes, RangeProofBytes,
    },
    ConfidentialAmountBytes, ConfidentialBalanceBytes, RistrettoPoint, Scalar,
};
use std::io::{self, Write};
use std::fs;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Keep the original types from the existing demo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key_hex: std::string::String,
    pub public_key_hex: std::string::String,
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
        println!("║     STELLAR CONFIDENTIAL TOKEN - SIMPLE CLI DEMO                  ║");
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

    // Convert JSON back to contract types - much simpler than before
    fn json_to_pubkey(&self, json: &Value) -> Result<CompressedPubkeyBytes, String> {
        let hex = json.get("0")
            .and_then(|v| v.as_str())
            .ok_or("Missing '0' field in pubkey JSON")?;
        
        let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("Expected 32 bytes, got {}", bytes.len()));
        }
        
        let bytes_n = BytesN::<32>::from_array(&self.env, &bytes.try_into().unwrap());
        Ok(CompressedPubkeyBytes(bytes_n))
    }

    fn json_to_new_balance_proof(&self, json: &Value) -> Result<NewBalanceProofBytes, String> {
        let sigma = json.get("sigma_proof").ok_or("Missing sigma_proof")?;
        let xs_hex = sigma.get("xs").and_then(|v| v.as_str()).ok_or("Missing xs")?;
        let alphas_hex = sigma.get("alphas").and_then(|v| v.as_str()).ok_or("Missing alphas")?;
        
        let zkrp = json.get("zkrp_new_balance").ok_or("Missing zkrp_new_balance")?;
        let zkrp_hex = zkrp.get("0").and_then(|v| v.as_str()).ok_or("Missing zkrp bytes")?;
        
        let xs_bytes = hex::decode(xs_hex).map_err(|e| format!("Invalid xs hex: {}", e))?;
        let alphas_bytes = hex::decode(alphas_hex).map_err(|e| format!("Invalid alphas hex: {}", e))?;
        let zkrp_bytes = hex::decode(zkrp_hex).map_err(|e| format!("Invalid zkrp hex: {}", e))?;
        
        Ok(NewBalanceProofBytes {
            sigma_proof: NewBalanceSigmaProofBytes {
                xs: BytesN::<576>::from_array(&self.env, &xs_bytes.try_into().map_err(|_| "Invalid xs length")?),
                alphas: BytesN::<64>::from_array(&self.env, &alphas_bytes.try_into().map_err(|_| "Invalid alphas length")?),
            },
            zkrp_new_balance: RangeProofBytes(
                BytesN::<2272>::from_array(&self.env, &zkrp_bytes.try_into().map_err(|_| "Invalid zkrp length")?)
            ),
        })
    }

    fn json_to_transfer_proof(&self, json: &Value) -> Result<TransferProofBytes, String> {
        let sigma = json.get("sigma_proof").ok_or("Missing sigma_proof")?;
        let xs_hex = sigma.get("xs").and_then(|v| v.as_str()).ok_or("Missing xs")?;
        let alphas_hex = sigma.get("alphas").and_then(|v| v.as_str()).ok_or("Missing alphas")?;
        
        let zkrp_balance = json.get("zkrp_new_balance").ok_or("Missing zkrp_new_balance")?;
        let zkrp_balance_hex = zkrp_balance.get("0").and_then(|v| v.as_str()).ok_or("Missing zkrp_new_balance bytes")?;
        
        let zkrp_amount = json.get("zkrp_amount").ok_or("Missing zkrp_amount")?;
        let zkrp_amount_hex = zkrp_amount.get("0").and_then(|v| v.as_str()).ok_or("Missing zkrp_amount bytes")?;
        
        let xs_bytes = hex::decode(xs_hex).map_err(|e| format!("Invalid xs hex: {}", e))?;
        let alphas_bytes = hex::decode(alphas_hex).map_err(|e| format!("Invalid alphas hex: {}", e))?;
        let zkrp_balance_bytes = hex::decode(zkrp_balance_hex).map_err(|e| format!("Invalid zkrp_balance hex: {}", e))?;
        let zkrp_amount_bytes = hex::decode(zkrp_amount_hex).map_err(|e| format!("Invalid zkrp_amount hex: {}", e))?;
        
        Ok(TransferProofBytes {
            sigma_proof: TransferSigmaProofBytes {
                xs: BytesN::<1088>::from_array(&self.env, &xs_bytes.try_into().map_err(|_| "Invalid xs length")?),
                alphas: BytesN::<128>::from_array(&self.env, &alphas_bytes.try_into().map_err(|_| "Invalid alphas length")?),
            },
            zkrp_new_balance: RangeProofBytes(
                BytesN::<2272>::from_array(&self.env, &zkrp_balance_bytes.try_into().map_err(|_| "Invalid zkrp_balance length")?)
            ),
            zkrp_amount: RangeProofBytes(
                BytesN::<2272>::from_array(&self.env, &zkrp_amount_bytes.try_into().map_err(|_| "Invalid zkrp_amount length")?)
            ),
        })
    }

    fn json_to_balance(&self, json: &Value) -> Result<ConfidentialBalanceBytes, String> {
        let mut bytes = Vec::new();
        
        for i in 1..=8 {
            let c_field = format!("c_{}", i);
            let d_field = format!("d_{}", i);
            
            let c_hex = json.get(&c_field).and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing {} field", c_field))?;
            let d_hex = json.get(&d_field).and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing {} field", d_field))?;
            
            bytes.extend(hex::decode(c_hex).map_err(|e| format!("Invalid {} hex: {}", c_field, e))?);
            bytes.extend(hex::decode(d_hex).map_err(|e| format!("Invalid {} hex: {}", d_field, e))?);
        }
        
        if bytes.len() != 512 {
            return Err(format!("Expected 512 bytes, got {}", bytes.len()));
        }
        
        Ok(ConfidentialBalanceBytes {
            c_1: BytesN::<32>::from_array(&self.env, &bytes[0..32].try_into().unwrap()),
            d_1: BytesN::<32>::from_array(&self.env, &bytes[32..64].try_into().unwrap()),
            c_2: BytesN::<32>::from_array(&self.env, &bytes[64..96].try_into().unwrap()),
            d_2: BytesN::<32>::from_array(&self.env, &bytes[96..128].try_into().unwrap()),
            c_3: BytesN::<32>::from_array(&self.env, &bytes[128..160].try_into().unwrap()),
            d_3: BytesN::<32>::from_array(&self.env, &bytes[160..192].try_into().unwrap()),
            c_4: BytesN::<32>::from_array(&self.env, &bytes[192..224].try_into().unwrap()),
            d_4: BytesN::<32>::from_array(&self.env, &bytes[224..256].try_into().unwrap()),
            c_5: BytesN::<32>::from_array(&self.env, &bytes[256..288].try_into().unwrap()),
            d_5: BytesN::<32>::from_array(&self.env, &bytes[288..320].try_into().unwrap()),
            c_6: BytesN::<32>::from_array(&self.env, &bytes[320..352].try_into().unwrap()),
            d_6: BytesN::<32>::from_array(&self.env, &bytes[352..384].try_into().unwrap()),
            c_7: BytesN::<32>::from_array(&self.env, &bytes[384..416].try_into().unwrap()),
            d_7: BytesN::<32>::from_array(&self.env, &bytes[416..448].try_into().unwrap()),
            c_8: BytesN::<32>::from_array(&self.env, &bytes[448..480].try_into().unwrap()),
            d_8: BytesN::<32>::from_array(&self.env, &bytes[480..512].try_into().unwrap()),
        })
    }

    fn json_to_amount(&self, json: &Value) -> Result<ConfidentialAmountBytes, String> {
        let mut bytes = Vec::new();
        
        for i in 1..=4 {
            let c_field = format!("c_{}", i);
            let d_field = format!("d_{}", i);
            
            let c_hex = json.get(&c_field).and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing {} field", c_field))?;
            let d_hex = json.get(&d_field).and_then(|v| v.as_str())
                .ok_or_else(|| format!("Missing {} field", d_field))?;
            
            bytes.extend(hex::decode(c_hex).map_err(|e| format!("Invalid {} hex: {}", c_field, e))?);
            bytes.extend(hex::decode(d_hex).map_err(|e| format!("Invalid {} hex: {}", d_field, e))?);
        }
        
        if bytes.len() != 256 {
            return Err(format!("Expected 256 bytes, got {}", bytes.len()));
        }
        
        Ok(ConfidentialAmountBytes {
            c_1: BytesN::<32>::from_array(&self.env, &bytes[0..32].try_into().unwrap()),
            d_1: BytesN::<32>::from_array(&self.env, &bytes[32..64].try_into().unwrap()),
            c_2: BytesN::<32>::from_array(&self.env, &bytes[64..96].try_into().unwrap()),
            d_2: BytesN::<32>::from_array(&self.env, &bytes[96..128].try_into().unwrap()),
            c_3: BytesN::<32>::from_array(&self.env, &bytes[128..160].try_into().unwrap()),
            d_3: BytesN::<32>::from_array(&self.env, &bytes[160..192].try_into().unwrap()),
            c_4: BytesN::<32>::from_array(&self.env, &bytes[192..224].try_into().unwrap()),
            d_4: BytesN::<32>::from_array(&self.env, &bytes[224..256].try_into().unwrap()),
        })
    }

    // Rest is the same as the original demo but simpler JSON parsing
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
                println!("❌ Failed to parse key file {}: {}", file_path, e);
                None
            }
        }
    }

    fn hex_to_scalar(hex_str: &str) -> Scalar {
        let bytes = hex::decode(hex_str).expect("Invalid hex");
        Scalar::from_bytes(&bytes.try_into().expect("Invalid scalar length")).expect("Invalid scalar")
    }

    fn hex_to_point(hex_str: &str) -> RistrettoPoint {
        let bytes = hex::decode(hex_str).expect("Invalid hex");
        RistrettoPoint::from_compressed(&bytes.try_into().expect("Invalid point length")).expect("Invalid point")
    }

    fn print_separator(&self) {
        println!("\n═══════════════════════════════════════════════════════════════════");
    }

    pub fn run(&mut self) {
        loop {
            self.print_separator();
            println!("\n📋 Available Actions:");
            println!("  1. Initialize contract");
            println!("  2. Load keys from files");
            println!("  3. Register confidential token");
            println!("  4. Register accounts");
            println!("  5. Deposit tokens");
            println!("  6. Execute rollover (from CLI JSON)");
            println!("  7. Execute transfer (from CLI JSON)");
            println!("  8. Execute withdrawal (from CLI JSON)");
            println!("  9. Check balances");
            println!("  0. Exit");
            
            print!("\n👉 Enter your choice: ");
            io::stdout().flush().unwrap();
            
            let mut input = std::string::String::new();
            io::stdin().read_line(&mut input).unwrap();
            
            match input.trim() {
                "1" => self.initialize_contract(),
                "2" => self.load_keys(),
                "3" => self.register_token(),
                "4" => self.register_accounts(),
                "5" => self.deposit(),
                "6" => self.rollover(),
                "7" => self.transfer(),
                "8" => self.withdrawal(),
                "9" => self.check_balances(),
                "0" => {
                    println!("\n👋 Goodbye!");
                    break;
                }
                _ => println!("❌ Invalid choice, please try again."),
            }
        }
    }

    fn initialize_contract(&mut self) {
        println!("\n🚀 Initializing Confidential Token Contract...");
        
        self.admin = Some(Address::generate(&self.env));
        self.alice = Some(Address::generate(&self.env));
        self.bob = Some(Address::generate(&self.env));
        
        let contract = self.env.register(ConfidentialToken, ());
        let token = ConfidentialTokenClient::new(&self.env, &contract);
        
        token.__constructor(
            &self.admin.as_ref().unwrap(),
            &7u32,
            &String::from_str(&self.env, "Confidential Token"),
            &String::from_str(&self.env, "CT"),
        );
        
        self.token = Some(token);
        
        println!("✅ Contract initialized successfully!");
    }

    fn load_keys(&mut self) {
        println!("\n🔑 Loading keys from files...");
        
        if let Some(alice_key) = self.load_key_pair_from_file("data/alice_key.json") {
            self.alice_secret_key = Some(Self::hex_to_scalar(&alice_key.secret_key_hex));
            self.alice_public_key = Some(Self::hex_to_point(&alice_key.public_key_hex));
            println!("✅ Alice keys loaded");
        }
        
        if let Some(bob_key) = self.load_key_pair_from_file("data/bob_key.json") {
            self.bob_secret_key = Some(Self::hex_to_scalar(&bob_key.secret_key_hex));
            self.bob_public_key = Some(Self::hex_to_point(&bob_key.public_key_hex));
            println!("✅ Bob keys loaded");
        }
        
        if let Some(auditor_key) = self.load_key_pair_from_file("data/auditor_key.json") {
            self.auditor_secret_key = Some(Self::hex_to_scalar(&auditor_key.secret_key_hex));
            self.auditor_public_key = Some(Self::hex_to_point(&auditor_key.public_key_hex));
            println!("✅ Auditor keys loaded");
        }
    }

    fn register_token(&mut self) {
        println!("\n📝 Registering confidential token...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        // Load auditor public key from CLI JSON
        let cli_json: Value = match fs::read_to_string("data/auditor_pubkey_cli.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(json) => json,
                Err(e) => {
                    println!("❌ Failed to parse auditor pubkey JSON: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read auditor pubkey file: {}", e);
                return;
            }
        };
        
        let auditor_pubkey = match self.json_to_pubkey(&cli_json) {
            Ok(pk) => pk,
            Err(e) => {
                println!("❌ Failed to convert pubkey: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        token.register_confidential_token(&auditor_pubkey);
        
        println!("✅ Confidential token registered with auditor!");
    }

    fn register_accounts(&mut self) {
        println!("\n📝 Registering confidential accounts...");
        
        if self.token.is_none() || self.alice_public_key.is_none() || self.bob_public_key.is_none() {
            println!("❌ Please initialize contract and load keys first!");
            return;
        }
        
        let token = self.token.as_ref().unwrap();
        
        // Register Alice
        let alice_pubkey = CompressedPubkeyBytes(
            BytesN::<32>::from_array(&self.env, &self.alice_public_key.unwrap().compress().to_bytes())
        );
        token.register_account(self.alice.as_ref().unwrap(), &alice_pubkey);
        println!("✅ Alice's account registered");
        
        // Register Bob  
        let bob_pubkey = CompressedPubkeyBytes(
            BytesN::<32>::from_array(&self.env, &self.bob_public_key.unwrap().compress().to_bytes())
        );
        token.register_account(self.bob.as_ref().unwrap(), &bob_pubkey);
        println!("✅ Bob's account registered");
    }

    fn deposit(&mut self) {
        println!("\n💰 Depositing tokens...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        print!("Enter deposit amount for Alice: ");
        io::stdout().flush().unwrap();
        let mut amount_str = std::string::String::new();
        io::stdin().read_line(&mut amount_str).unwrap();
        let amount: u64 = amount_str.trim().parse().unwrap_or(0);
        
        if amount == 0 {
            println!("❌ Invalid amount!");
            return;
        }
        
        let token = self.token.as_ref().unwrap();
        token.mint(self.alice.as_ref().unwrap(), &(amount as i128));
        println!("✅ Minted {} regular tokens to Alice", amount);
        
        token.deposit(self.alice.as_ref().unwrap(), &amount);
        println!("✅ Deposited {} tokens to Alice's confidential account", amount);
    }

    fn rollover(&mut self) {
        println!("\n🔄 Executing rollover from CLI JSON...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        // Load rollover data from CLI JSON
        let cli_data: Value = match fs::read_to_string("data/alice_rollover_cli.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse rollover JSON: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read rollover file: {}", e);
                return;
            }
        };
        
        let balance_amount = cli_data.get("balance_amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let proof = match self.json_to_new_balance_proof(cli_data.get("proof").unwrap()) {
            Ok(p) => p,
            Err(e) => {
                println!("❌ Failed to parse proof: {}", e);
                return;
            }
        };
        let new_balance = match self.json_to_balance(cli_data.get("new_balance").unwrap()) {
            Ok(b) => b,
            Err(e) => {
                println!("❌ Failed to parse balance: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let start = Instant::now();
        token.rollover_pending_balance(self.alice.as_ref().unwrap(), &new_balance, &proof);
        let duration = start.elapsed();
        
        println!("✅ Rollover executed successfully!");
        println!("   Balance amount: {} tokens", balance_amount);
        println!("   Execution time: {:?}", duration);
    }

    fn transfer(&mut self) {
        println!("\n💸 Executing transfer from CLI JSON...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        let cli_data: Value = match fs::read_to_string("data/transfer_cli.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse transfer JSON: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read transfer file: {}", e);
                return;
            }
        };
        
        let transfer_amount = cli_data.get("transfer_amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let alice_new_balance = cli_data.get("alice_new_balance").and_then(|v| v.as_u64()).unwrap_or(0);
        
        let proof = match self.json_to_transfer_proof(cli_data.get("proof").unwrap()) {
            Ok(p) => p,
            Err(e) => {
                println!("❌ Failed to parse proof: {}", e);
                return;
            }
        };
        
        let new_balance = match self.json_to_balance(cli_data.get("new_balance").unwrap()) {
            Ok(b) => b,
            Err(e) => {
                println!("❌ Failed to parse new_balance: {}", e);
                return;
            }
        };
        
        let alice_amount = match self.json_to_amount(cli_data.get("amount_alice").unwrap()) {
            Ok(a) => a,
            Err(e) => {
                println!("❌ Failed to parse amount_alice: {}", e);
                return;
            }
        };
        
        let bob_amount = match self.json_to_amount(cli_data.get("amount_bob").unwrap()) {
            Ok(a) => a,
            Err(e) => {
                println!("❌ Failed to parse amount_bob: {}", e);
                return;
            }
        };
        
        let auditor_amount = match self.json_to_amount(cli_data.get("amount_auditor").unwrap()) {
            Ok(a) => a,
            Err(e) => {
                println!("❌ Failed to parse amount_auditor: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let start = Instant::now();
        token.confidential_transfer(
            self.alice.as_ref().unwrap(),
            self.bob.as_ref().unwrap(),
            &new_balance,
            &alice_amount,
            &bob_amount,
            &auditor_amount,
            &proof,
        );
        let duration = start.elapsed();
        
        println!("✅ Transfer executed successfully!");
        println!("   Transfer amount: {} tokens", transfer_amount);
        println!("   Alice's new balance: {} tokens", alice_new_balance);
        println!("   Execution time: {:?}", duration);
    }

    fn withdrawal(&mut self) {
        println!("\n🏧 Executing withdrawal from CLI JSON...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        print!("Withdraw from (alice/bob): ");
        io::stdout().flush().unwrap();
        let mut user_str = std::string::String::new();
        io::stdin().read_line(&mut user_str).unwrap();
        let user = user_str.trim();
        
        let withdrawal_file = format!("data/{}_withdrawal_cli.json", user);
        
        let cli_data: Value = match fs::read_to_string(&withdrawal_file) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse withdrawal JSON: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read withdrawal file {}: {}", withdrawal_file, e);
                return;
            }
        };
        
        let withdrawal_amount = cli_data.get("withdrawal_amount").and_then(|v| v.as_u64()).unwrap_or(0);
        let new_balance_amount = cli_data.get("new_balance").and_then(|v| v.as_u64()).unwrap_or(0);
        
        let account = match user {
            "alice" => self.alice.as_ref().unwrap(),
            "bob" => self.bob.as_ref().unwrap(),
            _ => {
                println!("❌ Invalid user!");
                return;
            }
        };
        
        let proof = match self.json_to_new_balance_proof(cli_data.get("proof").unwrap()) {
            Ok(p) => p,
            Err(e) => {
                println!("❌ Failed to parse proof: {}", e);
                return;
            }
        };
        
        let new_balance = match self.json_to_balance(cli_data.get("new_balance_bytes").unwrap()) {
            Ok(b) => b,
            Err(e) => {
                println!("❌ Failed to parse new_balance_bytes: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let start = Instant::now();
        token.withdraw(account, &withdrawal_amount, &new_balance, &proof);
        let duration = start.elapsed();
        
        println!("✅ Withdrawal executed successfully!");
        println!("   Withdrawal amount: {} tokens", withdrawal_amount);
        println!("   New balance: {} tokens", new_balance_amount);
        println!("   Execution time: {:?}", duration);
    }

    fn check_balances(&mut self) {
        println!("\n💼 Checking balances...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        let token = self.token.as_ref().unwrap();
        
        let alice_regular = token.balance(self.alice.as_ref().unwrap());
        let bob_regular = token.balance(self.bob.as_ref().unwrap());
        
        println!("\n📊 Regular Token Balances:");
        println!("   Alice: {} tokens", alice_regular);
        println!("   Bob: {} tokens", bob_regular);
        
        if let Some(alice_conf) = read_account_confidential_ext(&self.env, self.alice.as_ref().unwrap()) {
            println!("\n🔐 Alice's Confidential Account: [encrypted]");
            if let Some(sk) = &self.alice_secret_key {
                let available_balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&alice_conf.available_balance);
                let decrypted = available_balance.decrypt(sk);
                println!("   🔓 Decrypted available: {} tokens", decrypted);
            }
        }
        
        if let Some(bob_conf) = read_account_confidential_ext(&self.env, self.bob.as_ref().unwrap()) {
            println!("\n🔐 Bob's Confidential Account: [encrypted]");
            if let Some(sk) = &self.bob_secret_key {
                let available_balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&bob_conf.available_balance);
                let decrypted = available_balance.decrypt(sk);
                println!("   🔓 Decrypted available: {} tokens", decrypted);
            }
        }
    }
}

pub fn run_demo() {
    let mut state = DemoState::new();
    state.run();
}