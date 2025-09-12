#![cfg(feature = "demo")]
extern crate std;

use crate::{
    contract::ConfidentialToken,
    utils::read_account_confidential_ext,
    ConfidentialTokenClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env, String, BytesN};
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

// CLI-compatible JSON structures matching contract spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCompressedPubkeyBytes {
    #[serde(rename = "0")]
    pub bytes: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialBalanceBytes {
    pub c_1: std::string::String,
    pub d_1: std::string::String,
    pub c_2: std::string::String,
    pub d_2: std::string::String,
    pub c_3: std::string::String,
    pub d_3: std::string::String,
    pub c_4: std::string::String,
    pub d_4: std::string::String,
    pub c_5: std::string::String,
    pub d_5: std::string::String,
    pub c_6: std::string::String,
    pub d_6: std::string::String,
    pub c_7: std::string::String,
    pub d_7: std::string::String,
    pub c_8: std::string::String,
    pub d_8: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialAmountBytes {
    pub c_1: std::string::String,
    pub d_1: std::string::String,
    pub c_2: std::string::String,
    pub d_2: std::string::String,
    pub c_3: std::string::String,
    pub d_3: std::string::String,
    pub c_4: std::string::String,
    pub d_4: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliRangeProofBytes {
    #[serde(rename = "0")]
    pub bytes: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliNewBalanceSigmaProofBytes {
    pub xs: std::string::String,
    pub alphas: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliTransferSigmaProofBytes {
    pub xs: std::string::String,
    pub alphas: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliNewBalanceProofBytes {
    pub sigma_proof: CliNewBalanceSigmaProofBytes,
    pub zkrp_new_balance: CliRangeProofBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliTransferProofBytes {
    pub sigma_proof: CliTransferSigmaProofBytes,
    pub zkrp_new_balance: CliRangeProofBytes,
    pub zkrp_amount: CliRangeProofBytes,
}

// Data structures for CLI files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key_hex: std::string::String,
    pub public_key_hex: std::string::String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliRolloverData {
    pub balance_amount: u64,
    pub proof: CliNewBalanceProofBytes,
    pub new_balance: CliConfidentialBalanceBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliTransactionData {
    pub transfer_amount: u64,
    pub alice_new_balance: u64,
    pub proof: CliTransferProofBytes,
    pub new_balance: CliConfidentialBalanceBytes,
    pub amount_alice: Option<CliConfidentialAmountBytes>,
    pub amount_bob: Option<CliConfidentialAmountBytes>,
    pub amount_auditor: Option<CliConfidentialAmountBytes>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliWithdrawalData {
    pub withdrawal_amount: u64,
    pub new_balance: u64,
    pub proof: CliNewBalanceProofBytes,
    pub new_balance_bytes: CliConfidentialBalanceBytes,
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
        println!("║     STELLAR CONFIDENTIAL TOKEN - CLI COMPATIBLE DEMO              ║");
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

    // Convert CLI JSON structures to contract types
    fn cli_pubkey_to_bytes(&self, cli: &CliCompressedPubkeyBytes) -> CompressedPubkeyBytes {
        let bytes = hex::decode(&cli.bytes).expect("Invalid hex in pubkey");
        let bytes_n = BytesN::<32>::from_array(&self.env, &bytes.try_into().expect("Invalid pubkey length"));
        CompressedPubkeyBytes(bytes_n)
    }

    fn cli_balance_to_bytes(&self, cli: &CliConfidentialBalanceBytes) -> ConfidentialBalanceBytes {
        let mut bytes = Vec::new();
        bytes.extend(hex::decode(&cli.c_1).expect("Invalid c_1 hex"));
        bytes.extend(hex::decode(&cli.d_1).expect("Invalid d_1 hex"));
        bytes.extend(hex::decode(&cli.c_2).expect("Invalid c_2 hex"));
        bytes.extend(hex::decode(&cli.d_2).expect("Invalid d_2 hex"));
        bytes.extend(hex::decode(&cli.c_3).expect("Invalid c_3 hex"));
        bytes.extend(hex::decode(&cli.d_3).expect("Invalid d_3 hex"));
        bytes.extend(hex::decode(&cli.c_4).expect("Invalid c_4 hex"));
        bytes.extend(hex::decode(&cli.d_4).expect("Invalid d_4 hex"));
        bytes.extend(hex::decode(&cli.c_5).expect("Invalid c_5 hex"));
        bytes.extend(hex::decode(&cli.d_5).expect("Invalid d_5 hex"));
        bytes.extend(hex::decode(&cli.c_6).expect("Invalid c_6 hex"));
        bytes.extend(hex::decode(&cli.d_6).expect("Invalid d_6 hex"));
        bytes.extend(hex::decode(&cli.c_7).expect("Invalid c_7 hex"));
        bytes.extend(hex::decode(&cli.d_7).expect("Invalid d_7 hex"));
        bytes.extend(hex::decode(&cli.c_8).expect("Invalid c_8 hex"));
        bytes.extend(hex::decode(&cli.d_8).expect("Invalid d_8 hex"));
        
        ConfidentialBalanceBytes {
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
        }
    }

    fn cli_amount_to_bytes(&self, cli: &CliConfidentialAmountBytes) -> ConfidentialAmountBytes {
        let mut bytes = Vec::new();
        bytes.extend(hex::decode(&cli.c_1).expect("Invalid c_1 hex"));
        bytes.extend(hex::decode(&cli.d_1).expect("Invalid d_1 hex"));
        bytes.extend(hex::decode(&cli.c_2).expect("Invalid c_2 hex"));
        bytes.extend(hex::decode(&cli.d_2).expect("Invalid d_2 hex"));
        bytes.extend(hex::decode(&cli.c_3).expect("Invalid c_3 hex"));
        bytes.extend(hex::decode(&cli.d_3).expect("Invalid d_3 hex"));
        bytes.extend(hex::decode(&cli.c_4).expect("Invalid c_4 hex"));
        bytes.extend(hex::decode(&cli.d_4).expect("Invalid d_4 hex"));
        
        ConfidentialAmountBytes {
            c_1: BytesN::<32>::from_array(&self.env, &bytes[0..32].try_into().unwrap()),
            d_1: BytesN::<32>::from_array(&self.env, &bytes[32..64].try_into().unwrap()),
            c_2: BytesN::<32>::from_array(&self.env, &bytes[64..96].try_into().unwrap()),
            d_2: BytesN::<32>::from_array(&self.env, &bytes[96..128].try_into().unwrap()),
            c_3: BytesN::<32>::from_array(&self.env, &bytes[128..160].try_into().unwrap()),
            d_3: BytesN::<32>::from_array(&self.env, &bytes[160..192].try_into().unwrap()),
            c_4: BytesN::<32>::from_array(&self.env, &bytes[192..224].try_into().unwrap()),
            d_4: BytesN::<32>::from_array(&self.env, &bytes[224..256].try_into().unwrap()),
        }
    }

    fn cli_new_balance_proof_to_bytes(&self, cli: &CliNewBalanceProofBytes) -> NewBalanceProofBytes {
        let xs_bytes = hex::decode(&cli.sigma_proof.xs).expect("Invalid xs hex");
        let alphas_bytes = hex::decode(&cli.sigma_proof.alphas).expect("Invalid alphas hex");
        let zkrp_bytes = hex::decode(&cli.zkrp_new_balance.bytes).expect("Invalid zkrp hex");
        
        NewBalanceProofBytes {
            sigma_proof: NewBalanceSigmaProofBytes {
                xs: BytesN::<576>::from_array(&self.env, &xs_bytes.try_into().expect("Invalid xs length")),
                alphas: BytesN::<64>::from_array(&self.env, &alphas_bytes.try_into().expect("Invalid alphas length")),
            },
            zkrp_new_balance: RangeProofBytes(BytesN::<2272>::from_array(&self.env, &zkrp_bytes.try_into().expect("Invalid zkrp length"))),
        }
    }

    fn cli_transfer_proof_to_bytes(&self, cli: &CliTransferProofBytes) -> TransferProofBytes {
        let xs_bytes = hex::decode(&cli.sigma_proof.xs).expect("Invalid xs hex");
        let alphas_bytes = hex::decode(&cli.sigma_proof.alphas).expect("Invalid alphas hex");
        let zkrp_new_balance_bytes = hex::decode(&cli.zkrp_new_balance.bytes).expect("Invalid zkrp_new_balance hex");
        let zkrp_amount_bytes = hex::decode(&cli.zkrp_amount.bytes).expect("Invalid zkrp_amount hex");
        
        TransferProofBytes {
            sigma_proof: TransferSigmaProofBytes {
                xs: BytesN::<1088>::from_array(&self.env, &xs_bytes.try_into().expect("Invalid xs length")),
                alphas: BytesN::<128>::from_array(&self.env, &alphas_bytes.try_into().expect("Invalid alphas length")),
            },
            zkrp_new_balance: RangeProofBytes(BytesN::<2272>::from_array(&self.env, &zkrp_new_balance_bytes.try_into().expect("Invalid zkrp_new_balance length"))),
            zkrp_amount: RangeProofBytes(BytesN::<2272>::from_array(&self.env, &zkrp_amount_bytes.try_into().expect("Invalid zkrp_amount length"))),
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
                println!("❌ Failed to parse key file {}: {}", file_path, e);
                None
            }
        }
    }

    fn load_pubkey_from_cli_file(&self, file_path: &str) -> Option<CompressedPubkeyBytes> {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(e) => {
                println!("❌ Failed to read pubkey file {}: {}", file_path, e);
                return None;
            }
        };
        
        match serde_json::from_str::<CliCompressedPubkeyBytes>(&content) {
            Ok(cli_pubkey) => Some(self.cli_pubkey_to_bytes(&cli_pubkey)),
            Err(e) => {
                println!("❌ Failed to parse pubkey file {}: {}", file_path, e);
                None
            }
        }
    }

    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        hex::decode(hex_str).expect(&format!("Invalid hex string: {}", hex_str))
    }

    fn hex_to_scalar(hex_str: &str) -> Scalar {
        let bytes = Self::hex_to_bytes(hex_str);
        Scalar::from_bytes(&bytes.try_into().expect("Invalid scalar length")).expect("Invalid scalar")
    }

    fn hex_to_point(hex_str: &str) -> RistrettoPoint {
        let bytes = Self::hex_to_bytes(hex_str);
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
            println!("  6. Execute rollover");
            println!("  7. Execute transfer");
            println!("  8. Execute withdrawal");
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
        
        // Initialize with standard token parameters
        token.__constructor(
            &self.admin.as_ref().unwrap(),
            &7u32,
            &String::from_str(&self.env, "Confidential Token"),
            &String::from_str(&self.env, "CT"),
        );
        
        self.token = Some(token);
        
        println!("✅ Contract initialized successfully!");
        println!("   Admin address: {:?}", self.admin.as_ref().unwrap());
        println!("   Alice address: {:?}", self.alice.as_ref().unwrap());
        println!("   Bob address: {:?}", self.bob.as_ref().unwrap());
    }

    fn load_keys(&mut self) {
        println!("\n🔑 Loading keys from CLI-compatible files...");
        
        // Load key pairs
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
        
        // Load auditor public key from CLI file
        let auditor_pubkey = match self.load_pubkey_from_cli_file("data/auditor_pubkey_cli.json") {
            Some(pk) => pk,
            None => {
                println!("❌ Could not load auditor public key from data/auditor_pubkey_cli.json");
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
        
        // Mint regular tokens first (as admin)
        token.mint(self.alice.as_ref().unwrap(), &(amount as i128));
        println!("✅ Minted {} regular tokens to Alice", amount);
        
        // Deposit to confidential account
        token.deposit(self.alice.as_ref().unwrap(), &amount);
        println!("✅ Deposited {} tokens to Alice's confidential account", amount);
    }

    fn rollover(&mut self) {
        println!("\n🔄 Executing rollover from CLI data...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        // Load rollover data from CLI file
        let rollover_data: CliRolloverData = match fs::read_to_string("data/alice_rollover_cli.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse rollover data: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read rollover file: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let proof = self.cli_new_balance_proof_to_bytes(&rollover_data.proof);
        let new_balance = self.cli_balance_to_bytes(&rollover_data.new_balance);
        
        let start = Instant::now();
        token.rollover_pending_balance(self.alice.as_ref().unwrap(), &new_balance, &proof);
        let duration = start.elapsed();
        
        println!("✅ Rollover executed successfully!");
        println!("   Balance amount: {} tokens", rollover_data.balance_amount);
        println!("   Execution time: {:?}", duration);
    }

    fn transfer(&mut self) {
        println!("\n💸 Executing transfer from CLI data...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        // Load transfer data from CLI file
        let transfer_data: CliTransactionData = match fs::read_to_string("data/transfer_cli.json") {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse transfer data: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read transfer file: {}", e);
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let proof = self.cli_transfer_proof_to_bytes(&transfer_data.proof);
        let new_balance = self.cli_balance_to_bytes(&transfer_data.new_balance);
        let alice_amount = self.cli_amount_to_bytes(&transfer_data.amount_alice.expect("Missing alice amount"));
        let bob_amount = self.cli_amount_to_bytes(&transfer_data.amount_bob.expect("Missing bob amount"));
        let auditor_amount = self.cli_amount_to_bytes(&transfer_data.amount_auditor.expect("Missing auditor amount"));
        
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
        println!("   Transfer amount: {} tokens", transfer_data.transfer_amount);
        println!("   Alice's new balance: {} tokens", transfer_data.alice_new_balance);
        println!("   Execution time: {:?}", duration);
    }

    fn withdrawal(&mut self) {
        println!("\n🏧 Executing withdrawal from CLI data...");
        
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
        
        // Load withdrawal data from CLI file
        let withdrawal_data: CliWithdrawalData = match fs::read_to_string(&withdrawal_file) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Failed to parse withdrawal data: {}", e);
                    return;
                }
            },
            Err(e) => {
                println!("❌ Failed to read withdrawal file {}: {}", withdrawal_file, e);
                return;
            }
        };
        
        let account = match user {
            "alice" => self.alice.as_ref().unwrap(),
            "bob" => self.bob.as_ref().unwrap(),
            _ => {
                println!("❌ Invalid user!");
                return;
            }
        };
        
        let token = self.token.as_ref().unwrap();
        let proof = self.cli_new_balance_proof_to_bytes(&withdrawal_data.proof);
        let new_balance = self.cli_balance_to_bytes(&withdrawal_data.new_balance_bytes);
        
        let start = Instant::now();
        token.withdraw(account, &withdrawal_data.withdrawal_amount, &new_balance, &proof);
        let duration = start.elapsed();
        
        println!("✅ Withdrawal executed successfully!");
        println!("   Withdrawal amount: {} tokens", withdrawal_data.withdrawal_amount);
        println!("   New balance: {} tokens", withdrawal_data.new_balance);
        println!("   Execution time: {:?}", duration);
    }

    fn check_balances(&mut self) {
        println!("\n💼 Checking balances...");
        
        if self.token.is_none() {
            println!("❌ Please initialize the contract first!");
            return;
        }
        
        let token = self.token.as_ref().unwrap();
        
        // Check regular balances
        let alice_regular = token.balance(self.alice.as_ref().unwrap());
        let bob_regular = token.balance(self.bob.as_ref().unwrap());
        
        println!("\n📊 Regular Token Balances:");
        println!("   Alice: {} tokens", alice_regular);
        println!("   Bob: {} tokens", bob_regular);
        
        // Check confidential balances (encrypted)
        if let Some(alice_conf) = read_account_confidential_ext(&self.env, self.alice.as_ref().unwrap()) {
            println!("\n🔐 Alice's Confidential Account:");
            println!("   Available balance: [encrypted]");
            println!("   Pending balance: [encrypted]");
            
            // Decrypt if we have the secret key
            if let Some(sk) = &self.alice_secret_key {
                let available_balance = stellar_confidential_crypto::ConfidentialBalance::from_env_bytes(&alice_conf.available_balance);
                let decrypted = available_balance.decrypt(sk);
                println!("   🔓 Decrypted available: {} tokens", decrypted);
            }
        }
        
        if let Some(bob_conf) = read_account_confidential_ext(&self.env, self.bob.as_ref().unwrap()) {
            println!("\n🔐 Bob's Confidential Account:");
            println!("   Available balance: [encrypted]");
            println!("   Pending balance: [encrypted]");
            
            // Decrypt if we have the secret key
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