use serde::{Deserialize, Serialize};
use serde_json::Value;

/// CLI-compatible JSON structures that match the contract spec format
/// These will be parsed correctly by stellar-cli when using --arg-file-path

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCompressedPubkeyBytes {
    #[serde(rename = "0")]
    pub bytes: String,  // 32-byte hex string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialBalanceBytes {
    pub c_1: String,  // 32-byte hex
    pub d_1: String,  // 32-byte hex
    pub c_2: String,  // 32-byte hex
    pub d_2: String,  // 32-byte hex
    pub c_3: String,  // 32-byte hex
    pub d_3: String,  // 32-byte hex
    pub c_4: String,  // 32-byte hex
    pub d_4: String,  // 32-byte hex
    pub c_5: String,  // 32-byte hex
    pub d_5: String,  // 32-byte hex
    pub c_6: String,  // 32-byte hex
    pub d_6: String,  // 32-byte hex
    pub c_7: String,  // 32-byte hex
    pub d_7: String,  // 32-byte hex
    pub c_8: String,  // 32-byte hex
    pub d_8: String,  // 32-byte hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialAmountBytes {
    pub c_1: String,  // 32-byte hex
    pub d_1: String,  // 32-byte hex
    pub c_2: String,  // 32-byte hex
    pub d_2: String,  // 32-byte hex
    pub c_3: String,  // 32-byte hex
    pub d_3: String,  // 32-byte hex
    pub c_4: String,  // 32-byte hex
    pub d_4: String,  // 32-byte hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliRangeProofBytes {
    #[serde(rename = "0")]
    pub bytes: String,  // BytesN<2272> as hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliNewBalanceSigmaProofBytes {
    pub xs: String,     // BytesN<576> as hex
    pub alphas: String, // BytesN<64> as hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliTransferSigmaProofBytes {
    pub xs: String,     // BytesN<1088> as hex
    pub alphas: String, // BytesN<128> as hex
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

/// Convert hex bytes to ConfidentialBalanceBytes structure
/// Assumes the hex string represents 16 * 32 = 512 bytes
pub fn hex_to_cli_balance(hex: &str) -> Result<CliConfidentialBalanceBytes, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    if bytes.len() != 512 {
        return Err(format!("Expected 512 bytes for balance, got {}", bytes.len()));
    }
    
    Ok(CliConfidentialBalanceBytes {
        c_1: hex::encode(&bytes[0..32]),
        d_1: hex::encode(&bytes[32..64]),
        c_2: hex::encode(&bytes[64..96]),
        d_2: hex::encode(&bytes[96..128]),
        c_3: hex::encode(&bytes[128..160]),
        d_3: hex::encode(&bytes[160..192]),
        c_4: hex::encode(&bytes[192..224]),
        d_4: hex::encode(&bytes[224..256]),
        c_5: hex::encode(&bytes[256..288]),
        d_5: hex::encode(&bytes[288..320]),
        c_6: hex::encode(&bytes[320..352]),
        d_6: hex::encode(&bytes[352..384]),
        c_7: hex::encode(&bytes[384..416]),
        d_7: hex::encode(&bytes[416..448]),
        c_8: hex::encode(&bytes[448..480]),
        d_8: hex::encode(&bytes[480..512]),
    })
}

/// Convert hex bytes to ConfidentialAmountBytes structure
/// Assumes the hex string represents 8 * 32 = 256 bytes
pub fn hex_to_cli_amount(hex: &str) -> Result<CliConfidentialAmountBytes, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    if bytes.len() != 256 {
        return Err(format!("Expected 256 bytes for amount, got {}", bytes.len()));
    }
    
    Ok(CliConfidentialAmountBytes {
        c_1: hex::encode(&bytes[0..32]),
        d_1: hex::encode(&bytes[32..64]),
        c_2: hex::encode(&bytes[64..96]),
        d_2: hex::encode(&bytes[96..128]),
        c_3: hex::encode(&bytes[128..160]),
        d_3: hex::encode(&bytes[160..192]),
        c_4: hex::encode(&bytes[192..224]),
        d_4: hex::encode(&bytes[224..256]),
    })
}

/// Convert hex bytes to NewBalanceProofBytes structure
/// The proof hex should be the XDR serialized proof
pub fn hex_to_cli_new_balance_proof(hex: &str) -> Result<CliNewBalanceProofBytes, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    // NewBalanceProofBytes structure:
    // - sigma_proof.xs: 576 bytes
    // - sigma_proof.alphas: 64 bytes
    // - zkrp_new_balance: 2272 bytes
    // Total: 2912 bytes
    
    if bytes.len() != 2912 {
        return Err(format!("Expected 2912 bytes for new balance proof, got {}", bytes.len()));
    }
    
    Ok(CliNewBalanceProofBytes {
        sigma_proof: CliNewBalanceSigmaProofBytes {
            xs: hex::encode(&bytes[0..576]),
            alphas: hex::encode(&bytes[576..640]),
        },
        zkrp_new_balance: CliRangeProofBytes {
            bytes: hex::encode(&bytes[640..2912]),
        },
    })
}

/// Convert hex bytes to TransferProofBytes structure
pub fn hex_to_cli_transfer_proof(hex: &str) -> Result<CliTransferProofBytes, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    // TransferProofBytes structure:
    // - sigma_proof.xs: 1088 bytes
    // - sigma_proof.alphas: 128 bytes
    // - zkrp_new_balance: 2272 bytes
    // - zkrp_amount: 2272 bytes
    // Total: 5760 bytes
    
    if bytes.len() != 5760 {
        return Err(format!("Expected 5760 bytes for transfer proof, got {}", bytes.len()));
    }
    
    Ok(CliTransferProofBytes {
        sigma_proof: CliTransferSigmaProofBytes {
            xs: hex::encode(&bytes[0..1088]),
            alphas: hex::encode(&bytes[1088..1216]),
        },
        zkrp_new_balance: CliRangeProofBytes {
            bytes: hex::encode(&bytes[1216..3488]),
        },
        zkrp_amount: CliRangeProofBytes {
            bytes: hex::encode(&bytes[3488..5760]),
        },
    })
}

/// Convert a public key hex to CLI-compatible format
pub fn hex_to_cli_pubkey(hex: &str) -> Result<CliCompressedPubkeyBytes, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for public key, got {}", bytes.len()));
    }
    
    Ok(CliCompressedPubkeyBytes {
        bytes: hex.to_string(),
    })
}