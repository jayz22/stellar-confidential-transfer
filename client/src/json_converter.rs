use serde_json::{json, Value};

/// Convert XDR hex bytes of a proof to CLI-compatible JSON
/// This takes the already-generated XDR bytes and formats them
/// into the JSON structure that stellar-cli expects
pub fn proof_xdr_to_cli_json(proof_hex: &str, proof_type: &str) -> Result<Value, String> {
    let bytes = hex::decode(proof_hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    match proof_type {
        "NewBalanceProof" => {
            // NewBalanceProofBytes structure in XDR:
            // - sigma_proof.xs: 576 bytes
            // - sigma_proof.alphas: 64 bytes  
            // - zkrp_new_balance: 2272 bytes
            // Total: 2912 bytes
            
            if bytes.len() != 2912 {
                return Err(format!("Expected 2912 bytes for NewBalanceProof, got {}", bytes.len()));
            }
            
            Ok(json!({
                "sigma_proof": {
                    "xs": hex::encode(&bytes[0..576]),
                    "alphas": hex::encode(&bytes[576..640])
                },
                "zkrp_new_balance": {
                    "0": hex::encode(&bytes[640..2912])  // RangeProofBytes is a tuple struct
                }
            }))
        }
        
        "TransferProof" => {
            // TransferProofBytes structure in XDR:
            // - sigma_proof.xs: 1088 bytes
            // - sigma_proof.alphas: 128 bytes
            // - zkrp_new_balance: 2272 bytes
            // - zkrp_amount: 2272 bytes
            // Total: 5760 bytes
            
            if bytes.len() != 5760 {
                return Err(format!("Expected 5760 bytes for TransferProof, got {}", bytes.len()));
            }
            
            Ok(json!({
                "sigma_proof": {
                    "xs": hex::encode(&bytes[0..1088]),
                    "alphas": hex::encode(&bytes[1088..1216])
                },
                "zkrp_new_balance": {
                    "0": hex::encode(&bytes[1216..3488])
                },
                "zkrp_amount": {
                    "0": hex::encode(&bytes[3488..5760])
                }
            }))
        }
        
        _ => Err(format!("Unknown proof type: {}", proof_type))
    }
}

/// Convert XDR hex bytes of ConfidentialBalanceBytes to CLI-compatible JSON
pub fn balance_xdr_to_cli_json(balance_hex: &str) -> Result<Value, String> {
    let bytes = hex::decode(balance_hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    // ConfidentialBalanceBytes: 16 * 32 = 512 bytes
    if bytes.len() != 512 {
        return Err(format!("Expected 512 bytes for balance, got {}", bytes.len()));
    }
    
    Ok(json!({
        "c_1": hex::encode(&bytes[0..32]),
        "d_1": hex::encode(&bytes[32..64]),
        "c_2": hex::encode(&bytes[64..96]),
        "d_2": hex::encode(&bytes[96..128]),
        "c_3": hex::encode(&bytes[128..160]),
        "d_3": hex::encode(&bytes[160..192]),
        "c_4": hex::encode(&bytes[192..224]),
        "d_4": hex::encode(&bytes[224..256]),
        "c_5": hex::encode(&bytes[256..288]),
        "d_5": hex::encode(&bytes[288..320]),
        "c_6": hex::encode(&bytes[320..352]),
        "d_6": hex::encode(&bytes[352..384]),
        "c_7": hex::encode(&bytes[384..416]),
        "d_7": hex::encode(&bytes[416..448]),
        "c_8": hex::encode(&bytes[448..480]),
        "d_8": hex::encode(&bytes[480..512])
    }))
}

/// Convert XDR hex bytes of ConfidentialAmountBytes to CLI-compatible JSON
pub fn amount_xdr_to_cli_json(amount_hex: &str) -> Result<Value, String> {
    let bytes = hex::decode(amount_hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    // ConfidentialAmountBytes: 8 * 32 = 256 bytes
    if bytes.len() != 256 {
        return Err(format!("Expected 256 bytes for amount, got {}", bytes.len()));
    }
    
    Ok(json!({
        "c_1": hex::encode(&bytes[0..32]),
        "d_1": hex::encode(&bytes[32..64]),
        "c_2": hex::encode(&bytes[64..96]),
        "d_2": hex::encode(&bytes[96..128]),
        "c_3": hex::encode(&bytes[128..160]),
        "d_3": hex::encode(&bytes[160..192]),
        "c_4": hex::encode(&bytes[192..224]),
        "d_4": hex::encode(&bytes[224..256])
    }))
}

/// Convert a public key hex to CLI-compatible JSON (for CompressedPubkeyBytes)
pub fn pubkey_to_cli_json(pubkey_hex: &str) -> Result<Value, String> {
    let bytes = hex::decode(pubkey_hex).map_err(|e| format!("Failed to decode hex: {}", e))?;
    
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes for pubkey, got {}", bytes.len()));
    }
    
    // CompressedPubkeyBytes is a tuple struct, so field name is "0"
    Ok(json!({
        "0": pubkey_hex
    }))
}