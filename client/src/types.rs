use stellar_confidential_crypto::{proof::{CompressedPubkeyBytes, NewBalanceProofBytes, NewBalanceSigmaProofBytes, TransferProofBytes, TransferSigmaProofBytes}, range_proof::RangeProofBytes, ConfidentialAmountBytes, ConfidentialBalanceBytes};
use soroban_sdk::{Env, IntoVal, FromVal};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairHex {
    pub secret_key: String,
    pub public_key: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliRangeProofBytes {
    #[serde(rename = "0")]
    pub bytes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliNewBalanceSigmaProofBytes {
    pub xs: String,     // BytesN<576> as hex
    pub alphas: String, // BytesN<576> as hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliTransferSigmaProofBytes {
    pub alphas: String, // BytesN<832> as hex
    pub xs: String,     // BytesN<1088> as hex
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
    pub zkrp_transfer_amount: CliRangeProofBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialAmountBytes {
    #[serde(rename = "0")]
    pub bytes: String // BytesN<256>    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfidentialBalanceBytes {
    #[serde(rename = "0")]
    pub bytes: String // BytesN<512>    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCompressedPubkeyBytes {
    #[serde(rename = "0")]
    pub bytes: String // BytesN<32>
}

// FromVal and IntoVal implementations for CliCompressedPubkeyBytes
impl FromVal<Env, CompressedPubkeyBytes> for CliCompressedPubkeyBytes {
    fn from_val(_e: &Env, v: &CompressedPubkeyBytes) -> Self {
        let bytes = v.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}

impl IntoVal<Env, CompressedPubkeyBytes> for CliCompressedPubkeyBytes {
    fn into_val(&self, e: &Env) -> CompressedPubkeyBytes {
        let bytes = hex::decode(&self.bytes).expect("Invalid hex string");
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        CompressedPubkeyBytes(soroban_sdk::BytesN::from_array(e, &array))
    }
}

// FromVal and IntoVal implementations for CliRangeProofBytes
impl FromVal<Env, RangeProofBytes> for CliRangeProofBytes {
    fn from_val(_e: &Env, v: &RangeProofBytes) -> Self {
        let len = v.0.len() as usize;
        let mut buf: Vec<u8> = vec![0u8; len];
        v.0.copy_into_slice(&mut buf);
        Self {
            bytes: hex::encode(buf),
        }
    }
}

impl IntoVal<Env, RangeProofBytes> for CliRangeProofBytes {
    fn into_val(&self, e: &Env) -> RangeProofBytes {
        let bytes = hex::decode(&self.bytes).expect("Invalid hex string");
        let soroban_bytes = soroban_sdk::Bytes::from_slice(e, &bytes);
        RangeProofBytes(soroban_bytes)
    }
}

// FromVal and IntoVal implementations for CliNewBalanceSigmaProofBytes
impl FromVal<Env, NewBalanceSigmaProofBytes> for CliNewBalanceSigmaProofBytes {
    fn from_val(_e: &Env, v: &NewBalanceSigmaProofBytes) -> Self {
        let alphas_bytes = v.alphas.to_array();
        let xs_bytes = v.xs.to_array();
        Self {
            alphas: hex::encode(alphas_bytes),
            xs: hex::encode(xs_bytes),
        }
    }
}

impl IntoVal<Env, NewBalanceSigmaProofBytes> for CliNewBalanceSigmaProofBytes {
    fn into_val(&self, e: &Env) -> NewBalanceSigmaProofBytes {
        let alphas_bytes = hex::decode(&self.alphas).expect("Invalid hex string");
        let xs_bytes = hex::decode(&self.xs).expect("Invalid hex string");
        
        let mut alphas_array = [0u8; 576];
        let mut xs_array = [0u8; 576];
        
        alphas_array.copy_from_slice(&alphas_bytes[..576]);
        xs_array.copy_from_slice(&xs_bytes[..576]);
        
        NewBalanceSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(e, &alphas_array),
            xs: soroban_sdk::BytesN::from_array(e, &xs_array),
        }
    }
}

// FromVal and IntoVal implementations for CliTransferSigmaProofBytes
impl FromVal<Env, TransferSigmaProofBytes> for CliTransferSigmaProofBytes {
    fn from_val(_e: &Env, v: &TransferSigmaProofBytes) -> Self {
        let alphas_bytes = v.alphas.to_array();
        let xs_bytes = v.xs.to_array();
        Self {
            alphas: hex::encode(alphas_bytes),
            xs: hex::encode(xs_bytes),
        }
    }
}

impl IntoVal<Env, TransferSigmaProofBytes> for CliTransferSigmaProofBytes {
    fn into_val(&self, e: &Env) -> TransferSigmaProofBytes {
        let alphas_bytes = hex::decode(&self.alphas).expect("Invalid hex string");
        let xs_bytes = hex::decode(&self.xs).expect("Invalid hex string");
        
        let mut alphas_array = [0u8; 832];
        let mut xs_array = [0u8; 1088];
        
        alphas_array.copy_from_slice(&alphas_bytes[..832]);
        xs_array.copy_from_slice(&xs_bytes[..1088]);
        
        TransferSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(e, &alphas_array),
            xs: soroban_sdk::BytesN::from_array(e, &xs_array),
        }
    }
}

// FromVal and IntoVal implementations for CliNewBalanceProofBytes
impl FromVal<Env, NewBalanceProofBytes> for CliNewBalanceProofBytes {
    fn from_val(e: &Env, v: &NewBalanceProofBytes) -> Self {
        Self {
            sigma_proof: CliNewBalanceSigmaProofBytes::from_val(e, &v.sigma_proof),
            zkrp_new_balance: CliRangeProofBytes::from_val(e, &v.zkrp_new_balance),
        }
    }
}

impl IntoVal<Env, NewBalanceProofBytes> for CliNewBalanceProofBytes {
    fn into_val(&self, e: &Env) -> NewBalanceProofBytes {
        NewBalanceProofBytes {
            sigma_proof: self.sigma_proof.into_val(e),
            zkrp_new_balance: self.zkrp_new_balance.into_val(e),
        }
    }
}

// FromVal and IntoVal implementations for CliTransferProofBytes
impl FromVal<Env, TransferProofBytes> for CliTransferProofBytes {
    fn from_val(e: &Env, v: &TransferProofBytes) -> Self {
        Self {
            sigma_proof: CliTransferSigmaProofBytes::from_val(e, &v.sigma_proof),
            zkrp_new_balance: CliRangeProofBytes::from_val(e, &v.zkrp_new_balance),
            zkrp_transfer_amount: CliRangeProofBytes::from_val(e, &v.zkrp_transfer_amount),
        }
    }
}

impl IntoVal<Env, TransferProofBytes> for CliTransferProofBytes {
    fn into_val(&self, e: &Env) -> TransferProofBytes {
        TransferProofBytes {
            sigma_proof: self.sigma_proof.into_val(e),
            zkrp_new_balance: self.zkrp_new_balance.into_val(e),
            zkrp_transfer_amount: self.zkrp_transfer_amount.into_val(e),
        }
    }
}

// FromVal and IntoVal implementations for CliConfidentialAmountBytes
impl FromVal<Env, ConfidentialAmountBytes> for CliConfidentialAmountBytes {
    fn from_val(_e: &Env, v: &ConfidentialAmountBytes) -> Self {
        let bytes = v.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}

impl IntoVal<Env, ConfidentialAmountBytes> for CliConfidentialAmountBytes {
    fn into_val(&self, e: &Env) -> ConfidentialAmountBytes {
        let bytes = hex::decode(&self.bytes).expect("Invalid hex string");
        let mut array = [0u8; 256];
        array.copy_from_slice(&bytes[..256]);
        ConfidentialAmountBytes(soroban_sdk::BytesN::from_array(e, &array))
    }
}

// FromVal and IntoVal implementations for CliConfidentialBalanceBytes
impl FromVal<Env, ConfidentialBalanceBytes> for CliConfidentialBalanceBytes {
    fn from_val(_e: &Env, v: &ConfidentialBalanceBytes) -> Self {
        let bytes = v.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}

impl IntoVal<Env, ConfidentialBalanceBytes> for CliConfidentialBalanceBytes {
    fn into_val(&self, e: &Env) -> ConfidentialBalanceBytes {
        let bytes = hex::decode(&self.bytes).expect("Invalid hex string");
        let mut array = [0u8; 512];
        array.copy_from_slice(&bytes[..512]);
        ConfidentialBalanceBytes(soroban_sdk::BytesN::from_array(e, &array))
    }
}

// Aggregate types for proof data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloverProofData {
    pub proof: CliNewBalanceProofBytes,
    pub encrypted_new_balance: CliConfidentialBalanceBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalProofData {
    pub proof: CliNewBalanceProofBytes,
    pub encrypted_new_balance: CliConfidentialBalanceBytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProofData {
    pub proof: CliTransferProofBytes,
    pub encrypted_new_balance: CliConfidentialBalanceBytes,
    pub encrypted_src_amount: CliConfidentialAmountBytes,
    pub encrypted_dest_amount: CliConfidentialAmountBytes,
    pub encrypted_auditor_amount: CliConfidentialAmountBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, FromVal, IntoVal};
    use stellar_confidential_crypto::proof::CompressedPubkeyBytes;
    use rand::{RngCore, thread_rng};

    #[test]
    fn test_compressed_pubkey_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random 32 bytes for pubkey
        let mut random_bytes = [0u8; 32];
        rng.fill_bytes(&mut random_bytes);
        let original = CompressedPubkeyBytes(soroban_sdk::BytesN::from_array(&env, &random_bytes));
        
        // Convert to CLI type
        let cli_type = CliCompressedPubkeyBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: CompressedPubkeyBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.0.to_array(), roundtrip.0.to_array());
        assert_eq!(cli_type.bytes, hex::encode(random_bytes));
    }

    #[test]
    fn test_range_proof_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random bytes for range proof
        let mut random_bytes = vec![0u8; 100]; // arbitrary size
        rng.fill_bytes(&mut random_bytes);
        let soroban_bytes = soroban_sdk::Bytes::from_slice(&env, &random_bytes);
        let original = RangeProofBytes(soroban_bytes);
        
        // Convert to CLI type
        let cli_type = CliRangeProofBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: RangeProofBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        let original_vec = {
            let mut buf = vec![0u8; original.0.len() as usize];
            original.0.copy_into_slice(&mut buf);
            buf
        };
        let roundtrip_vec = {
            let mut buf = vec![0u8; roundtrip.0.len() as usize];
            roundtrip.0.copy_into_slice(&mut buf);
            buf
        };
        
        assert_eq!(original_vec, roundtrip_vec);
        assert_eq!(cli_type.bytes, hex::encode(random_bytes));
    }

    #[test]
    fn test_new_balance_sigma_proof_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random bytes for sigma proof
        let mut alphas_bytes = [0u8; 576];
        let mut xs_bytes = [0u8; 576];
        rng.fill_bytes(&mut alphas_bytes);
        rng.fill_bytes(&mut xs_bytes);
        let original = NewBalanceSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(&env, &alphas_bytes),
            xs: soroban_sdk::BytesN::from_array(&env, &xs_bytes),
        };
        
        // Convert to CLI type
        let cli_type = CliNewBalanceSigmaProofBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: NewBalanceSigmaProofBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.alphas.to_array(), roundtrip.alphas.to_array());
        assert_eq!(original.xs.to_array(), roundtrip.xs.to_array());
        assert_eq!(cli_type.alphas, hex::encode(alphas_bytes));
        assert_eq!(cli_type.xs, hex::encode(xs_bytes));
    }

    #[test]
    fn test_transfer_sigma_proof_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random bytes for transfer sigma proof
        let mut alphas_bytes = [0u8; 832];
        let mut xs_bytes = [0u8; 1088];
        rng.fill_bytes(&mut alphas_bytes);
        rng.fill_bytes(&mut xs_bytes);
        let original = TransferSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(&env, &alphas_bytes),
            xs: soroban_sdk::BytesN::from_array(&env, &xs_bytes),
        };
        
        // Convert to CLI type
        let cli_type = CliTransferSigmaProofBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: TransferSigmaProofBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.alphas.to_array(), roundtrip.alphas.to_array());
        assert_eq!(original.xs.to_array(), roundtrip.xs.to_array());
        assert_eq!(cli_type.alphas, hex::encode(alphas_bytes));
        assert_eq!(cli_type.xs, hex::encode(xs_bytes));
    }

    #[test]
    fn test_new_balance_proof_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create nested proof structure
        let mut alphas_bytes = [0u8; 576];
        let mut xs_bytes = [0u8; 576];
        rng.fill_bytes(&mut alphas_bytes);
        rng.fill_bytes(&mut xs_bytes);
        let sigma_proof = NewBalanceSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(&env, &alphas_bytes),
            xs: soroban_sdk::BytesN::from_array(&env, &xs_bytes),
        };
        let mut range_proof_bytes = vec![0u8; 50];
        rng.fill_bytes(&mut range_proof_bytes);
        let zkrp_new_balance = RangeProofBytes(soroban_sdk::Bytes::from_slice(&env, &range_proof_bytes));
        
        let original = NewBalanceProofBytes {
            sigma_proof,
            zkrp_new_balance,
        };
        
        // Convert to CLI type
        let cli_type = CliNewBalanceProofBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: NewBalanceProofBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.sigma_proof.alphas.to_array(), roundtrip.sigma_proof.alphas.to_array());
        assert_eq!(original.sigma_proof.xs.to_array(), roundtrip.sigma_proof.xs.to_array());
        
        let original_range_vec = {
            let mut buf = vec![0u8; original.zkrp_new_balance.0.len() as usize];
            original.zkrp_new_balance.0.copy_into_slice(&mut buf);
            buf
        };
        let roundtrip_range_vec = {
            let mut buf = vec![0u8; roundtrip.zkrp_new_balance.0.len() as usize];
            roundtrip.zkrp_new_balance.0.copy_into_slice(&mut buf);
            buf
        };
        assert_eq!(original_range_vec, roundtrip_range_vec);
    }

    #[test]
    fn test_transfer_proof_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create nested proof structure
        let mut alphas_bytes = [0u8; 832];
        let mut xs_bytes = [0u8; 1088];
        rng.fill_bytes(&mut alphas_bytes);
        rng.fill_bytes(&mut xs_bytes);
        let sigma_proof = TransferSigmaProofBytes {
            alphas: soroban_sdk::BytesN::from_array(&env, &alphas_bytes),
            xs: soroban_sdk::BytesN::from_array(&env, &xs_bytes),
        };
        let mut range_proof_bytes1 = vec![0u8; 75];
        let mut range_proof_bytes2 = vec![0u8; 80];
        rng.fill_bytes(&mut range_proof_bytes1);
        rng.fill_bytes(&mut range_proof_bytes2);
        let zkrp_new_balance = RangeProofBytes(soroban_sdk::Bytes::from_slice(&env, &range_proof_bytes1));
        let zkrp_transfer_amount = RangeProofBytes(soroban_sdk::Bytes::from_slice(&env, &range_proof_bytes2));
        
        let original = TransferProofBytes {
            sigma_proof,
            zkrp_new_balance,
            zkrp_transfer_amount,
        };
        
        // Convert to CLI type
        let cli_type = CliTransferProofBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: TransferProofBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.sigma_proof.alphas.to_array(), roundtrip.sigma_proof.alphas.to_array());
        assert_eq!(original.sigma_proof.xs.to_array(), roundtrip.sigma_proof.xs.to_array());
        
        // Check range proofs
        let original_new_balance_vec = {
            let mut buf = vec![0u8; original.zkrp_new_balance.0.len() as usize];
            original.zkrp_new_balance.0.copy_into_slice(&mut buf);
            buf
        };
        let roundtrip_new_balance_vec = {
            let mut buf = vec![0u8; roundtrip.zkrp_new_balance.0.len() as usize];
            roundtrip.zkrp_new_balance.0.copy_into_slice(&mut buf);
            buf
        };
        assert_eq!(original_new_balance_vec, roundtrip_new_balance_vec);
        
        let original_transfer_amount_vec = {
            let mut buf = vec![0u8; original.zkrp_transfer_amount.0.len() as usize];
            original.zkrp_transfer_amount.0.copy_into_slice(&mut buf);
            buf
        };
        let roundtrip_transfer_amount_vec = {
            let mut buf = vec![0u8; roundtrip.zkrp_transfer_amount.0.len() as usize];
            roundtrip.zkrp_transfer_amount.0.copy_into_slice(&mut buf);
            buf
        };
        assert_eq!(original_transfer_amount_vec, roundtrip_transfer_amount_vec);
    }

    #[test]
    fn test_confidential_amount_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random 256 bytes for amount
        let mut random_bytes = [0u8; 256];
        rng.fill_bytes(&mut random_bytes);
        let original = ConfidentialAmountBytes(soroban_sdk::BytesN::from_array(&env, &random_bytes));
        
        // Convert to CLI type
        let cli_type = CliConfidentialAmountBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: ConfidentialAmountBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.0.to_array(), roundtrip.0.to_array());
        assert_eq!(cli_type.bytes, hex::encode(random_bytes));
    }

    #[test]
    fn test_confidential_balance_roundtrip() {
        let env = Env::default();
        let mut rng = thread_rng();
        
        // Create random 512 bytes for balance
        let mut random_bytes = [0u8; 512];
        rng.fill_bytes(&mut random_bytes);
        let original = ConfidentialBalanceBytes(soroban_sdk::BytesN::from_array(&env, &random_bytes));
        
        // Convert to CLI type
        let cli_type = CliConfidentialBalanceBytes::from_val(&env, &original);
        
        // Convert back to crypto type
        let roundtrip: ConfidentialBalanceBytes = cli_type.into_val(&env);
        
        // Verify they're equal
        assert_eq!(original.0.to_array(), roundtrip.0.to_array());
        assert_eq!(cli_type.bytes, hex::encode(random_bytes));
    }
}