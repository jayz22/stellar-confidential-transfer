use stellar_confidential_crypto::{proof::{CompressedPubkeyBytes, NewBalanceProofBytes, NewBalanceSigmaProofBytes, TransferProofBytes, TransferSigmaProofBytes}, range_proof::RangeProofBytes, ConfidentialAmountBytes, ConfidentialBalanceBytes};
use soroban_sdk::Env;

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

impl CliCompressedPubkeyBytes {
    pub fn from_crypto_type(_env: &Env, pubkey: &CompressedPubkeyBytes) -> Self {
        let bytes = pubkey.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}

// Conversion implementations
impl CliRangeProofBytes {
    pub fn from_crypto_type(_env: &Env, proof: &RangeProofBytes) -> Self {
        let len = proof.0.len() as usize;
        let mut buf: Vec<u8> = vec![0u8; len];
        proof.0.copy_into_slice(&mut buf);
        Self {
            bytes: hex::encode(buf),
        }
    }
}

impl CliNewBalanceSigmaProofBytes {
    pub fn from_crypto_type(_env: &Env, proof: &NewBalanceSigmaProofBytes) -> Self {
        let alphas_bytes = proof.alphas.to_array();
        let xs_bytes = proof.xs.to_array();
        Self {
            alphas: hex::encode(alphas_bytes),
            xs: hex::encode(xs_bytes),
        }
    }
}

impl CliTransferSigmaProofBytes {
    pub fn from_crypto_type(_env: &Env, proof: &TransferSigmaProofBytes) -> Self {
        let alphas_bytes = proof.alphas.to_array();
        let xs_bytes = proof.xs.to_array();
        Self {
            alphas: hex::encode(alphas_bytes),
            xs: hex::encode(xs_bytes),
        }
    }
}

impl CliNewBalanceProofBytes {
    pub fn from_crypto_type(env: &Env, proof: &NewBalanceProofBytes) -> Self {
        Self {
            sigma_proof: CliNewBalanceSigmaProofBytes::from_crypto_type(env, &proof.sigma_proof),
            zkrp_new_balance: CliRangeProofBytes::from_crypto_type(env, &proof.zkrp_new_balance),
        }
    }
}

impl CliTransferProofBytes {
    pub fn from_crypto_type(env: &Env, proof: &TransferProofBytes) -> Self {
        Self {
            sigma_proof: CliTransferSigmaProofBytes::from_crypto_type(env, &proof.sigma_proof),
            zkrp_new_balance: CliRangeProofBytes::from_crypto_type(env, &proof.zkrp_new_balance),
            zkrp_transfer_amount: CliRangeProofBytes::from_crypto_type(env, &proof.zkrp_transfer_amount),
        }
    }
}

impl CliConfidentialAmountBytes {
    pub fn from_crypto_type(_env: &Env, amount: &ConfidentialAmountBytes) -> Self {
        let bytes = amount.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}

impl CliConfidentialBalanceBytes {
    pub fn from_crypto_type(_env: &Env, balance: &ConfidentialBalanceBytes) -> Self {
        let bytes = balance.0.to_array();
        Self {
            bytes: hex::encode(bytes),
        }
    }
}