use crate::arith;
// TODO: Uncomment RangeProof import
use crate::{arith::new_scalar_from_u64/* , RangeProof*/};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use soroban_sdk::BytesN;

pub const AMOUNT_CHUNKS: u64 = 4;
pub const BALANCE_CHUNKS: u64 = 8;
pub const CHUNK_SIZE_BITS: u64 = 16;

#[derive(Debug, Clone)]
pub struct CompressedRistrettoBytes(pub BytesN<32>);

impl CompressedRistrettoBytes {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_array().to_vec()
    }
}

// TODO: Add `EncryptedChunkBytes`?
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub amount: RistrettoPoint, // C
    pub handle: RistrettoPoint, // D
}

impl EncryptedChunk {
    pub fn new_chunk_no_randomness(val: &Scalar) -> EncryptedChunk {
        EncryptedChunk {
            amount: arith::basepoint_mul(val),
            handle: RistrettoPoint::identity(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfidentialAmount(pub Vec<EncryptedChunk>); // 4 chunks
#[derive(Debug, Clone)]
pub struct ConfidentialBalance(pub Vec<EncryptedChunk>); // 8 chunks

impl ConfidentialAmount {
    pub fn new_amount_with_no_randomness(amount: u64) -> Self {
        todo!()
    }
}

impl ConfidentialBalance {
    pub fn new_balance_with_no_randomness(balance: u128) -> Self {
        todo!()
    }

    // TODO: Fixup
    // pub fn to_bytes(&self) -> Vec<u8> {
    //     let mut bytes = Vec::new();
    //     for chunk in &self.0 {
    //         bytes.extend(chunk.amount.0.to_array());
    //         bytes.extend(chunk.handle.0.to_array());
    //     }
    //     bytes
    // }
}

/// Splits a 64-bit integer amount into four 16-bit chunks, represented as `Scalar` values.
pub fn split_into_chunks_u64(amount: u64) -> Vec<Scalar> {
    (0..AMOUNT_CHUNKS)
        .map(|i| {
            let chunk = (amount >> (i * CHUNK_SIZE_BITS)) & 0xffff;
            new_scalar_from_u64(chunk)
        })
        .collect()
}

// TODO: Uncomment these
// pub fn prove_new_balance_range(new_balance: u128, randomness: &Vec<Scalar>) -> RangeProof {
//     todo!()
// }

// pub fn prove_transfer_amount_range(new_amount: u64, randomness: &Vec<Scalar>) -> RangeProof {
//     todo!()
// }

// pub fn verify_new_balance_range_proof(new_balance: &ConfidentialBalance, proof: &RangeProof) {
//     todo!()
// }

// pub fn verify_transfer_amount_range_proof(new_amount: &ConfidentialAmount, proof: &RangeProof) {
//     todo!()
// }
