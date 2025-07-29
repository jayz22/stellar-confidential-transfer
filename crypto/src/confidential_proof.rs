use crate::{RangeProofBytes};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use soroban_sdk::{Bytes, Env};

use super::confidential_balance::{
    split_into_chunks_u64, split_into_chunks_u128, ConfidentialAmount, ConfidentialBalance,
    AMOUNT_CHUNKS, BALANCE_CHUNKS, CHUNK_SIZE_BITS,
};

pub fn prove_new_balance_range(new_balance: u128, randomness: &std::vec::Vec<Scalar>) -> RangeProofBytes {
    assert_eq!(randomness.len(), BALANCE_CHUNKS, "Need randomness for each chunk");
    
    // Create bulletproof generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, BALANCE_CHUNKS); // 128 generators for 8 parties (chunks)
    
    // Create transcript with domain separation
    let mut transcript = Transcript::new(b"StellarConfidentialToken/BulletproofRangeProof");
    
    // Split balance into chunks (already done by caller via split_into_chunks_u128)
    let chunks = split_into_chunks_u128(new_balance);
    
    // Convert chunks to u64 values for bulletproofs API
    let mut values = std::vec![];
    for chunk in &chunks {
        // Extract the low 64 bits (chunks are guaranteed to be 16-bit values)
        values.push(chunk.to_bytes()[0] as u64 | ((chunk.to_bytes()[1] as u64) << 8));
    }
    
    // Convert randomness scalars to bulletproofs format
    let blindings: std::vec::Vec<Scalar> = randomness.iter().cloned().collect();
    
    // Create the batched range proof for all 8 chunks, each proving value is in [0, 2^16)
    let (proof, _commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &blindings,
        CHUNK_SIZE_BITS as usize,
    ).expect("Failed to create range proof");
    
    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    RangeProofBytes(Bytes::from_slice(&Env::default(), &proof_bytes))
}

pub fn prove_transfer_amount_range(new_amount: u64, randomness: &std::vec::Vec<Scalar>) -> RangeProofBytes {
    assert_eq!(randomness.len(), AMOUNT_CHUNKS, "Need randomness for each chunk");
    
    // Create bulletproof generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, AMOUNT_CHUNKS); // 64 generators for 4 parties (chunks)
    
    // Create transcript with domain separation
    let mut transcript = Transcript::new(b"StellarConfidentialToken/BulletproofRangeProof");
    
    // Split amount into chunks
    let chunks = split_into_chunks_u64(new_amount);
    
    // Convert chunks to u64 values for bulletproofs API
    let mut values = std::vec![];
    for chunk in &chunks {
        // Extract the low 64 bits (chunks are guaranteed to be 16-bit values)
        values.push(chunk.to_bytes()[0] as u64 | ((chunk.to_bytes()[1] as u64) << 8));
    }
    
    // Convert randomness scalars to bulletproofs format
    let blindings: std::vec::Vec<Scalar> = randomness.iter().cloned().collect();
    
    // Create the batched range proof for all 4 chunks, each proving value is in [0, 2^16)
    let (proof, _commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &blindings,
        CHUNK_SIZE_BITS as usize,
    ).expect("Failed to create range proof");
    
    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    RangeProofBytes(Bytes::from_slice(&Env::default(), &proof_bytes))
}

pub fn verify_new_balance_range_proof(_new_balance: &ConfidentialBalance, _proof: &RangeProofBytes) {
    todo!()
}

pub fn verify_transfer_amount_range_proof(_new_amount: &ConfidentialAmount, _proof: &RangeProofBytes) {
    todo!()
}