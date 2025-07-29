use crate::RangeProofBytes;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use soroban_sdk::{Bytes, Env};

use super::confidential_balance::{
    split_into_chunks_u128, split_into_chunks_u64, ConfidentialAmount, ConfidentialBalance,
    AMOUNT_CHUNKS, BALANCE_CHUNKS, CHUNK_SIZE_BITS,
};

// Max bitsize for range proofs
const RANGEPROOF_GENS_CAPACITY: usize = 64;

// TODO: Maybe this should be a parameter to these functions instead of being
// hardcoded here? It would still need to be hardcoded *somewhere* though.
const BULLETPROOFS_DST: &[u8] = b"StellarConfidentialToken/Bulletproofs";

// TODO: I'm writing these range proofs to prove that chunks are in the range
// [0, 2^16). Is that upper bound right? Should it be up to 2^32? Or can we
// assume all chunks are normalized to 16 bits?

// Chunks a u128 value into 8 16-bit chunks. For compatability with the
// bulletproofs library, this extends each chunk to 64 bits.
fn chunk_u128(value: u128) -> [u64; 8] {
    let mut chunks = [0u64; 8];
    for i in 0..8 {
        let masked = (value >> (i * 16)) & 0xFFFF;
        assert!(masked <= u16::MAX as u128, "Chunk exceeds u16 max");
        chunks[i] = masked as u64;
    }
    chunks
}

pub fn prove_new_balance_range(
    new_balance: u128,
    randomness: &[Scalar; BALANCE_CHUNKS],
) -> RangeProofBytes {
    // Create bulletproof generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, BALANCE_CHUNKS); // 64 generators for 8 parties (chunks)

    // Create transcript with domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);

    // Split balance into chunks
    let chunks = chunk_u128(new_balance);

    // TODO: Left off here. Do I need to return the commitments as well?
    // Create the batched range proof for all 8 chunks, each proving value is in [0, 2^16)
    let (proof, _commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &chunks,
        randomness,
        CHUNK_SIZE_BITS as usize,
    )
    .expect("Failed to create range proof");

    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    RangeProofBytes(Bytes::from_slice(&Env::default(), &proof_bytes))
}

// TOOD: Still need to cleanup this function
pub fn prove_transfer_amount_range(
    new_amount: u64,
    randomness: &[Scalar; AMOUNT_CHUNKS],
) -> RangeProofBytes {
    // Create bulletproof generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, AMOUNT_CHUNKS); // 64 generators for 4 parties (chunks)

    // Create transcript with domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);

    // Split amount into chunks
    let chunks = split_into_chunks_u64(new_amount);

    // Convert chunks to u64 values for bulletproofs API
    let mut values = [0u64; AMOUNT_CHUNKS];
    for (i, chunk) in chunks.iter().enumerate() {
        // Extract the low 64 bits (chunks are guaranteed to be 16-bit values)
        values[i] = chunk.to_bytes()[0] as u64 | ((chunk.to_bytes()[1] as u64) << 8);
    }

    // Convert randomness scalars to bulletproofs format
    let blindings = *randomness;

    // Create the batched range proof for all 4 chunks, each proving value is in [0, 2^16)
    let (proof, _commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &blindings,
        CHUNK_SIZE_BITS as usize,
    )
    .expect("Failed to create range proof");

    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    RangeProofBytes(Bytes::from_slice(&Env::default(), &proof_bytes))
}

pub fn verify_new_balance_range_proof(
    new_balance: &ConfidentialBalance,
    proof: &RangeProofBytes,
) -> Result<(), &'static str> {
    // Create the same bulletproof generators used in proving
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, BALANCE_CHUNKS);
    
    // Create transcript with the same domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);
    
    // Extract Pedersen commitments from the confidential balance
    let balance_points = new_balance.get_encrypted_balances();
    
    // Convert RistrettoPoints to CompressedRistretto for bulletproofs API
    let commitments: Vec<CompressedRistretto> = balance_points
        .iter()
        .map(|point| point.compress())
        .collect();
    
    // Deserialize the proof
    let proof_bytes: Vec<u8> = proof.0.iter().collect();
    let range_proof = RangeProof::from_bytes(&proof_bytes)
        .map_err(|_| "Failed to deserialize range proof")?;
    
    // Verify the range proof
    range_proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &commitments,
            CHUNK_SIZE_BITS as usize,
        )
        .map_err(|_| "Range proof verification failed")
}

pub fn verify_transfer_amount_range_proof(
    _new_amount: &ConfidentialAmount,
    _proof: &RangeProofBytes,
) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::{basepoint_mul, new_scalar_from_u64};
    use curve25519_dalek::traits::Identity;
    use curve25519_dalek::RistrettoPoint;
    
    #[test]
    fn test_prove_and_verify_new_balance_range() {
        // Test with a valid 128-bit balance
        let balance = 0x123456789ABCDEFu128;
        
        // Generate random scalars for the proof
        let mut randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            randomness[i] = Scalar::from(i as u64 + 1); // Simple non-zero scalars for testing
        }
        
        // Create the range proof
        let proof = prove_new_balance_range(balance, &randomness);
        
        // Create a confidential balance with the same chunks and randomness
        // This simulates having encrypted chunks where the commitments match the proof
        let chunks = chunk_u128(balance);
        let mut encrypted_chunks = [crate::confidential_balance::EncryptedChunk {
            amount: RistrettoPoint::identity(),
            handle: RistrettoPoint::identity(),
        }; BALANCE_CHUNKS];
        
        // Create Pedersen commitments for each chunk using the same generators as the proof
        let pc_gens = PedersenGens::default();
        for i in 0..BALANCE_CHUNKS {
            let chunk_scalar = new_scalar_from_u64(chunks[i]);
            let commitment = pc_gens.commit(chunk_scalar, randomness[i]).compress().decompress().unwrap();
            encrypted_chunks[i].amount = commitment;
        }
        
        let confidential_balance = ConfidentialBalance(encrypted_chunks);
        
        // Verify the proof
        let result = verify_new_balance_range_proof(&confidential_balance, &proof);
        assert!(result.is_ok(), "Proof verification failed: {:?}", result);
    }
    
    #[test]
    fn test_verify_with_wrong_balance_fails() {
        // Create a proof for one balance
        let balance = 12345u128;
        let mut randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            randomness[i] = Scalar::from(i as u64 + 1);
        }
        let proof = prove_new_balance_range(balance, &randomness);
        
        // But create commitments for a different balance
        let wrong_balance = 54321u128;
        let chunks = chunk_u128(wrong_balance);
        let mut encrypted_chunks = [crate::confidential_balance::EncryptedChunk {
            amount: RistrettoPoint::identity(),
            handle: RistrettoPoint::identity(),
        }; BALANCE_CHUNKS];
        
        let pc_gens = PedersenGens::default();
        for i in 0..BALANCE_CHUNKS {
            let chunk_scalar = new_scalar_from_u64(chunks[i]);
            let commitment = pc_gens.commit(chunk_scalar, randomness[i]).compress().decompress().unwrap();
            encrypted_chunks[i].amount = commitment;
        }
        
        let confidential_balance = ConfidentialBalance(encrypted_chunks);
        
        // Verification should fail
        let result = verify_new_balance_range_proof(&confidential_balance, &proof);
        assert!(result.is_err(), "Proof verification should have failed");
    }
    
    #[test]
    fn test_verify_with_invalid_proof_bytes_fails() {
        // Create a valid balance
        let balance = 12345u128;
        let chunks = chunk_u128(balance);
        let mut encrypted_chunks = [crate::confidential_balance::EncryptedChunk {
            amount: RistrettoPoint::identity(),
            handle: RistrettoPoint::identity(),
        }; BALANCE_CHUNKS];
        
        for i in 0..BALANCE_CHUNKS {
            let chunk_scalar = new_scalar_from_u64(chunks[i]);
            encrypted_chunks[i].amount = basepoint_mul(&chunk_scalar);
        }
        
        let confidential_balance = ConfidentialBalance(encrypted_chunks);
        
        // Create invalid proof bytes
        let invalid_proof = RangeProofBytes(Bytes::from_slice(&Env::default(), &[0u8; 100]));
        
        // Verification should fail
        let result = verify_new_balance_range_proof(&confidential_balance, &invalid_proof);
        assert!(result.is_err(), "Proof verification should have failed");
    }
}
