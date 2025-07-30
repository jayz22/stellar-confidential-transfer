use crate::RangeProofBytes;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use soroban_sdk::{Bytes, Env};

use super::confidential_balance::{
    ConfidentialAmount, ConfidentialBalance, EncryptedChunk, AMOUNT_CHUNKS, BALANCE_CHUNKS,
    CHUNK_SIZE_BITS,
};

// Result struct for prove_new_balance_range
#[derive(Debug, Clone)]
pub struct BalanceRangeProofResult {
    pub proof: RangeProofBytes,
    pub commitments: Vec<CompressedRistretto>,
}

// Result struct for prove_transfer_amount_range
#[derive(Debug, Clone)]
pub struct AmountRangeProofResult {
    pub proof: RangeProofBytes,
    pub commitments: Vec<CompressedRistretto>,
}

// Max bitsize for range proofs
const RANGEPROOF_GENS_CAPACITY: usize = 64;

// Label to use for domain separation in bulletproofs transcripts
const BULLETPROOFS_DST: &[u8] = b"StellarConfidentialToken/Bulletproofs";

// Generic helper function to create range proofs for chunked values
fn prove_range_generic<const N: usize>(
    chunks: &[u64; N],
    randomness: &[Scalar; N],
) -> (RangeProofBytes, Vec<CompressedRistretto>) {
    // Create bulletproof generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, N);

    // Create transcript with domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);

    // Create the batched range proof for all chunks, each proving value is in
    // [0, 2^16)
    let (proof, commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        chunks,
        randomness,
        CHUNK_SIZE_BITS as usize,
    )
    .expect("Failed to create range proof");

    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    (
        RangeProofBytes(Bytes::from_slice(&Env::default(), &proof_bytes)),
        commitments,
    )
}

// Generic helper function to verify range proofs
fn verify_range_generic<const N: usize>(
    commitments: &[CompressedRistretto],
    proof: &RangeProofBytes,
) -> Result<(), &'static str> {
    // Create the same bulletproof generators used in proving
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, N);

    // Create transcript with the same domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);

    // Deserialize the proof
    let proof_bytes: Vec<u8> = proof.0.iter().collect();
    let range_proof =
        RangeProof::from_bytes(&proof_bytes).map_err(|_| "Failed to deserialize range proof")?;

    // Verify the range proof
    range_proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            commitments,
            CHUNK_SIZE_BITS as usize,
        )
        .map_err(|_| "Range proof verification failed")
}

// Generic function to chunk a value into N 16-bit chunks.
// For compatibility with the bulletproofs library, this extends each chunk to 64 bits.
fn chunk_value<const N: usize>(value: u128) -> [u64; N] {
    let mut chunks = [0u64; N];
    for i in 0..N {
        let masked = (value >> (i * 16)) & 0xFFFF;
        assert!(masked <= u16::MAX as u128, "Chunk exceeds u16 max");
        chunks[i] = masked as u64;
    }
    chunks
}

// Chunks a u128 value into 8 16-bit chunks. For compatibility with the
// bulletproofs library, this extends each chunk to 64 bits.
fn chunk_u128(value: u128) -> [u64; 8] {
    chunk_value::<8>(value)
}

// Chunks a u64 value into 4 16-bit chunks. For compatibility with the
// bulletproofs library, this extends each chunk to 64 bits.
fn chunk_u64(value: u64) -> [u64; 4] {
    chunk_value::<4>(value as u128)
}

pub fn prove_new_balance_range(
    new_balance: u128,
    randomness: &[Scalar; BALANCE_CHUNKS],
) -> BalanceRangeProofResult {
    // Split balance into chunks
    let chunks = chunk_u128(new_balance);

    // Use generic helper to create the range proof
    let (proof, commitments) = prove_range_generic(&chunks, randomness);

    // Serialize the proof
    BalanceRangeProofResult { proof, commitments }
}

pub fn prove_transfer_amount_range(
    new_amount: u64,
    randomness: &[Scalar; AMOUNT_CHUNKS],
) -> AmountRangeProofResult {
    // Split amount into chunks
    let chunks = chunk_u64(new_amount);

    // Use generic helper to create the range proof
    let (proof, commitments) = prove_range_generic(&chunks, randomness);

    AmountRangeProofResult { proof, commitments }
}

pub fn verify_new_balance_range_proof(
    new_balance: &ConfidentialBalance,
    proof: &RangeProofBytes,
) -> Result<(), &'static str> {
    // Extract Pedersen commitments from the confidential balance
    let balance_points = new_balance.get_encrypted_balances();

    // Convert RistrettoPoints to CompressedRistretto for bulletproofs API
    let commitments: Vec<CompressedRistretto> = balance_points
        .iter()
        .map(|point| point.compress())
        .collect();

    // Use generic helper to verify the range proof
    verify_range_generic::<BALANCE_CHUNKS>(&commitments, proof)
}

pub fn verify_transfer_amount_range_proof(
    new_amount: &ConfidentialAmount,
    proof: &RangeProofBytes,
) -> Result<(), &'static str> {
    // Extract Pedersen commitments from the confidential amount
    let amount_points = new_amount.get_encrypted_amounts();

    // Convert RistrettoPoints to CompressedRistretto for bulletproofs API
    let commitments: Vec<CompressedRistretto> =
        amount_points.iter().map(|point| point.compress()).collect();

    // Use generic helper to verify the range proof
    verify_range_generic::<AMOUNT_CHUNKS>(&commitments, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    use std::array;

    #[test]
    fn test_prove_and_verify_new_balance_range() {
        // Test with a valid 128-bit balance
        let balance = 0x123456789ABCDEFu128;

        // Use zero randomness for the proof
        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];

        // Create the range proof
        let result = prove_new_balance_range(balance, &randomness);

        // Create a confidential balance using new_balance_with_no_randomness
        let confidential_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);

        // Verify the proof
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification failed: {:?}",
            verify_result
        );

        // Verify that the commitments from the proof match those from the confidential balance
        let expected_commitments: Vec<CompressedRistretto> = confidential_balance
            .get_encrypted_balances()
            .iter()
            .map(|point| point.compress())
            .collect();
        assert_eq!(
            result.commitments, expected_commitments,
            "Commitments from proof do not match expected commitments"
        );
    }

    #[test]
    fn test_verify_with_wrong_balance_fails() {
        // Create a proof for one balance
        let balance = 12345u128;
        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        let result = prove_new_balance_range(balance, &randomness);

        // But create commitments for a different balance
        let wrong_balance = 54321u128;
        let confidential_balance =
            ConfidentialBalance::new_balance_with_no_randomness(wrong_balance);

        // Verification should fail
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &result.proof);
        assert!(
            verify_result.is_err(),
            "Proof verification should have failed"
        );
    }

    #[test]
    fn test_verify_with_invalid_proof_bytes_fails() {
        // Create a valid balance
        let balance = 12345u128;
        let confidential_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);

        // Create invalid proof bytes
        let invalid_proof = RangeProofBytes(Bytes::from_slice(&Env::default(), &[0u8; 100]));

        // Verification should fail
        let result = verify_new_balance_range_proof(&confidential_balance, &invalid_proof);
        assert!(result.is_err(), "Proof verification should have failed");
    }

    #[test]
    fn test_prove_and_verify_transfer_amount_range() {
        // Test with a valid 64-bit amount
        let amount = 0x123456789ABCDEFu64;

        // Use zero randomness for the proof
        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];

        // Create the range proof
        let result = prove_transfer_amount_range(amount, &randomness);

        // Create a confidential amount using new_amount_with_no_randomness
        let confidential_amount = ConfidentialAmount::new_amount_with_no_randomness(amount);

        // Verify the proof
        let verify_result = verify_transfer_amount_range_proof(&confidential_amount, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification failed: {:?}",
            verify_result
        );
    }

    #[test]
    fn test_verify_transfer_amount_with_wrong_amount_fails() {
        // Create a proof for one amount
        let amount = 12345u64;
        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];
        let result = prove_transfer_amount_range(amount, &randomness);

        // But create commitments for a different amount
        let wrong_amount = 54321u64;
        let confidential_amount = ConfidentialAmount::new_amount_with_no_randomness(wrong_amount);

        // Verification should fail
        let verify_result = verify_transfer_amount_range_proof(&confidential_amount, &result.proof);
        assert!(
            verify_result.is_err(),
            "Proof verification should have failed"
        );
    }

    #[test]
    fn test_verify_transfer_amount_with_invalid_proof_bytes_fails() {
        // Create a valid amount
        let amount = 12345u64;
        let confidential_amount = ConfidentialAmount::new_amount_with_no_randomness(amount);

        // Create invalid proof bytes
        let invalid_proof = RangeProofBytes(Bytes::from_slice(&Env::default(), &[0u8; 100]));

        // Verification should fail
        let result = verify_transfer_amount_range_proof(&confidential_amount, &invalid_proof);
        assert!(result.is_err(), "Proof verification should have failed");
    }

    #[test]
    fn test_prove_and_verify_new_balance_range_with_nonzero_randomness() {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use rand::rngs::OsRng;

        // Test with a valid 128-bit balance
        let balance = 0x123456789ABCDEFu128;

        // Generate nonzero randomness for the proof
        let randomness = array::from_fn(|_| Scalar::random(&mut OsRng));

        // Create the range proof
        let result = prove_new_balance_range(balance, &randomness);

        // Create a fake confidential balance using the commitments from the proof
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk {
                amount: result.commitments[i]
                    .decompress()
                    .expect("Valid commitment"),
                // Use identity for handle since it's not used in verification
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_balance = ConfidentialBalance(encrypted_chunks);

        // Verify the proof
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification failed: {:?}",
            verify_result
        );

        // Verify that the commitments from the proof match those from the confidential balance
        let expected_commitments: Vec<CompressedRistretto> = confidential_balance
            .get_encrypted_balances()
            .iter()
            .map(|point| point.compress())
            .collect();
        assert_eq!(
            result.commitments, expected_commitments,
            "Commitments from proof do not match expected commitments"
        );
    }

    #[test]
    fn test_prove_and_verify_transfer_amount_range_with_nonzero_randomness() {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use rand::rngs::OsRng;

        // Test with a valid 64-bit amount
        let amount = 0x123456789ABCDEFu64;

        // Generate nonzero randomness for the proof
        let randomness = array::from_fn(|_| Scalar::random(&mut OsRng));

        // Create the range proof
        let result = prove_transfer_amount_range(amount, &randomness);

        // Create a fake confidential amount using the commitments from the proof
        // The handle values are arbitrary since they're not used in range proof verification
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk {
                amount: result.commitments[i]
                    .decompress()
                    .expect("Valid commitment"),
                // Use identity for handle since it's not used in verification
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_amount = ConfidentialAmount(encrypted_chunks);

        // Verify the proof
        let verify_result = verify_transfer_amount_range_proof(&confidential_amount, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification failed: {:?}",
            verify_result
        );

        // Verify that the commitments from the proof match those from the confidential amount
        let expected_commitments: Vec<CompressedRistretto> = confidential_amount
            .get_encrypted_amounts()
            .iter()
            .map(|point| point.compress())
            .collect();
        assert_eq!(
            result.commitments, expected_commitments,
            "Commitments from proof do not match expected commitments"
        );
    }
}
