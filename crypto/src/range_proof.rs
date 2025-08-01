use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use soroban_sdk::{contracttype, Bytes};

use crate::confidential_balance::{
    ConfidentialAmount, ConfidentialBalance, AMOUNT_CHUNKS, BALANCE_CHUNKS,
};
use crate::proof::Error;

// TODO: this module depends on `std`, we need to decouple from it before shipping

const BULLETPROOFS_NUM_BITS: usize = 16;
// Max bitsize for range proofs
const RANGEPROOF_GENS_CAPACITY: usize = 64;
// Label to use for domain separation in bulletproofs transcripts
const BULLETPROOFS_DST: &[u8] = b"StellarConfidentialToken/BulletproofRangeProof";

#[contracttype]
#[derive(Debug, Clone)]
pub struct RangeProofBytes(pub Bytes);

/// Result of proving a balance value is within valid range.
///
/// Contains both the range proof and the Pedersen commitments used in the
/// proof.
#[derive(Debug, Clone)]
pub struct BalanceRangeProofResult {
    /// The serialized bulletproof demonstrating the balance chunks are in valid range [0, 2^16)
    pub proof: RangeProofBytes,
    /// Pedersen commitments for each balance chunk (8 commitments for 128-bit
    /// balance).
    ///
    /// Note: This field primarily exists for testing and assurance purposes,
    /// and may be removed in the future as these commitments should be
    /// obtainable through ConfidentialBalance constructors.
    pub commitments: Vec<CompressedRistretto>,
}

/// Result of proving a transfer amount is within valid range.
///
/// Contains both the range proof and the Pedersen commitments used in the
/// proof.
#[derive(Debug, Clone)]
pub struct AmountRangeProofResult {
    /// The serialized bulletproof demonstrating the amount chunks are in valid range [0, 2^16)
    pub proof: RangeProofBytes,
    /// Pedersen commitments for each amount chunk (4 commitments for 64-bit
    /// amount).
    ///
    /// Note: This field primarily exists for testing and assurance purposes,
    /// and may be removed in the future as these commitments should be
    /// obtainable through ConfidentialAmount constructors.
    pub commitments: Vec<CompressedRistretto>,
}


// Generic helper function to verify range proofs
fn verify_range_generic<const N: usize>(
    commitments: &[CompressedRistretto],
    proof: &RangeProofBytes,
) -> Result<(), Error> {
    // Create the same bulletproof generators used in proving
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGEPROOF_GENS_CAPACITY, N);

    // Create transcript with the same domain separation
    let mut transcript = Transcript::new(BULLETPROOFS_DST);

    // Deserialize the proof
    let proof_bytes: Vec<u8> = proof.0.iter().collect();
    let range_proof =
        RangeProof::from_bytes(&proof_bytes).map_err(|_| Error::RangeProofVerificationFailed)?;

    // TODO: the `verify_multiple_with_rng` on `std`, we need to decouple from it.
    // Either by calling `prove_multiple_with_rng` function and pass in a 
    // non-std dependent rng (RngCore + CryptoRng), or move the bulletproof
    // verification entirely to the host side.

    // Verify the range proof
    range_proof
        .verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            commitments,
            BULLETPROOFS_NUM_BITS as usize,
        )
        .map_err(|_| Error::RangeProofVerificationFailed)
}

/// Verifies a zero-knowledge range proof for a confidential balance.
///
/// This function extracts the Pedersen commitments from the provided
/// confidential balance and verifies that the associated range proof is valid.
/// The proof demonstrates that each of the 8 chunks of the balance is within
/// the valid range [0, 2^16).
pub fn verify_new_balance_range_proof(
    new_balance: &ConfidentialBalance,
    proof: &RangeProofBytes,
) -> Result<(), Error> {
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

/// Verifies a zero-knowledge range proof for a confidential transfer amount.
///
/// This function extracts the Pedersen commitments from the provided
/// confidential amount and verifies that the associated range proof is valid.
/// The proof demonstrates that each of the 4 chunks of the amount is within the
/// valid range [0, 2^16).
pub fn verify_transfer_amount_range_proof(
    new_amount: &ConfidentialAmount,
    proof: &RangeProofBytes,
) -> Result<(), Error> {
    // Extract Pedersen commitments from the confidential amount
    let amount_points = new_amount.get_encrypted_amounts();

    // Convert RistrettoPoints to CompressedRistretto for bulletproofs API
    let commitments: Vec<CompressedRistretto> =
        amount_points.iter().map(|point| point.compress()).collect();

    // Use generic helper to verify the range proof
    verify_range_generic::<AMOUNT_CHUNKS>(&commitments, proof)
}

#[cfg(any(test, feature="testutils"))]
pub mod testutils {
use super::*;
use curve25519_dalek::scalar::Scalar;
use soroban_sdk::Env;

// Generic function to chunk a value into N 16-bit chunks.  For compatibility
// with the bulletproofs library, this extends each chunk to 64 bits.
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


// Generic helper function to create range proofs for chunked values. Provides a
// proof that each chunk is in the range [0, 2^num_bits). With the exception of
// testing, `num_bits` should always be `BULLETPROOFS_NUM_BITS` (16).
pub(crate) fn prove_range_generic<const N: usize>(
    env: &Env,
    chunks: &[u64; N],
    randomness: &[Scalar; N],
    num_bits: usize,
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
        num_bits,
    )
    .expect("Failed to create range proof");

    // Serialize the proof
    let proof_bytes = proof.to_bytes();
    (
        RangeProofBytes(Bytes::from_slice(env, &proof_bytes)),
        commitments,
    )
}


/// Creates a zero-knowledge range proof for a 128-bit balance value.
///
/// This function splits the balance into 8 chunks of 16 bits each and creates a
/// bulletproof demonstrating that each chunk is within the valid range
/// [0, 2^16).
pub fn prove_new_balance_range(
    env: &Env,
    new_balance: u128,
    randomness: &[Scalar; BALANCE_CHUNKS],
) -> BalanceRangeProofResult {
    // Split balance into chunks
    let chunks = chunk_u128(new_balance);

    // Use generic helper to create the range proof
    let (proof, commitments) = prove_range_generic(env, &chunks, randomness, BULLETPROOFS_NUM_BITS);

    // Serialize the proof
    BalanceRangeProofResult { proof, commitments }
}

/// Creates a zero-knowledge range proof for a 64-bit transfer amount.
///
/// This function splits the amount into 4 chunks of 16 bits each and creates a
/// bulletproof demonstrating that each chunk is within the valid range
/// [0, 2^16).
pub fn prove_transfer_amount_range(
    env: &Env,
    new_amount: u64,
    randomness: &[Scalar; AMOUNT_CHUNKS],
) -> AmountRangeProofResult {
    // Split amount into chunks
    let chunks = chunk_u64(new_amount);

    // Use generic helper to create the range proof
    let (proof, commitments) = prove_range_generic(env, &chunks, randomness, BULLETPROOFS_NUM_BITS);

    AmountRangeProofResult { proof, commitments }
}

}

#[cfg(test)]
mod tests {
    use super::*;
    use super::testutils::*;
    use crate::arith;
    use crate::confidential_balance::EncryptedChunk;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::traits::Identity;
    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;
    use soroban_sdk::Env;
    use std::array;

    #[test]
    fn test_prove_and_verify_new_balance_range() {
        let env = Env::default();

        // Test with a valid 128-bit balance
        let balance = 0x123456789ABCDEFu128;

        // Use zero randomness for the proof
        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];

        // Create the range proof
        let result = prove_new_balance_range(&env, balance, &randomness);

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
        let env = Env::default();
        // Create a proof for one balance
        let balance = 12345u128;
        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        let result = prove_new_balance_range(&env, balance, &randomness);
        
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
        let env = Env::default();
        // Test with a valid 64-bit amount
        let amount = 0x123456789ABCDEFu64;

        // Use zero randomness for the proof
        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];

        // Create the range proof
        let result = prove_transfer_amount_range(&env, amount, &randomness);

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
        let env = Env::default();
        // Create a proof for one amount
        let amount = 12345u64;
        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];
        let result = prove_transfer_amount_range(&env, amount, &randomness);

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
        let env = Env::default();

        // Test with a valid 128-bit balance
        let balance = 0x123456789ABCDEFu128;

        // Generate nonzero randomness for the proof
        let randomness = array::from_fn(|_| Scalar::random(&mut OsRng));

        // Create the range proof
        let result = prove_new_balance_range(&env, balance, &randomness);

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
        let env = Env::default();

        // Test with a valid 64-bit amount
        let amount = 0x123456789ABCDEFu64;

        // Generate nonzero randomness for the proof
        let randomness = array::from_fn(|_| Scalar::random(&mut OsRng));

        // Create the range proof
        let result = prove_transfer_amount_range(&env, amount, &randomness);

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

    #[test]
    fn test_verify_balance_with_chunk_over_16_bits_fails() {
        let env = Env::default();

        // Create chunks where one chunk has a value > 2^16-1
        // We'll use values that fit in 32 bits but not 16 bits
        let chunks = [
            1000u64,  // Valid 16-bit value
            2000u64,  // Valid 16-bit value
            70000u64, // Over 16-bit limit (70000 > 65535)
            3000u64,  // Valid 16-bit value
            4000u64,  // Valid 16-bit value
            5000u64,  // Valid 16-bit value
            6000u64,  // Valid 16-bit value
            7000u64,  // Valid 16-bit value
        ];

        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];

        // Create a valid range proof for 32-bit chunks
        let (proof_32bit, commitments) = prove_range_generic(&env, &chunks, &randomness, 32);

        // Create a confidential balance using the commitments from the 32-bit proof
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk {
                amount: commitments[i].decompress().expect("Valid commitment"),
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_balance = ConfidentialBalance(encrypted_chunks);

        // Verification should fail because the proof is for 32-bit chunks
        // but verify_new_balance_range_proof expects 16-bit chunks
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &proof_32bit);
        assert!(
            verify_result.is_err(),
            "Proof verification should have failed for 32-bit proof when expecting 16-bit proof"
        );
    }

    #[test]
    fn test_verify_amount_with_chunk_over_16_bits_fails() {
        let env = Env::default();

        // Create chunks where one chunk has a value > 2^16-1
        // We'll use values that fit in 32 bits but not 16 bits
        let chunks = [
            1000u64,  // Valid 16-bit value
            80000u64, // Over 16-bit limit (80000 > 65535)
            3000u64,  // Valid 16-bit value
            4000u64,  // Valid 16-bit value
        ];

        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];

        // Create a valid range proof for 32-bit chunks
        let (proof_32bit, commitments) = prove_range_generic(&env, &chunks, &randomness, 32);

        // Create a confidential amount using the commitments from the 32-bit proof
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk {
                amount: commitments[i].decompress().expect("Valid commitment"),
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_amount = ConfidentialAmount(encrypted_chunks);

        // Verification should fail because the proof is for 32-bit chunks
        // but verify_transfer_amount_range_proof expects 16-bit chunks
        let verify_result = verify_transfer_amount_range_proof(&confidential_amount, &proof_32bit);
        assert!(
            verify_result.is_err(),
            "Proof verification should have failed for 32-bit proof when expecting 16-bit proof"
        );
    }

    #[test]
    fn test_verify_balance_with_max_valid_chunks() {
        let env = Env::default();
        // Create a balance where all chunks are at the maximum valid value (2^16-1 = 65535)
        let max_chunk_value = 65535u16; // 2^16 - 1
        let balance = (max_chunk_value as u128) * 0x0001000100010001000100010001u128; // All chunks are 0xFFFF

        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        let result = prove_new_balance_range(&env, balance, &randomness);

        // Create a confidential balance using the valid proof
        let confidential_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);

        // Verification should succeed because all chunks are exactly at the limit
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification should succeed for chunks at max valid value: {:?}",
            verify_result
        );
    }

    #[test]
    fn test_verify_amount_with_max_valid_chunks() {
        let env = Env::default();
        // Create an amount where all chunks are at the maximum valid value (2^16-1 = 65535)
        let max_chunk_value = 65535u16; // 2^16 - 1
        let amount = (max_chunk_value as u64) * 0x000100010001u64; // All chunks are 0xFFFF

        let randomness = [Scalar::ZERO; AMOUNT_CHUNKS];
        let result = prove_transfer_amount_range(&env, amount, &randomness);

        // Create a confidential amount using the valid proof
        let confidential_amount = ConfidentialAmount::new_amount_with_no_randomness(amount);

        // Verification should succeed because all chunks are exactly at the limit
        let verify_result = verify_transfer_amount_range_proof(&confidential_amount, &result.proof);
        assert!(
            verify_result.is_ok(),
            "Proof verification should succeed for chunks at max valid value: {:?}",
            verify_result
        );
    }

    #[test]
    fn test_verify_with_manipulated_commitments_fails() {
        let env = Env::default();

        // Create a proof for a valid balance
        let balance = 0x123456789ABCDEFu128;
        let randomness = [Scalar::ZERO; BALANCE_CHUNKS];
        let result = prove_new_balance_range(&env, balance, &randomness);

        // Create a confidential balance with completely different random commitments
        // that don't correspond to the proof
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            // Create random commitments that have no relation to the proof
            let random_scalar = Scalar::random(&mut OsRng);
            encrypted_chunks[i] = EncryptedChunk {
                amount: arith::basepoint_mul(&random_scalar),
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_balance = ConfidentialBalance(encrypted_chunks);

        // Verification should fail because the commitments don't match the proof
        let verify_result = verify_new_balance_range_proof(&confidential_balance, &result.proof);
        assert!(
            verify_result.is_err(),
            "Proof verification should have failed for manipulated commitments"
        );

        // Similarly test for amount
        let amount = 0x123456789ABCDEFu64;
        let amount_randomness = [Scalar::ZERO; AMOUNT_CHUNKS];
        let amount_result = prove_transfer_amount_range(&env, amount, &amount_randomness);

        // Create a confidential amount with manipulated commitments
        let mut amount_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            let random_scalar = Scalar::random(&mut OsRng);
            amount_chunks[i] = EncryptedChunk {
                amount: arith::basepoint_mul(&random_scalar),
                handle: RistrettoPoint::identity(),
            };
        }
        let confidential_amount = ConfidentialAmount(amount_chunks);

        // Verification should fail
        let amount_verify_result =
            verify_transfer_amount_range_proof(&confidential_amount, &amount_result.proof);
        assert!(
            amount_verify_result.is_err(),
            "Proof verification should have failed for manipulated amount commitments"
        );
    }
}
