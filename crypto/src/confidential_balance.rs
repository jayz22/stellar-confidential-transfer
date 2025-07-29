use crate::arith;
use crate::{arith::new_scalar_from_u64 , RangeProof};
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

#[derive(Debug, Clone)]
pub struct EncryptedChunkBytes(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    amount: RistrettoPoint, // C
    handle: RistrettoPoint, // D
}

impl EncryptedChunk {
    pub fn new_chunk_no_randomness(val: &Scalar) -> Self {
        EncryptedChunk {
            amount: arith::basepoint_mul(val),
            handle: RistrettoPoint::identity(),
        }
    }

    pub fn to_bytes(&self) -> EncryptedChunkBytes {
        let mut bytes = Vec::new();
        bytes.extend(arith::point_to_bytes(&self.amount));
        bytes.extend(arith::point_to_bytes(&self.handle));
        EncryptedChunkBytes(bytes)
    }

    pub fn from_bytes(bytes: &EncryptedChunkBytes) -> Self {
        assert!(bytes.0.len() == 64, "EncryptedChunk must be 64 bytes");
        let amount = arith::bytes_to_point(&bytes.0[0..32]);
        let handle = arith::bytes_to_point(&bytes.0[32..64]);
        EncryptedChunk { amount, handle }
    }
}

#[derive(Debug, Clone)]
pub struct ConfidentialAmount(pub Vec<EncryptedChunk>); // 4 chunks
#[derive(Debug, Clone)]
pub struct ConfidentialBalance(pub Vec<EncryptedChunk>); // 8 chunks

impl ConfidentialAmount {
    pub fn new_amount_with_no_randomness(amount: u64) -> Self {
        let chunks = split_into_chunks_u64(amount);
        let encrypted_chunks = chunks
            .into_iter()
            .map(|chunk| EncryptedChunk::new_chunk_no_randomness(&chunk))
            .collect();
        ConfidentialAmount(encrypted_chunks)
    }
}

impl ConfidentialBalance {
    pub fn new_balance_with_no_randomness(balance: u128) -> Self {
        let chunks = split_into_chunks_u128(balance);
        let encrypted_chunks = chunks
            .into_iter()
            .map(|chunk| EncryptedChunk::new_chunk_no_randomness(&chunk))
            .collect();
        ConfidentialBalance(encrypted_chunks)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(|chunk| chunk.to_bytes().0).collect()
    }
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

/// Splits a 128-bit integer balance into eight 16-bit chunks, represented as `Scalar` values.
pub fn split_into_chunks_u128(balance: u128) -> Vec<Scalar> {
    (0..BALANCE_CHUNKS)
        .map(|i| {
            let chunk = (balance >> (i * CHUNK_SIZE_BITS)) & 0xffff;
            new_scalar_from_u64(chunk as u64)
        })
        .collect()
}

pub fn prove_new_balance_range(new_balance: u128, randomness: &Vec<Scalar>) -> RangeProof {
    todo!()
}

pub fn prove_transfer_amount_range(new_amount: u64, randomness: &Vec<Scalar>) -> RangeProof {
    todo!()
}

pub fn verify_new_balance_range_proof(new_balance: &ConfidentialBalance, proof: &RangeProof) {
    todo!()
}

pub fn verify_transfer_amount_range_proof(new_amount: &ConfidentialAmount, proof: &RangeProof) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_chunk_serialization() {
        // Test with zero value
        let zero_scalar = new_scalar_from_u64(0);
        let zero_chunk = EncryptedChunk::new_chunk_no_randomness(&zero_scalar);
        let zero_bytes = zero_chunk.to_bytes();
        let recovered_zero = EncryptedChunk::from_bytes(&zero_bytes);
        assert_eq!(zero_chunk.amount, recovered_zero.amount);
        assert_eq!(zero_chunk.handle, recovered_zero.handle);

        // Test with small value
        let small_scalar = new_scalar_from_u64(42);
        let small_chunk = EncryptedChunk::new_chunk_no_randomness(&small_scalar);
        let small_bytes = small_chunk.to_bytes();
        let recovered_small = EncryptedChunk::from_bytes(&small_bytes);
        assert_eq!(small_chunk.amount, recovered_small.amount);
        assert_eq!(small_chunk.handle, recovered_small.handle);

        // Test with max 16-bit value
        let max_scalar = new_scalar_from_u64(0xffff);
        let max_chunk = EncryptedChunk::new_chunk_no_randomness(&max_scalar);
        let max_bytes = max_chunk.to_bytes();
        let recovered_max = EncryptedChunk::from_bytes(&max_bytes);
        assert_eq!(max_chunk.amount, recovered_max.amount);
        assert_eq!(max_chunk.handle, recovered_max.handle);

        // Verify bytes length is always 64
        assert_eq!(zero_bytes.0.len(), 64);
        assert_eq!(small_bytes.0.len(), 64);
        assert_eq!(max_bytes.0.len(), 64);
    }

    #[test]
    fn test_encrypted_chunk_different_values_produce_different_bytes() {
        let scalar1 = new_scalar_from_u64(100);
        let scalar2 = new_scalar_from_u64(200);
        
        let chunk1 = EncryptedChunk::new_chunk_no_randomness(&scalar1);
        let chunk2 = EncryptedChunk::new_chunk_no_randomness(&scalar2);
        
        let bytes1 = chunk1.to_bytes();
        let bytes2 = chunk2.to_bytes();
        
        // Different values should produce different serializations
        assert_ne!(bytes1.0, bytes2.0);
    }

    #[test]
    #[should_panic(expected = "EncryptedChunk must be 64 bytes")]
    fn test_encrypted_chunk_from_bytes_wrong_length() {
        // Test with too few bytes
        let short_bytes = EncryptedChunkBytes(vec![0u8; 32]);
        EncryptedChunk::from_bytes(&short_bytes);
    }

    #[test]
    fn test_confidential_balance_to_bytes() {
        let balance = 0x0123456789ABCDEFu128;
        let conf_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);
        let bytes = conf_balance.to_bytes();
        
        // Should have 8 chunks * 64 bytes per chunk = 512 bytes
        assert_eq!(bytes.len(), 512);
        
        // Verify we can reconstruct each chunk
        for i in 0..8 {
            let chunk_bytes = EncryptedChunkBytes(bytes[i*64..(i+1)*64].to_vec());
            let recovered_chunk = EncryptedChunk::from_bytes(&chunk_bytes);
            assert_eq!(
                conf_balance.0[i].amount.compress(),
                recovered_chunk.amount.compress()
            );
            assert_eq!(
                conf_balance.0[i].handle.compress(),
                recovered_chunk.handle.compress()
            );
        }
    }

    #[test]
    fn test_split_into_chunks_u64() {
        // Test splitting various 64-bit values
        let test_cases = vec![
            (0u64, vec![0, 0, 0, 0]),
            (0xffffu64, vec![0xffff, 0, 0, 0]),
            (0x1234_5678u64, vec![0x5678, 0x1234, 0, 0]),
            (0x1234_5678_9abc_def0u64, vec![0xdef0, 0x9abc, 0x5678, 0x1234]),
        ];
        
        for (value, expected_chunks) in test_cases {
            let chunks = split_into_chunks_u64(value);
            assert_eq!(chunks.len(), 4);
            
            for (i, expected) in expected_chunks.iter().enumerate() {
                let chunk_value = chunks[i].to_bytes()[0] as u64 
                    | ((chunks[i].to_bytes()[1] as u64) << 8);
                assert_eq!(chunk_value, *expected);
            }
        }
    }

    #[test]
    fn test_split_into_chunks_u128() {
        // Test splitting various 128-bit values
        let test_cases = vec![
            (0u128, vec![0; 8]),
            (0xffffu128, vec![0xffff, 0, 0, 0, 0, 0, 0, 0]),
            (
                0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128,
                vec![0xcdef, 0x89ab, 0x4567, 0x0123, 0xcdef, 0x89ab, 0x4567, 0x0123],
            ),
        ];
        
        for (value, expected_chunks) in test_cases {
            let chunks = split_into_chunks_u128(value);
            assert_eq!(chunks.len(), 8);
            
            for (i, expected) in expected_chunks.iter().enumerate() {
                let chunk_value = chunks[i].to_bytes()[0] as u64 
                    | ((chunks[i].to_bytes()[1] as u64) << 8);
                assert_eq!(chunk_value, *expected);
            }
        }
    }
}
