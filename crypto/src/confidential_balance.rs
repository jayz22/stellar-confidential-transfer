use crate::arith;
use crate::{arith::new_scalar_from_u64 , RangeProofBytes};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec as SorobanVec};

pub const AMOUNT_CHUNKS: usize = 4;
pub const BALANCE_CHUNKS: usize = 8;
pub const CHUNK_SIZE_BITS: u64 = 16;

#[contracttype]
#[derive(Debug, Clone)]
pub struct CompressedRistrettoBytes(pub BytesN<32>);

impl CompressedRistrettoBytes {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_array()
    }
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct EncryptedChunkBytes {
    amount: CompressedRistrettoBytes, // C
    handle: CompressedRistrettoBytes, // D
}

//TODO: Uncomment
// #[contracttype]
// #[derive(Debug, Clone)]
// pub struct ConfidentialBalanceBytes(pub SorobanVec<EncryptedChunkBytes>); // 8 chunks

// impl ConfidentialBalanceBytes {
//     pub fn to_bytes(&self) -> [u8; 512]{
//         assert_eq!(self.0.len(), 8);
//         let mut bytes = [0u8; 512];
//         let mut i = 0;
//         for chunk in self.0.iter() {
//             bytes[i..i+32].copy_from_slice(&chunk.amount.0.to_array());
//             bytes[i+32..i+64].copy_from_slice(&chunk.handle.0.to_array());
//             i+=64;
//         }
//         debug_assert!(i == 512);
//         bytes
//     }
// }

#[derive(Debug, Clone)]
pub struct ConfidentialAmountBytes(pub SorobanVec<EncryptedChunkBytes>); // 4 chunks



#[derive(Debug, Clone, Copy)]
pub struct EncryptedChunk {
    pub amount: RistrettoPoint, // C
    pub handle: RistrettoPoint, // D
}

impl EncryptedChunk {
    pub fn zero_amount_and_randomness() -> Self {
        EncryptedChunk {
            amount: RistrettoPoint::identity(),
            handle: RistrettoPoint::identity(),
        }
    }

    pub fn new_chunk_no_randomness(val: &Scalar) -> Self {
        EncryptedChunk {
            amount: arith::basepoint_mul(val),
            handle: RistrettoPoint::identity(),
        }
    }

    pub fn to_env_bytes(&self, e: &Env) -> EncryptedChunkBytes {
        EncryptedChunkBytes {
            amount: CompressedRistrettoBytes(BytesN::<32>::from_array(e, &arith::point_to_bytes(&self.amount))),
            handle: CompressedRistrettoBytes(BytesN::<32>::from_array(e, &arith::point_to_bytes(&self.handle))),
        }
    }

    pub fn from_env_bytes(bytes: &EncryptedChunkBytes) -> Self {
        let amount = arith::bytes_to_point(&bytes.amount.0.to_array());
        let handle = arith::bytes_to_point(&bytes.handle.0.to_array());
        EncryptedChunk { amount, handle }
    }
}

#[derive(Debug, Clone)]
pub struct ConfidentialAmount(pub [EncryptedChunk; AMOUNT_CHUNKS]); // 4 chunks
#[derive(Debug, Clone)]
pub struct ConfidentialBalance(pub [EncryptedChunk; BALANCE_CHUNKS]); // 8 chunks

impl ConfidentialAmount {
    pub fn new_amount_with_no_randomness(amount: u64) -> Self {
        let chunks = split_into_chunks_u64(amount);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::new_chunk_no_randomness(&chunks[i]);
        }
        ConfidentialAmount(encrypted_chunks)
    }

    pub fn from_env_bytes(bytes: &ConfidentialAmountBytes) -> Self {
        assert_eq!(bytes.0.len() as usize, AMOUNT_CHUNKS);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::from_env_bytes(&bytes.0.get(i as u32).unwrap());
        }
        ConfidentialAmount(encrypted_chunks)        
    }
    
    pub fn get_encrypted_amounts(&self) -> [RistrettoPoint; AMOUNT_CHUNKS] {
        let mut amounts = [RistrettoPoint::default(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            amounts[i] = self.0[i].amount;
        }
        amounts
    }
}

impl ConfidentialBalance {
    pub fn new_balance_with_no_randomness(balance: u128) -> Self {
        let chunks = split_into_chunks_u128(balance);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::new_chunk_no_randomness(&chunks[i]);
        }
        ConfidentialBalance(encrypted_chunks)
    }

    // pub fn from_env_bytes(bytes: &ConfidentialBalanceBytes) -> Self {
    //     assert_eq!(bytes.0.len() as usize, BALANCE_CHUNKS);
    //     let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
    //     for i in 0..BALANCE_CHUNKS {
    //         encrypted_chunks[i] = EncryptedChunk::from_env_bytes(&bytes.0.get(i as u32).unwrap());
    //     }
    //     ConfidentialBalance(encrypted_chunks)
    // }

    pub fn get_encrypted_balances(&self) -> [RistrettoPoint; BALANCE_CHUNKS] {
        let mut balances = [RistrettoPoint::default(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            balances[i] = self.0[i].amount;
        }
        balances
    }

    pub fn get_decryption_handles(&self) -> [RistrettoPoint; BALANCE_CHUNKS] {
        let mut handles = [RistrettoPoint::default(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            handles[i] = self.0[i].handle;
        }
        handles
    }
    // pub fn to_bytes(&self) -> Vec<u8> {
    //     self.0.iter().flat_map(|chunk| chunk.to_bytes().0).collect()
    // }
}

/// Splits a 64-bit integer amount into four 16-bit chunks, represented as `Scalar` values.
pub fn split_into_chunks_u64(amount: u64) -> [Scalar; AMOUNT_CHUNKS] {
    let mut res = [Scalar::ZERO; AMOUNT_CHUNKS];
    for i in 0..AMOUNT_CHUNKS {
        let chunk = (amount >> (i as u64 * CHUNK_SIZE_BITS)) & 0xffff;
        res[i] = new_scalar_from_u64(chunk);
    }
    res    
}

/// Splits a 64-bit integer amount into four 16-bit chunks, represented as `ScalarBytes` values.
pub fn split_into_chunk_bytes_u64(amount: u64) ->  [[u8; 32]; AMOUNT_CHUNKS] {
    let mut res = [[0; 32]; AMOUNT_CHUNKS];
    for i in 0..AMOUNT_CHUNKS {
        let chunk = (amount >> (i as u64 * CHUNK_SIZE_BITS)) & 0xffff;
        res[i] = new_scalar_from_u64(chunk).to_bytes();
    }
    res
}

/// Splits a 128-bit integer balance into eight 16-bit chunks, represented as `Scalar` values.
pub fn split_into_chunks_u128(balance: u128) -> [Scalar; BALANCE_CHUNKS] {
    let mut res = [Scalar::ZERO; BALANCE_CHUNKS];
    for i in 0..BALANCE_CHUNKS {
        let chunk = (balance >> (i as u64 * CHUNK_SIZE_BITS)) & 0xffff;
        res[i] = new_scalar_from_u64(chunk as u64);
    }
    res
}


#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn test_encrypted_chunk_serialization() {
    //     // Test with zero value
    //     let zero_scalar = new_scalar_from_u64(0);
    //     let zero_chunk = EncryptedChunk::new_chunk_no_randomness(&zero_scalar);
    //     let zero_bytes = zero_chunk.to_bytes();
    //     let recovered_zero = EncryptedChunk::from_bytes(&zero_bytes);
    //     assert_eq!(zero_chunk.amount, recovered_zero.amount);
    //     assert_eq!(zero_chunk.handle, recovered_zero.handle);

    //     // Test with small value
    //     let small_scalar = new_scalar_from_u64(42);
    //     let small_chunk = EncryptedChunk::new_chunk_no_randomness(&small_scalar);
    //     let small_bytes = small_chunk.to_bytes();
    //     let recovered_small = EncryptedChunk::from_bytes(&small_bytes);
    //     assert_eq!(small_chunk.amount, recovered_small.amount);
    //     assert_eq!(small_chunk.handle, recovered_small.handle);

    //     // Test with max 16-bit value
    //     let max_scalar = new_scalar_from_u64(0xffff);
    //     let max_chunk = EncryptedChunk::new_chunk_no_randomness(&max_scalar);
    //     let max_bytes = max_chunk.to_bytes();
    //     let recovered_max = EncryptedChunk::from_bytes(&max_bytes);
    //     assert_eq!(max_chunk.amount, recovered_max.amount);
    //     assert_eq!(max_chunk.handle, recovered_max.handle);

    //     // Verify bytes length is always 64
    //     assert_eq!(zero_bytes.0.len(), 64);
    //     assert_eq!(small_bytes.0.len(), 64);
    //     assert_eq!(max_bytes.0.len(), 64);
    // }

    // #[test]
    // fn test_encrypted_chunk_different_values_produce_different_bytes() {
    //     let scalar1 = new_scalar_from_u64(100);
    //     let scalar2 = new_scalar_from_u64(200);
        
    //     let chunk1 = EncryptedChunk::new_chunk_no_randomness(&scalar1);
    //     let chunk2 = EncryptedChunk::new_chunk_no_randomness(&scalar2);
        
    //     let bytes1 = chunk1.to_bytes();
    //     let bytes2 = chunk2.to_bytes();
        
    //     // Different values should produce different serializations
    //     assert_ne!(bytes1.0, bytes2.0);
    // }

    // #[test]
    // #[should_panic(expected = "EncryptedChunk must be 64 bytes")]
    // fn test_encrypted_chunk_from_bytes_wrong_length() {
    //     // Test with too few bytes
    //     let short_bytes = EncryptedChunkBytes(vec![0u8; 32]);
    //     EncryptedChunk::from_bytes(&short_bytes);
    // }

    // #[test]
    // fn test_confidential_balance_to_bytes() {
    //     let balance = 0x0123456789ABCDEFu128;
    //     let conf_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);
    //     let bytes = conf_balance.to_bytes();
        
    //     // Should have 8 chunks * 64 bytes per chunk = 512 bytes
    //     assert_eq!(bytes.len(), 512);
        
    //     // Verify we can reconstruct each chunk
    //     for i in 0..8 {
    //         let chunk_bytes = EncryptedChunkBytes(bytes[i*64..(i+1)*64].to_vec());
    //         let recovered_chunk = EncryptedChunk::from_bytes(&chunk_bytes);
    //         assert_eq!(
    //             conf_balance.0[i].amount.compress(),
    //             recovered_chunk.amount.compress()
    //         );
    //         assert_eq!(
    //             conf_balance.0[i].handle.compress(),
    //             recovered_chunk.handle.compress()
    //         );
    //     }
    // }

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
