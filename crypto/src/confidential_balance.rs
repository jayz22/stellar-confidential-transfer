use crate::arith;
use crate::arith::new_scalar_from_u64;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use soroban_sdk::{contracttype, BytesN, Env, Vec};
use core::{assert_eq, debug_assert};

pub const AMOUNT_CHUNKS: usize = 4;
pub const BALANCE_CHUNKS: usize = 8;
pub const CHUNK_SIZE_BITS: u64 = 16;
pub const RISTRETTO_FIELD_SIZE_BITS: usize = 32;

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
    pub amount: CompressedRistrettoBytes, // C
    pub handle: CompressedRistrettoBytes, // D
}

#[contracttype]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialBalanceBytes(pub Vec<EncryptedChunkBytes>); // 8 chunks

impl ConfidentialBalanceBytes {
    pub fn to_bytes(&self) -> [u8; 2 * BALANCE_CHUNKS * RISTRETTO_FIELD_SIZE_BITS] {
        assert_eq!(self.0.len() as usize, BALANCE_CHUNKS);
        let mut bytes = [0u8; 512];
        let mut i = 0;
        for chunk in self.0.iter() {
            bytes[i..i + 32].copy_from_slice(&chunk.amount.0.to_array());
            bytes[i + 32..i + 64].copy_from_slice(&chunk.handle.0.to_array());
            i += 64;
        }
        debug_assert!(i == 512);
        bytes
    }

    pub fn zero(e: &Env) -> Self {
        ConfidentialBalance::new_balance_with_no_randomness(0u128).to_env_bytes(e)
    }

    pub fn add_amount(e: &Env, balance: &Self, amount: &ConfidentialAmountBytes) -> Self {
        let mut balance = ConfidentialBalance::from_env_bytes(balance);
        balance.add_amount(ConfidentialAmount::from_env_bytes(amount));
        balance.to_env_bytes(e)
    }
}

#[contracttype]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialAmountBytes(pub Vec<EncryptedChunkBytes>); // 4 chunks

impl ConfidentialAmountBytes {
    pub fn to_bytes(&self) -> [u8; 2 * AMOUNT_CHUNKS * RISTRETTO_FIELD_SIZE_BITS] {
        assert_eq!(self.0.len() as usize, AMOUNT_CHUNKS);
        let mut bytes = [0u8; 256];
        let mut i = 0;
        for chunk in self.0.iter() {
            bytes[i..i + 32].copy_from_slice(&chunk.amount.0.to_array());
            bytes[i + 32..i + 64].copy_from_slice(&chunk.handle.0.to_array());
            i += 64;
        }
        debug_assert!(i == 256);
        bytes
    }

    pub fn add(e: &Env, lhs: &Self, rhs: &Self) -> Self {
        let lhs = ConfidentialAmount::from_env_bytes(lhs);
        let rhs = ConfidentialAmount::from_env_bytes(rhs);
        lhs.add(&rhs).to_env_bytes(e)
    }

    pub fn zero(e: &Env) -> Self {
        ConfidentialAmount::new_amount_with_no_randomness(0u64).to_env_bytes(e)
    }

    pub fn from_u64_with_no_randomness(e: &Env, amount: u64) -> Self {
        ConfidentialAmount::new_amount_with_no_randomness(amount).to_env_bytes(e)
    }
}

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

    #[cfg(any(test, feature = "testutils"))]
    pub fn new(val: &Scalar, randomness: &Scalar, ek: &RistrettoPoint) -> Self {
        EncryptedChunk {
            amount: arith::basepoint_mul(val)
                + arith::point_mul(&arith::hash_to_point_base(), randomness), // C = vG + rH
            handle: arith::point_mul(ek, randomness), // D = r*P
        }
    }

    pub fn to_env_bytes(&self, e: &Env) -> EncryptedChunkBytes {
        EncryptedChunkBytes {
            amount: CompressedRistrettoBytes(BytesN::<32>::from_array(
                e,
                &arith::point_to_bytes(&self.amount),
            )),
            handle: CompressedRistrettoBytes(BytesN::<32>::from_array(
                e,
                &arith::point_to_bytes(&self.handle),
            )),
        }
    }

    pub fn from_env_bytes(bytes: &EncryptedChunkBytes) -> Self {
        let amount = arith::bytes_to_point(&bytes.amount.0.to_array());
        let handle = arith::bytes_to_point(&bytes.handle.0.to_array());
        EncryptedChunk { amount, handle }
    }

    pub fn add(&self, other: &Self) -> Self {
        EncryptedChunk {
            amount: self.amount + other.amount,
            handle: self.handle + other.handle,
        }
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

    #[cfg(any(test, feature = "testutils"))]
    pub fn new_amount_from_u64(
        amount: u64,
        randomness: &[Scalar; AMOUNT_CHUNKS],
        ek: &RistrettoPoint,
    ) -> ConfidentialAmount {
        let balance_chunks = split_into_chunks_u64(amount);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::new(&balance_chunks[i], &randomness[i], ek);
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

    pub fn to_env_bytes(&self, e: &Env) -> ConfidentialAmountBytes {
        let mut chunks = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            chunks.push_back(self.0[i].to_env_bytes(e));
        }
        ConfidentialAmountBytes(chunks)
    }

    pub fn get_encrypted_amounts(&self) -> [RistrettoPoint; AMOUNT_CHUNKS] {
        let mut amounts = [RistrettoPoint::default(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            amounts[i] = self.0[i].amount;
        }
        amounts
    }

    pub fn get_decryption_handles(&self) -> [RistrettoPoint; AMOUNT_CHUNKS] {
        let mut handles = [RistrettoPoint::default(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            handles[i] = self.0[i].handle;
        }
        handles
    }

    // this just compare chunk by chunk, that each pair of chunks are the same value
    // it does *not* account for normalization semantics.
    pub fn encrypted_amounts_are_equal(lhs: &Self, rhs: &Self) -> bool {
        for i in 0..AMOUNT_CHUNKS {
            if lhs.0[i].amount != rhs.0[i].amount {
                return false;
            }
        }
        true
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result_chunks = [EncryptedChunk::zero_amount_and_randomness(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            result_chunks[i] = self.0[i].add(&other.0[i]);
        }
        ConfidentialAmount(result_chunks)
    }

    #[cfg(any(test, feature="testutils"))]
    // the amount is guaruanteed to fit into u64, here we retrieve the u128 which can be truncated safely    
    pub fn decrypt(&self, dk: &Scalar) -> u128 {
        use crate::arith::{point_mul, try_solve_dlp_kangaroo};
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::traits::Identity;
        
        let mut result = 0u128;
        
        for i in 0..AMOUNT_CHUNKS {
            // Compute mg = C - d*D = vG (the randomness cancels out)
            let mg = self.0[i].amount - point_mul(&self.0[i].handle, dk);
            
            // Try to solve discrete log using pollard-kangaroo
            let chunk_value = if mg == RistrettoPoint::identity() {
                // If mg is the identity point, the chunk value is 0
                0u64
            } else if let Some(scalar) = try_solve_dlp_kangaroo(&mg) {
                // Convert scalar back to u64 - for small values this is safe
                scalar_to_u64_safe(&scalar)
            } else {
                panic!("Failed to decrypt chunk {}: discrete log too large", i);
            };
            
            // Accumulate the chunk value into the result
            result += (chunk_value as u128) << (i as u64 * CHUNK_SIZE_BITS);
        }
        
        result
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

    #[cfg(any(test, feature = "testutils"))]
    pub fn new_balance_from_u128(
        balance: u128,
        randomness: &[Scalar; BALANCE_CHUNKS],
        ek: &RistrettoPoint,
    ) -> ConfidentialBalance {
        let balance_chunks = split_into_chunks_u128(balance);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::new(&balance_chunks[i], &randomness[i], ek);
        }
        ConfidentialBalance(encrypted_chunks)
    }

    pub fn from_env_bytes(bytes: &ConfidentialBalanceBytes) -> Self {
        assert_eq!(bytes.0.len() as usize, BALANCE_CHUNKS);
        let mut encrypted_chunks = [EncryptedChunk::zero_amount_and_randomness(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            encrypted_chunks[i] = EncryptedChunk::from_env_bytes(&bytes.0.get(i as u32).unwrap());
        }
        ConfidentialBalance(encrypted_chunks)
    }

    pub fn to_env_bytes(&self, e: &Env) -> ConfidentialBalanceBytes {
        let mut chunks = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            chunks.push_back(self.0[i].to_env_bytes(e));
        }
        ConfidentialBalanceBytes(chunks)
    }

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

    pub fn add_amount(&mut self, amount: ConfidentialAmount) {
        for i in 0..AMOUNT_CHUNKS {
            self.0[i] = self.0[i].add(&amount.0[i]);
        }
    }

    #[cfg(any(test, feature="testutils"))]
    pub fn decrypt(&self, dk: &Scalar) -> u128 {
        use crate::arith::{point_mul, try_solve_dlp_kangaroo};
        use curve25519_dalek::ristretto::RistrettoPoint;
        use curve25519_dalek::traits::Identity;
        
        let mut result = 0u128;
        
        for i in 0..BALANCE_CHUNKS {
            // Compute mg = C - d*D = vG (the randomness cancels out)
            let mg = self.0[i].amount - point_mul(&self.0[i].handle, dk);
            
            // Try to solve discrete log using pollard-kangaroo
            let chunk_value = if mg == RistrettoPoint::identity() {
                // If mg is the identity point, the chunk value is 0
                0u64
            } else if let Some(scalar) = try_solve_dlp_kangaroo(&mg) {
                // Convert scalar back to u64 - for small values this is safe
                scalar_to_u64_safe(&scalar)
            } else {
                panic!("Failed to decrypt chunk {}: discrete log too large", i);
            };
            
            // Accumulate the chunk value into the result
            result += (chunk_value as u128) << (i as u64 * CHUNK_SIZE_BITS);
        }
        
        result
    }
}

#[cfg(any(test, feature="testutils"))]
fn scalar_to_u64_safe(scalar: &Scalar) -> u64 {
    // Convert scalar to bytes and then to u64
    // This is safe for small values (up to 2^64-1)
    let bytes = scalar.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
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
pub fn split_into_chunk_bytes_u64(amount: u64) -> [[u8; 32]; AMOUNT_CHUNKS] {
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

#[cfg(any(test, feature = "testutils"))]
pub mod testutils {
    use crate::arith::point_mul;

    use super::*;
    use rand::rngs::OsRng;

    pub fn generate_balance_randomness() -> [Scalar; BALANCE_CHUNKS] {
        let mut res = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            res[i] = Scalar::random(&mut OsRng)
        }
        res
    }

    pub fn generate_amount_randomness() -> [Scalar; AMOUNT_CHUNKS] {
        let mut res = [Scalar::ZERO; AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            res[i] = Scalar::random(&mut OsRng)
        }
        res
    }

    pub fn new_balance_with_mismatched_decryption_handle(
        correct_balance: &ConfidentialBalanceBytes,
        ek: &RistrettoPoint,
    ) -> ConfidentialBalanceBytes {
        let r = generate_balance_randomness();
        let mut wrong_balance = ConfidentialBalance::from_env_bytes(correct_balance);
        for i in 0..BALANCE_CHUNKS {
            wrong_balance.0[i].handle = point_mul(ek, &r[i]);
        }
        wrong_balance.to_env_bytes(correct_balance.0.env())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
            (
                0x1234_5678_9abc_def0u64,
                vec![0xdef0, 0x9abc, 0x5678, 0x1234],
            ),
        ];

        for (value, expected_chunks) in test_cases {
            let chunks = split_into_chunks_u64(value);
            assert_eq!(chunks.len(), 4);

            for (i, expected) in expected_chunks.iter().enumerate() {
                let chunk_value =
                    chunks[i].to_bytes()[0] as u64 | ((chunks[i].to_bytes()[1] as u64) << 8);
                assert_eq!(chunk_value, *expected);
            }
        }
    }

    #[test]
    fn test_confidential_balance_encrypt_decrypt_roundtrip() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        // Test cases with various balance values
        let test_cases = vec![
            0u128,                    // Zero
            1u128,                    // Minimum positive
            0xffffu128,              // Single chunk maximum (65535)
            0x1_0000u128,            // Just over single chunk
            0x1234_5678u128,         // Multiple chunks
            0xffff_ffff_ffff_ffffu128, // Maximum that fits in 4 chunks
            0x1234_5678_9abc_def0_1234_5678_9abc_cdefu128, // Large value using all chunks
        ];

        for balance in test_cases {
            // Generate test keys
            let secret_key = new_scalar_from_u64(12345);
            let public_key = pubkey_from_secret_key(&secret_key);
            
            // Create randomness for encryption
            let randomness = [
                new_scalar_from_u64(100), new_scalar_from_u64(200), 
                new_scalar_from_u64(300), new_scalar_from_u64(400),
                new_scalar_from_u64(500), new_scalar_from_u64(600),
                new_scalar_from_u64(700), new_scalar_from_u64(800),
            ];
            
            // Encrypt the balance
            let confidential_balance = ConfidentialBalance::new_balance_from_u128(
                balance,
                &randomness,
                &public_key,
            );
            
            // Decrypt and verify
            let decrypted_balance = confidential_balance.decrypt(&secret_key);
            assert_eq!(
                decrypted_balance, balance,
                "Failed to decrypt balance: expected {}, got {}",
                balance, decrypted_balance
            );
        }
    }

    #[test]
    fn test_confidential_balance_no_randomness_decrypt() {
        // Test with no randomness (simpler case)
        let test_balances = vec![0u128, 42u128, 0xffffu128, 0x12345678u128];
        
        for balance in test_balances {
            let confidential_balance = ConfidentialBalance::new_balance_with_no_randomness(balance);
            
            // With no randomness, we can decrypt with any secret key (handles are identity)
            let dummy_secret = new_scalar_from_u64(0);
            let decrypted = confidential_balance.decrypt(&dummy_secret);
            
            assert_eq!(
                decrypted, balance,
                "No-randomness decrypt failed: expected {}, got {}",
                balance, decrypted
            );
        }
    }

    #[test]
    fn test_confidential_balance_zero_chunks() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let secret_key = new_scalar_from_u64(98765);
        let public_key = pubkey_from_secret_key(&secret_key);
        
        // Balance with many zero chunks
        let balance = 0x1000u128; // Only chunk 1 has value
        let randomness = [
            new_scalar_from_u64(1), new_scalar_from_u64(2), 
            new_scalar_from_u64(3), new_scalar_from_u64(4),
            new_scalar_from_u64(5), new_scalar_from_u64(6),
            new_scalar_from_u64(7), new_scalar_from_u64(8),
        ];
        
        let confidential_balance = ConfidentialBalance::new_balance_from_u128(
            balance,
            &randomness,
            &public_key,
        );
        
        let decrypted = confidential_balance.decrypt(&secret_key);
        assert_eq!(decrypted, balance);
    }

    #[test]
    fn test_confidential_balance_edge_values() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let secret_key = new_scalar_from_u64(55555);
        let public_key = pubkey_from_secret_key(&secret_key);
        
        // Test edge values for each chunk position
        let edge_cases = vec![
            0xffff_0000_0000_0000_0000_0000_0000_0000u128, // Max in chunk 7
            0x0000_ffff_0000_0000_0000_0000_0000_0000u128, // Max in chunk 6
            0x0000_0000_0000_0000_ffff_0000_0000_0000u128, // Max in chunk 3
            0x0000_0000_0000_0000_0000_0000_0000_ffffu128, // Max in chunk 0
        ];
        
        for balance in edge_cases {
            let randomness = [
                new_scalar_from_u64(11), new_scalar_from_u64(22), 
                new_scalar_from_u64(33), new_scalar_from_u64(44),
                new_scalar_from_u64(55), new_scalar_from_u64(66),
                new_scalar_from_u64(77), new_scalar_from_u64(88),
            ];
            
            let confidential_balance = ConfidentialBalance::new_balance_from_u128(
                balance,
                &randomness,
                &public_key,
            );
            
            let decrypted = confidential_balance.decrypt(&secret_key);
            assert_eq!(
                decrypted, balance,
                "Edge case failed: expected {:#x}, got {:#x}",
                balance, decrypted
            );
        }
    }

    #[test]
    fn test_scalar_to_u64_safe() {
        use crate::arith::new_scalar_from_u64;
        
        let test_values = vec![0u64, 1u64, 42u64, 0xffffu64, 0x12345678u64];
        
        for value in test_values {
            let scalar = new_scalar_from_u64(value);
            let converted = scalar_to_u64_safe(&scalar);
            assert_eq!(
                converted, value,
                "scalar_to_u64_safe failed: expected {}, got {}",
                value, converted
            );
        }
    }

    #[test]
    fn test_confidential_amount_encrypt_decrypt_roundtrip() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        // Test cases with various u64 amounts (since ConfidentialAmount is designed for u64)
        let test_cases = vec![
            0u64,                    // Zero
            1u64,                    // Minimum positive
            0xffffu64,              // Single chunk maximum (65535)
            0x1_0000u64,            // Just over single chunk
            0x1234_5678u64,         // Multiple chunks
            0xffff_ffff_ffff_ffffu64, // Maximum u64 value
        ];

        for amount in test_cases {
            // Generate test keys
            let secret_key = new_scalar_from_u64(98765);
            let public_key = pubkey_from_secret_key(&secret_key);
            
            // Create randomness for encryption (4 chunks for ConfidentialAmount)
            let randomness = [
                new_scalar_from_u64(111), new_scalar_from_u64(222), 
                new_scalar_from_u64(333), new_scalar_from_u64(444),
            ];
            
            // Encrypt the amount
            let confidential_amount = ConfidentialAmount::new_amount_from_u64(
                amount,
                &randomness,
                &public_key,
            );
            
            // Decrypt and verify
            let decrypted_amount = confidential_amount.decrypt(&secret_key);
            assert_eq!(
                decrypted_amount as u64, amount,
                "Failed to decrypt amount: expected {}, got {} (as u64: {})",
                amount, decrypted_amount, decrypted_amount as u64
            );
            
            // Verify the decrypted value fits safely in u64
            assert!(
                decrypted_amount <= u64::MAX as u128,
                "Decrypted amount {} exceeds u64::MAX", decrypted_amount
            );
        }
    }

    #[test]
    fn test_confidential_amount_no_randomness_decrypt() {
        // Test with no randomness (simpler case for amounts)
        let test_amounts = vec![0u64, 42u64, 0xffffu64, 0x12345678u64, u64::MAX];
        
        for amount in test_amounts {
            let confidential_amount = ConfidentialAmount::new_amount_with_no_randomness(amount);
            
            // With no randomness, we can decrypt with any secret key (handles are identity)
            let dummy_secret = new_scalar_from_u64(0);
            let decrypted = confidential_amount.decrypt(&dummy_secret);
            
            assert_eq!(
                decrypted as u64, amount,
                "No-randomness decrypt failed: expected {}, got {} (as u64: {})",
                amount, decrypted, decrypted as u64
            );
        }
    }

    #[test]
    fn test_confidential_amount_zero_chunks() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let secret_key = new_scalar_from_u64(11111);
        let public_key = pubkey_from_secret_key(&secret_key);
        
        // Amount with many zero chunks (only chunk 1 has value)
        let amount = 0x10000u64; // 65536, which puts value only in chunk 1
        let randomness = [
            new_scalar_from_u64(10), new_scalar_from_u64(20), 
            new_scalar_from_u64(30), new_scalar_from_u64(40),
        ];
        
        let confidential_amount = ConfidentialAmount::new_amount_from_u64(
            amount,
            &randomness,
            &public_key,
        );
        
        let decrypted = confidential_amount.decrypt(&secret_key);
        assert_eq!(decrypted as u64, amount);
    }

    #[test]
    fn test_confidential_amount_edge_values() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let secret_key = new_scalar_from_u64(77777);
        let public_key = pubkey_from_secret_key(&secret_key);
        
        // Test edge values for each chunk position (4 chunks for amounts)
        let edge_cases = vec![
            0xffff_0000_0000_0000u64, // Max in chunk 3
            0x0000_ffff_0000_0000u64, // Max in chunk 2  
            0x0000_0000_ffff_0000u64, // Max in chunk 1
            0x0000_0000_0000_ffffu64, // Max in chunk 0
            0xffff_ffff_0000_0000u64, // Max in chunks 2,3
            0x0000_0000_ffff_ffffu64, // Max in chunks 0,1
        ];
        
        for amount in edge_cases {
            let randomness = [
                new_scalar_from_u64(101), new_scalar_from_u64(202), 
                new_scalar_from_u64(303), new_scalar_from_u64(404),
            ];
            
            let confidential_amount = ConfidentialAmount::new_amount_from_u64(
                amount,
                &randomness,
                &public_key,
            );
            
            let decrypted = confidential_amount.decrypt(&secret_key);
            assert_eq!(
                decrypted as u64, amount,
                "Edge case failed: expected {:#x}, got {:#x} (as u64: {:#x})",
                amount, decrypted, decrypted as u64
            );
        }
    }

    #[test]
    fn test_confidential_amount_max_values() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let secret_key = new_scalar_from_u64(99999);
        let public_key = pubkey_from_secret_key(&secret_key);
        
        // Test maximum values
        let max_values = vec![
            u64::MAX,                 // Maximum u64
            0xffff_ffff_ffff_0000u64, // Almost max
            0x8000_0000_0000_0000u64, // Half of max (MSB set)
        ];
        
        for amount in max_values {
            let randomness = [
                new_scalar_from_u64(1001), new_scalar_from_u64(2002), 
                new_scalar_from_u64(3003), new_scalar_from_u64(4004),
            ];
            
            let confidential_amount = ConfidentialAmount::new_amount_from_u64(
                amount,
                &randomness,
                &public_key,
            );
            
            let decrypted = confidential_amount.decrypt(&secret_key);
            assert_eq!(
                decrypted as u64, amount,
                "Max value test failed: expected {:#x}, got {:#x}",
                amount, decrypted as u64
            );
            
            // Verify it fits in u64 range
            assert!(decrypted <= u64::MAX as u128);
        }
    }

    #[test]
    fn test_confidential_amount_different_keys() {
        use crate::arith::{new_scalar_from_u64, pubkey_from_secret_key};
        
        let amount = 0x123456789abcdef0u64;
        
        // Test with different key pairs
        let key_pairs = vec![
            (new_scalar_from_u64(1), new_scalar_from_u64(1)),
            (new_scalar_from_u64(12345), new_scalar_from_u64(12345)),
            (new_scalar_from_u64(u32::MAX as u64), new_scalar_from_u64(u32::MAX as u64)),
        ];
        
        for (encrypt_key, decrypt_key) in key_pairs {
            let public_key = pubkey_from_secret_key(&encrypt_key);
            let randomness = [
                new_scalar_from_u64(555), new_scalar_from_u64(666), 
                new_scalar_from_u64(777), new_scalar_from_u64(888),
            ];
            
            let confidential_amount = ConfidentialAmount::new_amount_from_u64(
                amount,
                &randomness,
                &public_key,
            );
            
            let decrypted = confidential_amount.decrypt(&decrypt_key);
            assert_eq!(
                decrypted as u64, amount,
                "Different keys test failed with keys ({}, {}): expected {:#x}, got {:#x}",
                encrypt_key.as_bytes()[0], decrypt_key.as_bytes()[0], amount, decrypted as u64
            );
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
                vec![
                    0xcdef, 0x89ab, 0x4567, 0x0123, 0xcdef, 0x89ab, 0x4567, 0x0123,
                ],
            ),
        ];

        for (value, expected_chunks) in test_cases {
            let chunks = split_into_chunks_u128(value);
            assert_eq!(chunks.len(), 8);

            for (i, expected) in expected_chunks.iter().enumerate() {
                let chunk_value =
                    chunks[i].to_bytes()[0] as u64 | ((chunks[i].to_bytes()[1] as u64) << 8);
                assert_eq!(chunk_value, *expected);
            }
        }
    }
}
