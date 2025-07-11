use solana_zk_sdk::encryption::{elgamal, pedersen};
use std::convert::TryFrom;

/// Converts a 128-bit signed integer into an array of eight 16-bit chunks.
///
/// The value is split into 8 chunks of 16 bits each, stored in little-endian
/// order (least significant chunk first). This chunking enables efficient
/// encryption of large values using ElGamal encryption on smaller chunks.
///
/// # Arguments
/// * `value` - The i128 value to chunk. Must be non-negative.
///
/// # Returns
/// An array of 8 u16 values representing the chunked value.
///
/// # Panics
/// * If the value is negative
fn chunk_i128(value: i128) -> [u16; 8] {
    assert!(value >= 0, "Value must be non-negative");
    let mut chunks = [0u16; 8];
    for i in 0..8 {
        let masked = (value >> (i * 16)) & 0xFFFF;
        assert!(masked <= u16::MAX as i128, "Chunk exceeds u16 max");
        chunks[i] = masked as u16;
    }
    chunks
}

/// Reconstructs a 128-bit signed integer from an array of potentially
/// overlapping 32-bit chunks.
///
/// Each chunk is shifted by 16 bits relative to the previous chunk and summed
/// together.  This function is used to reconstruct decrypted values where each
/// chunk may contain values larger than 16 bits due to homomorphic operations.
///
/// # Arguments
/// * `chunks` - Array of 8 u32 values to join
///
/// # Returns
/// The reconstructed i128 value
///
/// # Panics
/// If the resulting value is negative (would overflow into the sign bit)
fn join_i128(chunks: &[u32; 8]) -> i128 {
    let mut value = 0i128;
    for (i, &chunk) in chunks.iter().enumerate() {
        value += (chunk as i128) << (i * 16);
    }
    assert!(value >= 0, "Joined value must be non-negative");
    value
}

/// Encrypts a single 16-bit chunk using ElGamal encryption.
///
/// # Arguments
/// * `pubkey` - The ElGamal public key to use for encryption
/// * `amount` - The 16-bit value to encrypt
/// * `rand_value` - The randomness for the encryption
///
/// # Returns
/// An ElGamal ciphertext containing the encrypted chunk
fn encrypt_chunk(
    pubkey: &elgamal::ElGamalPubkey,
    amount: u16,
    rand_value: &pedersen::PedersenOpening,
) -> elgamal::ElGamalCiphertext {
    pubkey.encrypt_with(amount, rand_value)
}

/// Decrypts a single ElGamal ciphertext chunk to recover a 32-bit value.
///
/// # Arguments
/// * `secret_key` - The ElGamal secret key for decryption
/// * `ciphertext` - The ciphertext to decrypt
///
/// # Returns
/// The decrypted u32 value
///
/// # Panics
/// * If decryption fails (e.g., ciphertext is malformed)
/// * If the decrypted value exceeds u32::MAX
fn decrypt_chunk(
    secret_key: &elgamal::ElGamalSecretKey,
    ciphertext: &elgamal::ElGamalCiphertext,
) -> u32 {
    match secret_key.decrypt_u32(ciphertext) {
        Some(value) => {
            assert!(value <= u32::MAX.into(), "Decrypted value exceeds u32 max");
            value as u32
        }
        None => panic!("Decryption failed"),
    }
}

/// Internal representation of an encrypted 128-bit integer.
///
/// This struct holds 8 Pedersen commitments (one for each chunk) and a shared
/// ElGamal decryption handle. All chunks share the same decryption handle to
/// enable efficient storage with the same randomness.
struct EncryptedI128 {
    commitments: [pedersen::PedersenCommitment; 8],
    handle: elgamal::DecryptHandle,
}

impl EncryptedI128 {
    /// Serializes the encrypted value to a byte representation.
    ///
    /// # Returns
    /// An `EncryptedI128Bytes` struct containing the serialized commitments and
    /// handle
    fn to_bytes(&self) -> EncryptedI128Bytes {
        let mut commitments_bytes = [[0u8; 32]; 8];
        for (i, commitment) in self.commitments.iter().enumerate() {
            commitments_bytes[i] = commitment.to_bytes();
        }

        EncryptedI128Bytes {
            commitments: commitments_bytes,
            handle: self.handle.to_bytes(),
        }
    }

    /// Deserializes an encrypted value from its byte representation.
    ///
    /// # Arguments
    /// * `bytes` - The serialized encrypted value
    ///
    /// # Returns
    /// The deserialized `EncryptedI128` struct
    ///
    /// # Panics
    /// * If any part of the structure is malformed
    fn from_bytes(bytes: &EncryptedI128Bytes) -> EncryptedI128 {
        let mut commitments = [pedersen::PedersenCommitment::default(); 8];
        for (i, commitment_bytes) in bytes.commitments.iter().enumerate() {
            match pedersen::PedersenCommitment::from_bytes(commitment_bytes) {
                Some(commitment) => commitments[i] = commitment,
                // TODO(Brett): Should we do something other than panic here?
                None => panic!("Invalid commitment bytes"),
            }
        }

        match elgamal::DecryptHandle::from_bytes(&bytes.handle) {
            Some(handle) => EncryptedI128 {
                commitments,
                handle,
            },
            // TODO(Brett): Should we do something other than panic here?
            None => panic!("Invalid handle bytes"),
        }
    }
}

/// Serialized form of an encrypted 128-bit integer.
///
/// This struct contains the byte representation of 8 Pedersen commitments
/// (32 bytes each) and one ElGamal decryption handle (32 bytes). This format
/// is suitable for storage and transmission.
pub struct EncryptedI128Bytes {
    pub commitments: [[u8; 32]; 8],
    pub handle: [u8; 32],
}

/// Encrypts a 128-bit signed integer using twisted ElGamal encryption.
///
/// The value is split into 8 chunks of 16 bits each, and each chunk is
/// encrypted separately using the same randomness.
///
/// # Arguments
/// * `pubkey_bytes` - The ElGamal public key as 32 bytes
/// * `value` - The i128 value to encrypt (must be non-negative)
/// * `rand_value` - The randomness to use for encryption (shared across all
///   chunks)
///
/// # Returns
/// The encrypted value as `EncryptedI128Bytes`
///
/// # Panics
/// * If the public key bytes are invalid
/// * If the value is negative
pub fn encrypt_i128(
    pubkey_bytes: &[u8; 32],
    value: i128,
    rand_value: &pedersen::PedersenOpening,
) -> EncryptedI128Bytes {
    // TODO(Brett): Error handling on failed conversion from bytes? Unwrap call
    // panics on failure.
    let pubkey = elgamal::ElGamalPubkey::try_from(pubkey_bytes as &[u8]).unwrap();
    let chunks = chunk_i128(value);
    // Encrypt first chunk and split into commitment and decryption handle
    let first_chunk_ciphertext = encrypt_chunk(&pubkey, chunks[0], rand_value);
    let mut commitments = [pedersen::PedersenCommitment::default(); 8];
    commitments[0] = first_chunk_ciphertext.commitment;
    let handle = first_chunk_ciphertext.handle;

    for (i, &chunk) in chunks[1..].iter().enumerate() {
        let ciphertext = encrypt_chunk(&pubkey, chunk, rand_value);
        commitments[i + 1] = ciphertext.commitment;
        assert_eq!(
            ciphertext.handle, handle,
            "All chunks must have the same decryption handle"
        );
    }
    EncryptedI128 {
        commitments,
        handle,
    }
    .to_bytes()
}

/// Decrypts an encrypted 128-bit integer.
///
/// Each chunk is decrypted separately and then combined to reconstruct the
/// original value. The decryption of each chunk yields a u32 value that may
/// be larger than 16 bits due to homomorphic operations.
///
/// # Arguments
/// * `secret_key` - The ElGamal secret key for decryption
/// * `ciphertext_bytes` - The encrypted value to decrypt
///
/// # Returns
/// The decrypted i128 value
///
/// # Panics
/// * If any chunk decryption fails
/// * If the reconstructed value is negative
pub fn decrypt_i128(
    secret_key: &elgamal::ElGamalSecretKey,
    ciphertext_bytes: &EncryptedI128Bytes,
) -> i128 {
    let ciphertext = EncryptedI128::from_bytes(ciphertext_bytes);
    let mut chunks = [0u32; 8];
    for (i, commitment) in ciphertext.commitments.iter().enumerate() {
        let ciphertext = elgamal::ElGamalCiphertext {
            commitment: commitment.clone(),
            handle: ciphertext.handle.clone(),
        };
        chunks[i] = decrypt_chunk(secret_key, &ciphertext);
    }
    join_i128(&chunks)
}

/// Adds two encrypted 128-bit integers homomorphically.
///
/// The addition is performed by adding corresponding commitments and handles
/// pairwise. This operation preserves the encryption while computing the sum.
///
/// # Arguments
/// * `lhs_bytes` - The first encrypted value
/// * `rhs_bytes` - The second encrypted value
///
/// # Returns
/// The encrypted sum as `EncryptedI128Bytes`
pub fn add_encrypted_i128(
    lhs_bytes: &EncryptedI128Bytes,
    rhs_bytes: &EncryptedI128Bytes,
) -> EncryptedI128Bytes {
    // Deserialize
    let lhs = EncryptedI128::from_bytes(lhs_bytes);
    let rhs = EncryptedI128::from_bytes(rhs_bytes);

    // Add commitments pairwise
    let mut new_commitments = [pedersen::PedersenCommitment::default(); 8];
    for i in 0..8 {
        new_commitments[i] = lhs.commitments[i] + rhs.commitments[i];
    }
    EncryptedI128 {
        commitments: new_commitments,
        handle: lhs.handle + rhs.handle,
    }
    .to_bytes()
}

/// Subtracts two encrypted 128-bit integers homomorphically.
///
/// The subtraction is performed by subtracting corresponding commitments and
/// handles pairwise. Note that this implementation currently has limitations
/// with borrowing across chunks.
///
/// # Arguments
/// * `lhs_bytes` - The encrypted minuend
/// * `rhs_bytes` - The encrypted subtrahend
///
/// # Returns
/// The encrypted difference as `EncryptedI128Bytes`
///
/// # Known Issues
/// * WARNING: This implementation is currently broken for cases where
///   the lower chunk needs to borrow from a higher chunk. This can lead
///   to panics during decryption if a chunk goes negative.
// TODO(Brett): Deduplicate with `add_encrypted_i128`. Perhaps use a generic
// binop function? Do this only after fixing issue with subtraction borrowing.
pub fn sub_encrypted_i128(
    lhs_bytes: &EncryptedI128Bytes,
    rhs_bytes: &EncryptedI128Bytes,
) -> EncryptedI128Bytes {
    // Deserialize
    let lhs = EncryptedI128::from_bytes(lhs_bytes);
    let rhs = EncryptedI128::from_bytes(rhs_bytes);

    // Subtract commitments pairwise
    let mut new_commitments = [pedersen::PedersenCommitment::default(); 8];
    for i in 0..8 {
        // TODO(Brett): This is subtly broken right now as it does not handle
        // borrowing from higher chunks to prevent lower chunks from going
        // negative. See the comment in `test_sub_encrypted_i128` for more
        // details. Remove 'Known issues' doc comment when fixed.
        new_commitments[i] = lhs.commitments[i] - rhs.commitments[i];
    }
    EncryptedI128 {
        commitments: new_commitments,
        handle: lhs.handle - rhs.handle,
    }
    .to_bytes()
}

// Tests for private functions
#[cfg(test)]
mod tests {
    use super::*;
    use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk::encryption::pedersen::PedersenOpening;

    // Test that encrypting and decrypting a single chunk works correctly.
    #[test]
    fn test_chunk_encryption_decryption() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);

        let amount: u16 = u16::MAX; // Use a maximum value for testing
        let rand_value = PedersenOpening::new_rand();
        let ciphertext: ElGamalCiphertext = encrypt_chunk(&pubkey, amount, &rand_value);
        let decrypted_amount: u32 = decrypt_chunk(&secret_key, &ciphertext);

        assert_eq!(decrypted_amount, amount as u32);
    }

    // Test the serialization and deserialization of EncryptedI128.
    #[test]
    fn test_serialize_deserialize_encrypted_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_value = PedersenOpening::new_rand();
        let value = 123456789i128;

        // Create an encrypted value (now returns EncryptedI128Bytes)
        let encrypted_bytes = encrypt_i128(&pubkey_bytes, value, &rand_value);

        // Convert to EncryptedI128 to test serialization
        let original_encrypted = EncryptedI128::from_bytes(&encrypted_bytes);

        // Serialize the encrypted value
        let serialized = original_encrypted.to_bytes();

        // Deserialize back
        let deserialized = EncryptedI128::from_bytes(&serialized);

        // Check that they are equal by comparing all fields
        for i in 0..8 {
            assert_eq!(
                original_encrypted.commitments[i],
                deserialized.commitments[i]
            );
        }
        assert_eq!(original_encrypted.handle, deserialized.handle);

        // Also verify that decryption still works correctly
        let decrypted_value = decrypt_i128(&secret_key, &serialized);
        assert_eq!(decrypted_value, value);
    }

    // Test the basic chunking and joining operations.
    #[test]
    fn test_simple_chunk_join_i128() {
        let val = 123456789i128;
        let chunked = chunk_i128(val);
        let chunked_as_u32: [u32; 8] = chunked.map(|x| x as u32);
        let joined = join_i128(&chunked_as_u32);
        assert_eq!(joined, val);
    }

    // Test join_i128 with chunks that exceed 16-bit boundaries.
    // This simulates the result of homomorphic operations where chunks
    // may contain values larger than 16 bits due to carries from addition.
    #[test]
    fn test_join_i128_with_overlapping_chunks() {
        let chunks: [u32; 8] = [
            0x1FFFF, // Overlaps into next position (requires 17 bits)
            0x20000, // Overlaps into next position
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];

        // Expected value
        let expected = 0x20001FFFF; // 0x1FFFF + (0x20000 << 16)

        let result = join_i128(&chunks);
        assert_eq!(result, expected);
    }

    // Test that join_i128 correctly panics when the result would be negative.
    #[test]
    #[should_panic(expected = "Joined value must be non-negative")]
    fn test_join_i128_negative_overflow() {
        // Test case: Values that would cause overflow into the sign bit
        // This should trigger the negative value assertion
        let chunks: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0x8000];
        // This would set the most significant bit, making the i128 negative
        join_i128(&chunks);
    }

    // Test join_i128 with the maximum positive i128 value.
    #[test]
    fn test_join_i128_maximum_positive() {
        // Test the maximum positive i128 value
        let chunks: [u32; 8] = [
            0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x7FFF,
        ];
        let expected = i128::MAX;
        assert_eq!(join_i128(&chunks), expected);
    }
}
