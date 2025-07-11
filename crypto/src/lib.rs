pub mod encryption;


#[cfg(test)]
mod tests {
    use super::encryption::*;
    use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk::encryption::pedersen::PedersenOpening;

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

    #[test]
    fn test_encrypt_decrypt_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();

        let value = 123456789i128; // Example value for testing
        let rand_value = PedersenOpening::new_rand();
        let ciphertext = encrypt_i128(&pubkey_bytes, value, &rand_value);
        let decrypted_value = decrypt_i128(&secret_key, &ciphertext);
        assert_eq!(decrypted_value, value);
    }

    #[test]
    fn test_add_encrypted_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_value1 = PedersenOpening::new_rand();
        let rand_value2 = PedersenOpening::new_rand();
        let value1 = 123456789i128;
        let value2 = 987654321i128;
        let encrypted1 = encrypt_i128(&pubkey_bytes, value1, &rand_value1);
        let encrypted2 = encrypt_i128(&pubkey_bytes, value2, &rand_value2);
        let encrypted_sum = add_encrypted_i128(&encrypted1, &encrypted2);
        let decrypted_sum = decrypt_i128(&secret_key, &encrypted_sum);
        assert_eq!(decrypted_sum, value1 + value2);
    }

    #[test]
    fn test_sub_encrypted_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_value1 = PedersenOpening::new_rand();
        let rand_value2 = PedersenOpening::new_rand();
        // TODO: Subtraction is a little broken right now. Currently *every*
        // chunk needs to remain positive or this will fail to decrypt.
        // However, if a lower chunk needs to "borrow" from a higher chunk, it
        // will fail. See the commented out example below. How do other chains
        // handle this? Can we interpret these as signed integers instead?
        // value1 has an "all zero" lower chunk
        // let value1: i128 = 0x10000;
        // value2 is much smaller than value1, but has a non-zero lowest chunk.
        // Therefore, subtraction will need to borrow from the higher chunks.
        // But this currently fails during decryption.
        // let value2 = 0x1;
        // TODO: Be sure to test more complicated cases where the borrowing comes from multiple chunks away (e.g. 0x100000000 - 0x1)
        let value1 = 10;
        let value2 = 5;
        let encrypted1 = encrypt_i128(&pubkey_bytes, value1, &rand_value1);
        let encrypted2 = encrypt_i128(&pubkey_bytes, value2, &rand_value2);
        let encrypted_diff = sub_encrypted_i128(&encrypted1, &encrypted2);
        let decrypted_diff = decrypt_i128(&secret_key, &encrypted_diff);
        assert_eq!(decrypted_diff, value1 - value2);
    }

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
            assert_eq!(original_encrypted.commitments[i], deserialized.commitments[i]);
        }
        assert_eq!(original_encrypted.handle, deserialized.handle);

        // Also verify that decryption still works correctly
        let decrypted_value = decrypt_i128(&secret_key, &serialized);
        assert_eq!(decrypted_value, value);
    }

}