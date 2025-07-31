pub mod arith;
pub mod encryption;
pub mod proof;
pub use proof::*;
pub mod confidential_balance;
pub use confidential_balance::*;
pub mod range_proof;

#[cfg(test)]
mod tests {
    use super::encryption::*;
    use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk::encryption::pedersen::PedersenOpening;

    fn encrypt_decrypt_helper(value: i128) {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_value = PedersenOpening::new_rand();
        let ciphertext = encrypt_i128(&pubkey_bytes, value, &rand_value);
        let decrypted_value = decrypt_i128(&secret_key, &ciphertext);
        assert_eq!(decrypted_value, value);
    }

    // Test the full encrypt-decrypt cycle for a 128-bit integer.
    #[test]
    fn test_encrypt_decrypt_i128() {
        // Midrange value
        encrypt_decrypt_helper(123456789i128);

        // Edge case: 0
        encrypt_decrypt_helper(0i128);

        // Edge case: max value
        encrypt_decrypt_helper(i128::MAX);
    }

    // Test homomorphic addition of two encrypted 128-bit integers.
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

    fn test_sub_helper(lhs: i128, rhs: i128) {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_lhs = PedersenOpening::new_rand();
        let rand_rhs = PedersenOpening::new_rand();
        let encrypted1 = encrypt_i128(&pubkey_bytes, lhs, &rand_lhs);
        let encrypted2 = encrypt_i128(&pubkey_bytes, rhs, &rand_rhs);
        let encrypted_diff = sub_encrypted_i128(&encrypted1, &encrypted2);
        let decrypted_diff = decrypt_i128(&secret_key, &encrypted_diff);
        assert_eq!(decrypted_diff, lhs - rhs);
    }

    // Test homomorphic subtraction of two encrypted 128-bit integers.
    #[test]
    fn test_sub_encrypted_i128() {
        // Simple case where no borrowing is needed
        test_sub_helper(10, 5);

        // Case where borrowing is needed from the next chunk
        test_sub_helper(0x10000, 0x1);

        // Case where borrowing is needed from multiple chunks
        test_sub_helper(0x100000000, 0x1);
    }
}
