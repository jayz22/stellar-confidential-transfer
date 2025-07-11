pub mod encryption;

#[cfg(test)]
mod tests {
    use super::encryption::*;
    use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk::encryption::pedersen::PedersenOpening;

    // Test the full encrypt-decrypt cycle for a 128-bit integer.
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

    // Test homomorphic subtraction of two encrypted 128-bit integers.
    // TODO(Brett): This test only passes with simple values that do not require
    // borrowing between chunks due to known bugs with subtraction that likely
    // need to be addressed during decryption.
    #[test]
    fn test_sub_encrypted_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let pubkey_bytes: [u8; 32] = pubkey.into();
        let rand_value1 = PedersenOpening::new_rand();
        let rand_value2 = PedersenOpening::new_rand();
        // TODO(Brett): Subtraction is a little broken right now. Currently
        // *every* chunk needs to remain positive or this will fail to decrypt.
        // However, if a lower chunk needs to "borrow" from a higher chunk, it
        // will fail. See the commented out example below. How do other chains
        // handle this? Can we interpret these as signed integers instead?
        // value1 has an "all zero" lower chunk
        // let value1: i128 = 0x10000;
        // value2 is much smaller than value1, but has a non-zero lowest chunk.
        // Therefore, subtraction will need to borrow from the higher chunks.
        // But this currently fails during decryption.
        // let value2 = 0x1;
        // TODO(Brett): Be sure to test more complicated cases where the
        // borrowing comes from multiple chunks away (e.g. 0x100000000 - 0x1)
        let value1 = 10;
        let value2 = 5;
        let encrypted1 = encrypt_i128(&pubkey_bytes, value1, &rand_value1);
        let encrypted2 = encrypt_i128(&pubkey_bytes, value2, &rand_value2);
        let encrypted_diff = sub_encrypted_i128(&encrypted1, &encrypted2);
        let decrypted_diff = decrypt_i128(&secret_key, &encrypted_diff);
        assert_eq!(decrypted_diff, value1 - value2);
    }
}
