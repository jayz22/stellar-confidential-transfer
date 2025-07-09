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

        let value = 123456789i128; // Example value for testing
        let rand_value = PedersenOpening::new_rand();
        let ciphertext = encrypt_i128(&pubkey, value, &rand_value);
        let decrypted_value = decrypt_i128(&secret_key, &ciphertext);
        assert_eq!(decrypted_value, value);
    }

    #[test]
    fn test_add_encrypted_i128() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);
        let rand_value1 = PedersenOpening::new_rand();
        let rand_value2 = PedersenOpening::new_rand();
        let value1 = 123456789i128;
        let value2 = 987654321i128;
        let encrypted1 = encrypt_i128(&pubkey, value1, &rand_value1);
        let encrypted2 = encrypt_i128(&pubkey, value2, &rand_value2);
        let encrypted_sum = encrypted1 + encrypted2;
        let decrypted_sum = decrypt_i128(&secret_key, &encrypted_sum);
        assert_eq!(decrypted_sum, value1 + value2);
    }
}