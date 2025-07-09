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
}