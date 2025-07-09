pub mod encryption;


#[cfg(test)]
mod tests {
    use super::encryption::{decrypt_chunk, encrypt_chunk};
    use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalPubkey, ElGamalSecretKey};
    use solana_zk_sdk::encryption::pedersen::PedersenOpening;

    #[test]
    fn test_encryption_decryption() {
        let secret_key = ElGamalSecretKey::new_rand();
        let pubkey = ElGamalPubkey::new(&secret_key);

        let amount: u16 = u16::MAX; // Use a maximum value for testing
        let rand_value = PedersenOpening::new_rand();
        let ciphertext: ElGamalCiphertext = encrypt_chunk(&pubkey, amount, &rand_value);
        let decrypted_amount: u32 = decrypt_chunk(&secret_key, &ciphertext);

        assert_eq!(decrypted_amount, amount as u32);
    }
}