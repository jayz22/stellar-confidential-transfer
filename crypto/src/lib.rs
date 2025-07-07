pub mod encryption;

#[cfg(test)]
mod tests {
    use super::encryption::{decrypt, encrypt};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rust_elgamal as elgamal;

    #[test]
    fn test_encryption_decryption() {
        let mut rng = StdRng::from_entropy();
        let privkey = elgamal::DecryptionKey::new(&mut rng);
        let pubkey = privkey.encryption_key();

        let amount: i128 = 112;
        let blinding_factor = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let ciphertext = encrypt(&pubkey, amount, blinding_factor);

        // Decrypt the ciphertext
        let decrypted_amount = decrypt(&ciphertext, &privkey);

        assert_eq!(decrypted_amount, amount);
    }
}