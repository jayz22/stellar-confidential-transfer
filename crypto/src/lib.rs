pub mod encryption;

#[cfg(test)]
mod tests {
    use super::encryption::{decrypt_chunk, encrypt_chunk, add, sub};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rust_elgamal as elgamal;

    #[test]
    fn test_encryption_decryption() {
        let mut rng = StdRng::from_entropy();
        let privkey = elgamal::DecryptionKey::new(&mut rng);
        let pubkey = privkey.encryption_key();

        // Maximum chunk amount (u16::MAX) takes ~5.5 seconds to decrypt on my machine
        let amount = 42; //u16::MAX;
        let blinding_factor = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let ciphertext = encrypt_chunk(&pubkey, amount, blinding_factor);

        // Decrypt the ciphertext
        let decrypted_amount = decrypt_chunk(&ciphertext, &privkey);

        assert_eq!(decrypted_amount, amount as u32);
    }

    #[test]
    fn test_add() {
        let mut rng = StdRng::from_entropy();
        let privkey = elgamal::DecryptionKey::new(&mut rng);
        let pubkey = privkey.encryption_key();

        let x1= 42;
        let r1 = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let c1= encrypt_chunk(&pubkey, x1, r1);

        let x2 = 24;
        let r2 = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let c2 = encrypt_chunk(&pubkey, x2, r2);

        // Add the ciphertexts
        let res_c = add(&c1, &c2);

        // Decrypt the ciphertext
        let decrypted_amount = decrypt_chunk(&res_c, &privkey);

        assert_eq!(decrypted_amount, (x1 + x2) as u32);
    }

    // TODO: Write a test_binop function to dedup the add and sub tests
    #[test]
    fn test_sub() {
        let mut rng = StdRng::from_entropy();
        let privkey = elgamal::DecryptionKey::new(&mut rng);
        let pubkey = privkey.encryption_key();

        let x1= 42;
        let r1 = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let c1= encrypt_chunk(&pubkey, x1, r1);

        let x2 = 24;
        let r2 = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let c2 = encrypt_chunk(&pubkey, x2, r2);

        // Subtract the ciphertexts
        let res_c = sub(&c1, &c2);

        // Decrypt the ciphertext
        let decrypted_amount = decrypt_chunk(&res_c, &privkey);

        assert_eq!(decrypted_amount, (x1 - x2) as u32);
    }


}