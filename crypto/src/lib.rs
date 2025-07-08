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

        // TODO: Maximum chunk amount (u16::MAX) takes ~5.5 seconds to decrypt
        // on my machine. This means that decrypting a u32::MAX (which is the
        // largest a chunk can grow to) would take 2^16 times longer, or a
        // little over 4 DAYS!  If we use constant time operations it would
        // *always* take that long to decrypt a single chunk. So perhaps we
        // should ensure the chunks stay *well* below 2^32. I think the counter
        // is already keeping it to a lower power of two, but I'm not sure what
        // that power is. We should check how long decryption times are for
        // whatever max int we can reach. For example, if we stay below 2^24,
        // then we can cut decryption time down to "only" ~23 minutes per chunk.
        //
        // On a related note, the design doc says the max counter value is
        // 10^16, but I think it's supposed to be 2^16? perhaps it should be
        // more like 2^8 given the note above (I think this would limit chunks
        // to 2^24, right?)
        let amount = 42; //u16::MAX;
        let blinding_factor = elgamal::Scalar::random(&mut rng);

        // Encrypt the amount
        let ciphertext = encrypt_chunk(&pubkey, amount, blinding_factor);

        // Decrypt the ciphertext
        let decrypted_amount = decrypt_chunk(&ciphertext, &privkey);

        assert_eq!(decrypted_amount, amount as u32);
    }

    fn test_binop(
        f: fn(&[u8; 64], &[u8; 64]) -> [u8; 64],
        lhs: u16,
        rhs: u16,
        expected: u32
    ) {
        let mut rng = StdRng::from_entropy();
        let privkey = elgamal::DecryptionKey::new(&mut rng);
        let pubkey = privkey.encryption_key();

        let r1 = elgamal::Scalar::random(&mut rng);
        let c1 = encrypt_chunk(&pubkey, lhs, r1);

        let r2 = elgamal::Scalar::random(&mut rng);
        let c2 = encrypt_chunk(&pubkey, rhs, r2);

        // Perform the binary operation
        let res_c = f(&c1, &c2);

        // Decrypt the result
        let res = decrypt_chunk(&res_c, &privkey);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_add() {
        let lhs = 42;
        let rhs = 24;
        test_binop(add, lhs, rhs, (lhs + rhs) as u32);
    }

    // Test addition with a values that would overflow a u16.
    // NOTE: This test takes a few seconds to run due to the expensive
    // decryption operation on large values.
    #[test]
    fn test_add_large() {
        let lhs = u16::MAX;
        let rhs = 400;
        test_binop(add, lhs, rhs, lhs as u32 + rhs as u32);
    }

    #[test]
    fn test_sub() {
        let lhs = 42;
        let rhs = 24;
        test_binop(sub, lhs, rhs, (lhs - rhs) as u32);
    }


}