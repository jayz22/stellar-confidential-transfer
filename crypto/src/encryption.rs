use solana_zk_sdk::encryption::{elgamal, pedersen};

// Convert an i128 into an array of 16-bit chunks.
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

pub fn encrypt_chunk(pubkey: &elgamal::ElGamalPubkey, amount: u16, rand_value: &pedersen::PedersenOpening)
    -> elgamal::ElGamalCiphertext
{
    // TODO: Should this function take a random value as input and use
    // `encrypt_with` instead?
    pubkey.encrypt_with(amount, rand_value)
}

pub fn decrypt_chunk(secret_key: &elgamal::ElGamalSecretKey,
                     ciphertext: &elgamal::ElGamalCiphertext)
    -> u32
{
    match secret_key.decrypt_u32(ciphertext) {
        Some(value) => {
            assert!(value <= u32::MAX.into(), "Decrypted value exceeds u32 max");
            value as u32
        }
        None => panic!("Decryption failed")
    }
}

pub fn encrypt_i128(pubkey: &elgamal::ElGamalPubkey, value: i128, rand_value: &pedersen::PedersenOpening)
    -> (Vec<pedersen::PedersenCommitment>, elgamal::DecryptHandle)
{
    let chunks = chunk_i128(value);
    // Encrypt first chunk and split into commitment and decryption handle
    let first_chunk_ciphertext = encrypt_chunk(pubkey, chunks[0], rand_value);
    let mut commitments = Vec::new();
    commitments.push(first_chunk_ciphertext.commitment);
    let handle = first_chunk_ciphertext.handle;

    for &chunk in &chunks[1..] {
        let ciphertext = encrypt_chunk(pubkey, chunk, rand_value);
        commitments.push(ciphertext.commitment);
        assert_eq!(ciphertext.handle, handle, "All chunks must have the same decryption handle");
    }
    assert_eq!(commitments.len(), 8, "Expected 8 encrypted chunks");
    (commitments, handle)
}
