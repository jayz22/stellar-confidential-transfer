use solana_zk_sdk::encryption::{elgamal, pedersen};
use std::convert::TryFrom;

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

// This joins potentially overlapping 32-bit chunks into a single i128
// TODO: Test this function. Include edge case where the final chunk is too
// large.
fn join_i128(chunks: &[u32; 8]) -> i128 {
    let mut value = 0i128;
    for (i, &chunk) in chunks.iter().enumerate() {
        // TODO: Need to handle potential overflow in the final chunk. Should
        // panic if the final chunk is larger than u16::MAX. Technically I think
        // it should be less than u16::MAX too, because we are using i128s to
        // represent values that cannot be negative, so we really only have 127
        // bits to work with.
        value += (chunk as i128) << (i * 16);
    }
    value
}

// TODO: Mark private
pub fn encrypt_chunk(pubkey: &elgamal::ElGamalPubkey, amount: u16, rand_value: &pedersen::PedersenOpening)
    -> elgamal::ElGamalCiphertext
{
    // TODO: Should this function take a random value as input and use
    // `encrypt_with` instead?
    pubkey.encrypt_with(amount, rand_value)
}

// TODO: Mark private
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

pub struct EncryptedI128 {
    commitments: [pedersen::PedersenCommitment; 8],
    handle: elgamal::DecryptHandle,
}

pub fn encrypt_i128(pubkey_bytes: &[u8; 32], value: i128, rand_value: &pedersen::PedersenOpening)
    -> EncryptedI128
{
    // TODO: Error handling on unwrap call?
    let pubkey = elgamal::ElGamalPubkey::try_from(pubkey_bytes as &[u8]).unwrap();
    let chunks = chunk_i128(value);
    // Encrypt first chunk and split into commitment and decryption handle
    let first_chunk_ciphertext = encrypt_chunk(&pubkey, chunks[0], rand_value);
    let mut commitments = [pedersen::PedersenCommitment::default(); 8];
    commitments[0] = first_chunk_ciphertext.commitment;
    let handle = first_chunk_ciphertext.handle;

    for (i, &chunk) in chunks[1..].iter().enumerate() {
        let ciphertext = encrypt_chunk(&pubkey, chunk, rand_value);
        commitments[i+1] = ciphertext.commitment;
        assert_eq!(ciphertext.handle, handle, "All chunks must have the same decryption handle");
    }
    // TODO: Is this unnecessarily copying these fields? Can I just construct
    // an EncryptedI128 directly and fill in the values from there?
    EncryptedI128 { commitments, handle }
}

pub fn decrypt_i128(secret_key: &elgamal::ElGamalSecretKey,
                    ciphertext: &EncryptedI128)
    -> i128
{
    let mut chunks = [0u32; 8];
    for (i, commitment) in ciphertext.commitments.iter().enumerate() {
        let ciphertext = elgamal::ElGamalCiphertext {
            commitment: commitment.clone(),
            handle: ciphertext.handle.clone(),
        };
        chunks[i] = decrypt_chunk(secret_key, &ciphertext);
    }
    join_i128(&chunks)
}

pub fn add_encrypted_i128(
    lhs: &EncryptedI128,
    rhs: &EncryptedI128,
) -> EncryptedI128 {
    // Add commitments pairwise
    let mut new_commitments = [pedersen::PedersenCommitment::default(); 8];
    for i in 0..8 {
        new_commitments[i] = lhs.commitments[i] + rhs.commitments[i];
    }
    EncryptedI128 {
        commitments: new_commitments,
        handle: lhs.handle + rhs.handle
    }
}

pub fn sub_encrypted_i128(
    lhs: &EncryptedI128,
    rhs: &EncryptedI128,
) -> EncryptedI128 {
    // Subtract commitments pairwise
    let mut new_commitments = [pedersen::PedersenCommitment::default(); 8];
    for i in 0..8 {
        new_commitments[i] = lhs.commitments[i] - rhs.commitments[i];
    }
    EncryptedI128 {
        commitments: new_commitments,
        handle: lhs.handle - rhs.handle
    }
}