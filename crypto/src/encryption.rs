use solana_zk_sdk::encryption::elgamal;


pub fn encrypt_chunk(pubkey: &elgamal::ElGamalPubkey, amount: u16)
    -> elgamal::ElGamalCiphertext
{
    // TODO: Should this function take a random value as input and use
    // `encrypt_with` instead?
    pubkey.encrypt(amount)
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