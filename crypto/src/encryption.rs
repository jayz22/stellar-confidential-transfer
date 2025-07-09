use solana_zk_sdk::encryption::elgamal;


pub fn encrypt_chunk(pubkey: &elgamal::ElGamalPubkey, amount: u16)
    -> elgamal::ElGamalCiphertext
{
    // TODO: Should this function take a random value as input and use
    // `encrypt_with` instead?
    pubkey.encrypt(amount)
}