use std::result;

use rust_elgamal as elgamal;

fn bytes_to_point(bytes: &[u8]) -> elgamal::RistrettoPoint {
    assert_eq!(bytes.len(), 32, "Expected 32 bytes for Ristretto point");
    let comp_point = elgamal::CompressedRistretto::from_slice(bytes);
    match comp_point.decompress() {
        Some(point) => point,
        None => panic!("TODO: Failed to decompress point from bytes"),
    }
}

fn bytes_to_points(bytes: &[u8; 64])
   -> (elgamal::RistrettoPoint, elgamal::RistrettoPoint) {
    let (bytes1, bytes2) = bytes.split_at(32);
    (
        bytes_to_point(bytes1),
        bytes_to_point(bytes2),
    )
}

fn points_to_bytes(p1: &elgamal::RistrettoPoint, p2: &elgamal::RistrettoPoint) -> [u8; 64] {
    // TODO: Is there a better way to concatenate two byte arrays?
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&p1.compress().to_bytes());
    bytes[32..].copy_from_slice(&p2.compress().to_bytes());
    bytes
}

pub fn binop(
    f : fn(&elgamal::RistrettoPoint, &elgamal::RistrettoPoint) -> elgamal::RistrettoPoint,
    lhs: &[u8; 64],
    rhs: &[u8; 64]) -> [u8; 64] {
    // Convert the byte arrays to Ristretto points
    let (lhs_c, lhs_d) = bytes_to_points(lhs);
    let (rhs_c, rhs_d) = bytes_to_points(rhs);

    // Perform the binops
    let result_c = f(&lhs_c, &rhs_c);
    let result_d = f(&lhs_d, &rhs_d);

    // Convert the result back to a byte array
    points_to_bytes(&result_c, &result_d)
}

// TODO: `add` and `sub` might be shadowing some std functions. Maybe rename
// them?
pub fn add(lhs: &[u8; 64], rhs: &[u8; 64]) -> [u8; 64] {
    // TODO: Are there concerns about overflow here?
    binop(|&a, &b| a + b, &lhs, &rhs)
}

pub fn sub(lhs: &[u8; 64], rhs: &[u8; 64]) -> [u8; 64] {
    // TODO: Are the concerns about underflow here?
    binop(|&a, &b| a - b, &lhs, &rhs)
}

// TODO: Looks like generating a random blinding factor requires std, so this
// library assumes you've generated a secure blinding factor elsewhere. Is that
// OK? This function wont be called by a contract "in the clear", so maybe it
// should be split off into a separate library that can use std?
pub fn encrypt_chunk(pubkey: &elgamal::EncryptionKey, amount: u16, blinding_factor: elgamal::Scalar) -> [u8; 64] {
    // TODO: Throw an exception or return an error or something instead of
    // panicking?
    //assert!(amount >=0, "Amount must be non-negative");

    // Convert the amount to a scalar
    // TODO: Is this right? The docs say the scalar is modulo $\ell$ in the
    // group. Is that what we want?
    let amount_scalar = elgamal::Scalar::from(amount);

    // Encrypt the amount using the public key and blinding factor
    // TODO: The docs say that `exp_encrypt_with` is much slow to decrypt and
    // offers a faster encryption scheme that takes points as input. I think
    // this is expected though. We know decryption will be slow. I don't think
    // the point version (`encrypt_with`) will work for us? I think the `exp` in
    // this function has to do with "exponentiation", which lines up with my
    // understanding of how we're using elgamal.
    let ciphertext = pubkey.exp_encrypt_with(amount_scalar, blinding_factor);
    let (c, d) = ciphertext.inner();

    // Convert the ciphertext to bytes
    points_to_bytes(&c, &d)
}

// NOTE: Although chunks start out as 16-bit values, they may grow up to 32 bits
// during homomorphic operations. That is why this function returns a 32-bit
// integer. Note that the larger the value, the slower this function will be. In
// a real (non-prototype) application we would probably want this function to be
// constant time, but for now we will just use a linear search over possible
// decrypted points.
pub fn decrypt_chunk(ciphertext: &[u8; 64], privkey: &elgamal::DecryptionKey) -> u32 {
    // Split the ciphertext into two points
    let (p1, p2) = bytes_to_points(ciphertext);

    // Reconstruct the ciphertext from the points
    let ciphertext = elgamal::Ciphertext::from((p1, p2));

    // Decrypt the ciphertext using the private key
    let amount_point = privkey.decrypt(ciphertext);

    // TODO: Decrease input size and change this loop to test every possible
    // input value
    // TODO: This is the complete opposite of a timing-attack resilient
    // decryption
    for i in 0..= u32::MAX {
        let test_scalar = elgamal::Scalar::from(i);
        let test_point = &test_scalar * &elgamal::GENERATOR_TABLE;
        if amount_point == test_point {
            return i;
        }
    }

    // TODO: Do something other than panic here?
    panic!("Decryption failed: could not find matching scalar for point");
}

// TODO: Looks like there are two types of encrypt functions: Ones that take an
// RNG, and ones that take a pregenerated random number. Not sure which one we
// want to expose here; probably the one with the preselected random number.
// There's also a comment that the version that takes a scalar input is much
// slower to decrypt than the version that takes a curve point. Still, I think
// we want the scalar version.
//
// On the decrypt side, it looks like there is no random value passed in, so I
// guess the random value is encoded in the ciphertext somewhere?