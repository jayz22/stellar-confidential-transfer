use rust_elgamal as elgamal;

fn bytes_to_point(bytes: &[u8]) -> elgamal::RistrettoPoint {
    assert_eq!(bytes.len(), 32, "Expected 32 bytes for Ristretto point");
    let comp_point = elgamal::CompressedRistretto::from_slice(bytes);
    match comp_point.decompress() {
        Some(point) => point,
        None => panic!("TODO: Failed to decompress point from bytes"),
    }
}

fn point_to_bytes(point: &elgamal::RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

pub fn binop(
    f : fn(&elgamal::RistrettoPoint, &elgamal::RistrettoPoint) -> elgamal::RistrettoPoint,
    lhs: &[u8; 32],
    rhs: &[u8; 32]) -> [u8; 32] {
    // Convert the byte arrays to Ristretto points
    let lhs_point = bytes_to_point(lhs);
    let rhs_point = bytes_to_point(rhs);

    // Perform the binop
    let result_point = f(&lhs_point, &rhs_point);

    // Convert the result back to a byte array
    point_to_bytes(&result_point)
}

pub fn add(lhs: [u8; 32], rhs: [u8; 32]) -> [u8; 32] {
    // TODO: Are there concerns about overflow here?
    binop(|&a, &b| a + b, &lhs, &rhs)
}

pub fn sub(lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    // TODO: Are the concerns about underflow here?
    binop(|&a, &b| a - b, &lhs, &rhs)
}

// TODO: Looks like generating a random blinding factor requires std, so this
// library assumes you've generated a secure blinding factor elsewhere. Is that
// OK? This function wont be called by a contract "in the clear", so maybe it
// should be split off into a separate library that can use std?
pub fn encrypt(pubkey: &elgamal::EncryptionKey, amount: i128, blinding_factor: elgamal::Scalar) -> [u8; 64] {
    // TODO: Throw an exception or return an error or something instead of
    // panicking?
    assert!(amount >=0, "Amount must be non-negative");

    // Convert the amount to a scalar
    // TODO: Is this right? The docs say the scalar is modulo $\ell$ in the
    // group. Is that what we want?
    let amount_scalar = elgamal::Scalar::from(amount.cast_unsigned());

    // Encrypt the amount using the public key and blinding factor
    // TODO: The docs say that `exp_encrypt_with` is much slow to decrypt and
    // offers a faster encryption scheme that takes points as input. I think
    // this is expected though. We know decryption will be slow. I don't think
    // the point version (`encrypt_with`) will work for us? I think the `exp` in
    // this function has to do with "exponentiation", which lines up with my
    // understanding of how we're using elgamal.
    let ciphertext = pubkey.exp_encrypt_with(amount_scalar, blinding_factor);
    let (p1, p2) = ciphertext.inner();

    // Convert the ciphertext to bytes
    // TODO: Is there a better way to concatenate two byte arrays?
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&point_to_bytes(&p1));
    bytes[32..].copy_from_slice(&point_to_bytes(&p2));

    bytes
}

pub fn decrypt(ciphertext: &[u8; 64], privkey: &elgamal::DecryptionKey) -> i128 {
    // Split the ciphertext into two points
    let (bytes1, bytes2) = ciphertext.split_at(32);
    let (p1, p2) = (
        bytes_to_point(bytes1),
        bytes_to_point(bytes2),
    );

    // Reconstruct the ciphertext from the points
    let ciphertext = elgamal::Ciphertext::from((p1, p2));

    // Decrypt the ciphertext using the private key
    let amount_point = privkey.decrypt(ciphertext);

    // TODO: Decrease input size and change this loop to test every possible
    // input value
    for i in 0..128 {
        let test_scalar = elgamal::Scalar::from(i as u128);
        let test_point = &test_scalar * &elgamal::GENERATOR_TABLE;
        if amount_point == test_point {
            return i;
        }
    }
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