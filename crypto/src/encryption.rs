use rust_elgamal as elgamal;

fn bytes_to_point(bytes: &[u8; 32]) -> elgamal::RistrettoPoint {
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
    let lhs_point = bytes_to_point(&lhs);
    let rhs_point = bytes_to_point(&rhs);

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

pub fn encrypt(pubkey: &elgamal::EncryptionKey, amount: i128, blinding_factor: elgamal::Scalar) -> [u8; 64] {
    // TODO: Throw an exception or return an error or something instead of
    // panicking?
    assert!(amount >=0, "Amount must be non-negative");

    // Convert the amount to a scalar
    let amount_scalar = elgamal::Scalar::from(amount.cast_unsigned());

    // Encrypt the amount using the public key and blinding factor
    let ciphertext = pubkey.exp_encrypt_with(amount_scalar, blinding_factor);
    let (p1, p2) = ciphertext.inner();

    // Convert the ciphertext to bytes
    // TODO: Is there a better way to concatenate two byte arrays?
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&point_to_bytes(&p1));
    bytes[32..].copy_from_slice(&point_to_bytes(&p2));

    bytes
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