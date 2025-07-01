use rust_elgamal as elgamal;

fn bytes_to_point(bytes: &[u8; 32]) -> elgamal::RistrettoPoint {
    let comp_point = elgamal::CompressedRistretto::from_slice(bytes);
    match comp_point.decompress() {
        Some(point) => point,
        None => panic!("TODO: Failed to decompress point from bytes"),
    }

}

pub fn binop(
    f : fn(&elgamal::RistrettoPoint, &elgamal::RistrettoPoint) -> elgamal::RistrettoPoint,
    lhs: [u8; 32],
    rhs: [u8; 32]) -> [u8; 32] {
    // Convert the byte arrays to Ristretto points
    let lhs_point = bytes_to_point(&lhs);
    let rhs_point = bytes_to_point(&rhs);

    // Perform the binop
    let result_point = f(&lhs_point, &rhs_point);

    // Convert the result back to a byte array
    let compressed_result = result_point.compress();
    compressed_result.to_bytes()
}

pub fn add(lhs: [u8; 32], rhs: [u8; 32]) -> [u8; 32] {
    binop(|a, b| a + b, lhs, rhs)
}

pub fn sub(lhs: [u8; 32], rhs: [u8; 32]) -> [u8; 32] {
    binop(|a, b| a - b, lhs, rhs)
}

