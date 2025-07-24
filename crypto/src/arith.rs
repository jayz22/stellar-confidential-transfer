use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

////////////////////////////////////////////////////////////////////////////////
/// scalar helpers
////////////////////////////////////////////////////////////////////////////////

pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a - b
}

pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a * b
}

pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

////////////////////////////////////////////////////////////////////////////////
/// point helpers
////////////////////////////////////////////////////////////////////////////////

pub fn point_mul(point: &RistrettoPoint, scalar: &Scalar) -> RistrettoPoint {
    point * scalar
}

pub fn compress_point(point: &RistrettoPoint) -> CompressedRistretto {
    point.compress()
}

pub fn decompress_point(compressed: &CompressedRistretto) -> RistrettoPoint {
    compressed.decompress().expect("Invalid compressed point")
}

pub fn point_to_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

pub fn bytes_to_point(bytes: &[u8; 32]) -> RistrettoPoint {
    // TODO(Brett): Error handling for invalid bytes
    decompress_point(&CompressedRistretto::from_slice(bytes).expect("Invalid compressed point"))
}
