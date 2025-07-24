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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn test_scalar_add() {
        let a = Scalar::from(5u64);
        let b = Scalar::from(7u64);
        let result = scalar_add(&a, &b);
        assert_eq!(result, Scalar::from(12u64));

        // Test with zero
        let zero = Scalar::from(0u64);
        assert_eq!(scalar_add(&a, &zero), a);

        // Test commutativity
        assert_eq!(scalar_add(&a, &b), scalar_add(&b, &a));
    }

    #[test]
    fn test_scalar_sub() {
        let a = Scalar::from(10u64);
        let b = Scalar::from(3u64);
        let result = scalar_sub(&a, &b);
        assert_eq!(result, Scalar::from(7u64));

        // Test subtraction with itself
        assert_eq!(scalar_sub(&a, &a), Scalar::from(0u64));

        // Test subtraction with zero
        let zero = Scalar::from(0u64);
        assert_eq!(scalar_sub(&a, &zero), a);
    }

    #[test]
    fn test_scalar_mul() {
        let a = Scalar::from(6u64);
        let b = Scalar::from(7u64);
        let result = scalar_mul(&a, &b);
        assert_eq!(result, Scalar::from(42u64));

        // Test multiplication by one
        let one = Scalar::from(1u64);
        assert_eq!(scalar_mul(&a, &one), a);

        // Test multiplication by zero
        let zero = Scalar::from(0u64);
        assert_eq!(scalar_mul(&a, &zero), zero);

        // Test commutativity
        assert_eq!(scalar_mul(&a, &b), scalar_mul(&b, &a));
    }

    #[test]
    fn test_scalar_to_bytes_and_back() {
        let scalar = Scalar::from(12345u64);
        let bytes = scalar_to_bytes(&scalar);
        let recovered = bytes_to_scalar(&bytes);
        assert_eq!(scalar, recovered);

        // Test with random scalar
        let random_scalar = Scalar::random(&mut rand::thread_rng());
        let bytes = scalar_to_bytes(&random_scalar);
        let recovered = bytes_to_scalar(&bytes);
        assert_eq!(random_scalar, recovered);
    }

    #[test]
    fn test_bytes_to_scalar_mod_order() {
        // Test that bytes_to_scalar properly reduces modulo the order
        let large_bytes = [0xff; 32];
        let scalar = bytes_to_scalar(&large_bytes);
        // The result should be valid (no panic) and deterministic
        let scalar2 = bytes_to_scalar(&large_bytes);
        assert_eq!(scalar, scalar2);
    }

    #[test]
    fn test_point_mul() {
        let base = constants::RISTRETTO_BASEPOINT_POINT;
        let scalar = Scalar::from(3u64);
        let result = point_mul(&base, &scalar);

        // Verify by adding base point three times
        let expected = &base + &base + &base;
        assert_eq!(result, expected);

        // Test multiplication by zero
        let zero = Scalar::from(0u64);
        let zero_result = point_mul(&base, &zero);
        assert_eq!(zero_result, RistrettoPoint::identity());

        // Test multiplication by one
        let one = Scalar::from(1u64);
        let one_result = point_mul(&base, &one);
        assert_eq!(one_result, base);
    }

    #[test]
    fn test_compress_and_decompress_point() {
        let point = constants::RISTRETTO_BASEPOINT_POINT;
        let compressed = compress_point(&point);
        let decompressed = decompress_point(&compressed);
        assert_eq!(point, decompressed);

        // Test with identity point
        let identity = RistrettoPoint::identity();
        let compressed_id = compress_point(&identity);
        let decompressed_id = decompress_point(&compressed_id);
        assert_eq!(identity, decompressed_id);
    }

    #[test]
    fn test_point_to_bytes_and_back() {
        let point = constants::RISTRETTO_BASEPOINT_POINT;
        let bytes = point_to_bytes(&point);
        let recovered = bytes_to_point(&bytes);
        assert_eq!(point, recovered);

        // Test with a different point
        let scalar = Scalar::from(42u64);
        let point2 = &point * &scalar;
        let bytes2 = point_to_bytes(&point2);
        let recovered2 = bytes_to_point(&bytes2);
        assert_eq!(point2, recovered2);
    }

    #[test]
    fn test_point_operations_consistency() {
        // Test that compress_point and point_to_bytes produce the same result
        let point = constants::RISTRETTO_BASEPOINT_POINT;
        let compressed = compress_point(&point);
        let bytes_from_compress = compressed.to_bytes();
        let bytes_from_point = point_to_bytes(&point);
        assert_eq!(bytes_from_compress, bytes_from_point);
    }

    #[test]
    fn test_scalar_arithmetic_properties() {
        let a = Scalar::from(15u64);
        let b = Scalar::from(8u64);
        let c = Scalar::from(3u64);

        // Test associativity of addition
        let left = scalar_add(&scalar_add(&a, &b), &c);
        let right = scalar_add(&a, &scalar_add(&b, &c));
        assert_eq!(left, right);

        // Test associativity of multiplication
        let left = scalar_mul(&scalar_mul(&a, &b), &c);
        let right = scalar_mul(&a, &scalar_mul(&b, &c));
        assert_eq!(left, right);

        // Test distributivity
        let left = scalar_mul(&a, &scalar_add(&b, &c));
        let right = scalar_add(&scalar_mul(&a, &b), &scalar_mul(&a, &c));
        assert_eq!(left, right);
    }
}
