use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use sha2::Sha512;

use crate::{ScalarBytes, AMOUNT_CHUNKS, CHUNK_SIZE_BITS};

////////////////////////////////////////////////////////////////////////////////
/// scalar helpers
////////////////////////////////////////////////////////////////////////////////

/// Create a scalar from a u64 value.
pub fn new_scalar_from_u64(value: u64) -> Scalar {
    Scalar::from(value)
}

/// Create a scalar from a u128 value.
pub fn new_scalar_from_u128(value: u128) -> Scalar {
    Scalar::from(value)
}

/// Add two scalars.
pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

/// Add a scalar to another in place.
pub fn scalar_add_assign(a: &mut Scalar, b: &Scalar) {
    *a += b;
}

/// Subtract two scalars.
pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a - b
}

/// Subtract a scalar from another in place.
pub fn scalar_sub_assign(a: &mut Scalar, b: &Scalar) {
    *a -= b;
}

/// Multiply two scalars.
pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a * b
}

/// Multiply a scalar by another in place.
pub fn scalar_mul_assign(a: &mut Scalar, b: &Scalar) {
    *a *= b;
}

/// Convert a scalar to bytes.
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

/// Convert bytes to a scalar (reduced modulo the group order).
pub fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

////////////////////////////////////////////////////////////////////////////////
/// point helpers
////////////////////////////////////////////////////////////////////////////////

/// Get the base point of the Ristretto group.
pub fn basepoint() -> RistrettoPoint {
    constants::RISTRETTO_BASEPOINT_POINT
}

/// Multiply the base point by a scalar.
pub fn basepoint_mul(scalar: &Scalar) -> RistrettoPoint {
    scalar * constants::RISTRETTO_BASEPOINT_TABLE
}

/// Returns the hash-to-point result of serializing the basepoint of the
/// Ristretto255 group.
pub fn hash_to_point_base() -> RistrettoPoint {
    // The point derived from the SHA3-512 hash of the basepoint.
    const HASH_BASE_POINT: [u8; 32] = [
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74,
        0x5f, 0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87,
        0x11, 0x34,
    ];
    bytes_to_point(&HASH_BASE_POINT)
}

/// Multiply a point by a scalar.
pub fn point_mul(point: &RistrettoPoint, scalar: &Scalar) -> RistrettoPoint {
    point * scalar
}

/// Compress a point to its compressed form.
pub fn point_compress(point: &RistrettoPoint) -> CompressedRistretto {
    point.compress()
}

/// Decompress a compressed point.
pub fn point_decompress(compressed: &CompressedRistretto) -> RistrettoPoint {
    compressed.decompress().expect("Invalid compressed point")
}

/// Convert a point to bytes.
pub fn point_to_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

/// Convert bytes to a point.
pub fn bytes_to_point(bytes: &[u8]) -> RistrettoPoint {
    // TODO(Brett): Error handling for invalid bytes
    assert!(bytes.len() == 32, "Bytes must be 32 bytes long");
    point_decompress(&CompressedRistretto::from_slice(bytes).expect("Invalid compressed point"))
}

/// Check if two points are equal.
pub fn point_equals(a: &RistrettoPoint, b: &RistrettoPoint) -> bool {
    a == b
}

/// Compute the sum of multiple scalar-point products.
pub fn multi_scalar_mul(points: &[RistrettoPoint], scalars: &[Scalar]) -> RistrettoPoint {
    assert_eq!(
        points.len(),
        scalars.len(),
        "Points and scalars must have the same length"
    );
    RistrettoPoint::multiscalar_mul(scalars, points)
}

pub fn new_scalar_from_sha2_512(bytes: &Vec<u8>) -> Scalar {
    Scalar::hash_from_bytes::<Sha512>(bytes)
}

/// Raises 2 to the power of the provided exponent and returns the result as a scalar.
pub fn new_scalar_from_pow2(exp: u8) -> Scalar {
    new_scalar_from_u128(1 << exp)
}


/// Calculates the linear combination of the provided scalars.
/// Computes the sum of element-wise products: sum(lhs[i] * rhs[i]) for all i.
pub fn scalar_linear_combination(lhs: &[Scalar], rhs: &[Scalar]) -> Scalar {
    assert_eq!(lhs.len(), rhs.len(), "Vectors must have the same length");
    
    let mut result = Scalar::from(0u64);
    
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        let product = scalar_mul(l, r);
        scalar_add_assign(&mut result, &product);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    // Check that our hash_to_point_base function produces the expected point.
    #[test]
    fn test_hash_to_point_base() {
        use sha3::Sha3_512;

        // Compute expected point by hashing basepoint as SHA3-512 and
        // constructing a point from it.
        let basepoint_bytes = basepoint().compress().to_bytes();
        let expected = RistrettoPoint::hash_from_bytes::<Sha3_512>(&basepoint_bytes);

        assert_eq!(
            hash_to_point_base(),
            expected,
            "Got different point than expected"
        );
    }

    #[test]
    fn test_basepoint_mul() {
        // Test multiplication by zero
        let zero = Scalar::from(0u64);
        let result = basepoint_mul(&zero);
        assert_eq!(result, RistrettoPoint::identity());

        // Test multiplication by one
        let one = Scalar::from(1u64);
        let result = basepoint_mul(&one);
        assert_eq!(result, basepoint());

        // Test multiplication by small scalar
        let scalar = Scalar::from(5u64);
        let result = basepoint_mul(&scalar);
        let expected = &basepoint() + &basepoint() + &basepoint() + &basepoint() + &basepoint();
        assert_eq!(result, expected);

        // Test that basepoint_mul is consistent with point_mul
        let scalar = Scalar::from(42u64);
        let result_basepoint_mul = basepoint_mul(&scalar);
        let result_point_mul = point_mul(&basepoint(), &scalar);
        assert_eq!(result_basepoint_mul, result_point_mul);

        // Test with large scalar
        let large_scalar = Scalar::from(0x1234567890abcdefu64);
        let result = basepoint_mul(&large_scalar);
        let expected = point_mul(&basepoint(), &large_scalar);
        assert_eq!(result, expected);

        // Test that different scalars produce different points
        let scalar1 = Scalar::from(7u64);
        let scalar2 = Scalar::from(11u64);
        let result1 = basepoint_mul(&scalar1);
        let result2 = basepoint_mul(&scalar2);
        assert_ne!(result1, result2);

        // Test distributivity: basepoint_mul(a + b) = basepoint_mul(a) + basepoint_mul(b)
        let a = Scalar::from(13u64);
        let b = Scalar::from(17u64);
        let sum = scalar_add(&a, &b);
        let result_sum = basepoint_mul(&sum);
        let result_separate = &basepoint_mul(&a) + &basepoint_mul(&b);
        assert_eq!(result_sum, result_separate);
    }

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
        let compressed = point_compress(&point);
        let decompressed = point_decompress(&compressed);
        assert_eq!(point, decompressed);

        // Test with identity point
        let identity = RistrettoPoint::identity();
        let compressed_id = point_compress(&identity);
        let decompressed_id = point_decompress(&compressed_id);
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
        let compressed = point_compress(&point);
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

    #[test]
    fn test_scalar_add_assign() {
        let mut a = Scalar::from(5u64);
        let b = Scalar::from(7u64);
        let expected = scalar_add(&a, &b);

        scalar_add_assign(&mut a, &b);
        assert_eq!(a, expected);
        assert_eq!(a, Scalar::from(12u64));

        // Test with zero
        let mut a = Scalar::from(10u64);
        let zero = Scalar::from(0u64);
        scalar_add_assign(&mut a, &zero);
        assert_eq!(a, Scalar::from(10u64));

        // Test multiple additions
        let mut a = Scalar::from(1u64);
        let b = Scalar::from(2u64);
        let c = Scalar::from(3u64);
        scalar_add_assign(&mut a, &b);
        scalar_add_assign(&mut a, &c);
        assert_eq!(a, Scalar::from(6u64));
    }

    #[test]
    fn test_scalar_sub_assign() {
        let mut a = Scalar::from(10u64);
        let b = Scalar::from(3u64);
        let expected = scalar_sub(&a, &b);

        scalar_sub_assign(&mut a, &b);
        assert_eq!(a, expected);
        assert_eq!(a, Scalar::from(7u64));

        // Test subtraction with zero
        let mut a = Scalar::from(15u64);
        let zero = Scalar::from(0u64);
        scalar_sub_assign(&mut a, &zero);
        assert_eq!(a, Scalar::from(15u64));

        // Test subtraction with itself
        let mut a = Scalar::from(20u64);
        let b = a.clone();
        scalar_sub_assign(&mut a, &b);
        assert_eq!(a, Scalar::from(0u64));

        // Test multiple subtractions
        let mut a = Scalar::from(20u64);
        let b = Scalar::from(5u64);
        let c = Scalar::from(3u64);
        scalar_sub_assign(&mut a, &b);
        scalar_sub_assign(&mut a, &c);
        assert_eq!(a, Scalar::from(12u64));
    }

    #[test]
    fn test_scalar_mul_assign() {
        let mut a = Scalar::from(6u64);
        let b = Scalar::from(7u64);
        let expected = scalar_mul(&a, &b);

        scalar_mul_assign(&mut a, &b);
        assert_eq!(a, expected);
        assert_eq!(a, Scalar::from(42u64));

        // Test multiplication by one
        let mut a = Scalar::from(25u64);
        let one = Scalar::from(1u64);
        scalar_mul_assign(&mut a, &one);
        assert_eq!(a, Scalar::from(25u64));

        // Test multiplication by zero
        let mut a = Scalar::from(100u64);
        let zero = Scalar::from(0u64);
        scalar_mul_assign(&mut a, &zero);
        assert_eq!(a, Scalar::from(0u64));

        // Test multiple multiplications
        let mut a = Scalar::from(2u64);
        let b = Scalar::from(3u64);
        let c = Scalar::from(4u64);
        scalar_mul_assign(&mut a, &b);
        scalar_mul_assign(&mut a, &c);
        assert_eq!(a, Scalar::from(24u64));
    }

    #[test]
    fn test_multi_scalar_mul() {
        let base = constants::RISTRETTO_BASEPOINT_POINT;

        // Test with single point and scalar
        let points = vec![base];
        let scalars = vec![Scalar::from(5u64)];
        let result = multi_scalar_mul(&points, &scalars);
        let expected = point_mul(&base, &Scalar::from(5u64));
        assert_eq!(result, expected);

        // Test with multiple points and scalars
        let point1 = base;
        let point2 = point_mul(&base, &Scalar::from(2u64));
        let point3 = point_mul(&base, &Scalar::from(3u64));
        let points = vec![point1, point2, point3];
        let scalars = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let result = multi_scalar_mul(&points, &scalars);
        // Expected: 1*base + 2*(2*base) + 3*(3*base) = 1*base + 4*base + 9*base = 14*base
        let expected = point_mul(&base, &Scalar::from(14u64));
        assert_eq!(result, expected);

        // Test with zero scalars
        let points = vec![base, point2];
        let scalars = vec![Scalar::from(0u64), Scalar::from(0u64)];
        let result = multi_scalar_mul(&points, &scalars);
        assert_eq!(result, RistrettoPoint::identity());

        // Test with mixed zero and non-zero scalars
        let points = vec![base, point2, point3];
        let scalars = vec![Scalar::from(0u64), Scalar::from(5u64), Scalar::from(0u64)];
        let result = multi_scalar_mul(&points, &scalars);
        // Expected: 0*base + 5*(2*base) + 0*(3*base) = 10*base
        let expected = point_mul(&base, &Scalar::from(10u64));
        assert_eq!(result, expected);

        // Test empty vectors
        let points: Vec<RistrettoPoint> = vec![];
        let scalars: Vec<Scalar> = vec![];
        let result = multi_scalar_mul(&points, &scalars);
        assert_eq!(result, RistrettoPoint::identity());

        // Test with identity point
        let identity = RistrettoPoint::identity();
        let points = vec![identity, base];
        let scalars = vec![Scalar::from(100u64), Scalar::from(7u64)];
        let result = multi_scalar_mul(&points, &scalars);
        // Expected: 100*identity + 7*base = 0 + 7*base = 7*base
        let expected = point_mul(&base, &Scalar::from(7u64));
        assert_eq!(result, expected);
    }

    #[test]
    #[should_panic(expected = "Points and scalars must have the same length")]
    fn test_multi_scalar_mul_length_mismatch() {
        let base = constants::RISTRETTO_BASEPOINT_POINT;
        let points = vec![base, base];
        let scalars = vec![Scalar::from(1u64)];
        multi_scalar_mul(&points, &scalars);
    }
}
