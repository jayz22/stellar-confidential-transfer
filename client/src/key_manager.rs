use crate::types::KeyPairHex;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use soroban_sdk::Env;
use stellar_confidential_crypto::{
    arith::pubkey_from_secret_key,
    RistrettoPoint,
};

pub struct KeyManager {
    _env: Env,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            _env: Env::default(),
        }
    }

    /// Generate a single key pair from a seed, return (sk, pk)
    pub fn generate_key_pair(&self, seed: u64) -> (Scalar, RistrettoPoint) {
        // Create a seeded RNG from the provided seed
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Generate a cryptographically secure random scalar
        let secret = Scalar::random(&mut rng);
        let public = pubkey_from_secret_key(&secret);

        (secret, public)
    }

    pub fn generate_key_pair_hex(&self, seed: u64) -> KeyPairHex {
        let kp = self.generate_key_pair(seed);
        KeyPairHex {
            secret_key: hex::encode(kp.0.to_bytes()),
            public_key: hex::encode(kp.1.compress().to_bytes()),
        }
    }

    /// Convert hex string back to Scalar (for proof generation)
    pub fn hex_to_scalar(&self, hex_str: &str) -> Result<Scalar, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("Scalar must be 32 bytes".to_string());
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(array))
    }

    /// Convert hex string back to RistrettoPoint
    pub fn hex_to_point(&self, hex_str: &str) -> Result<RistrettoPoint, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
        if bytes.len() != 32 {
            return Err("Point must be 32 bytes".to_string());
        }
        let compressed = curve25519_dalek::ristretto::CompressedRistretto::from_slice(&bytes)
            .map_err(|_| "Invalid compressed point")?;
        compressed.decompress().ok_or("Cannot decompress point".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeded_key_generation_is_deterministic() {
        let key_manager = KeyManager::new();
        let seed = 12345u64;
        
        // Generate the same key pair twice with the same seed
        let keypair1 = key_manager.generate_key_pair_hex(seed);
        let keypair2 = key_manager.generate_key_pair_hex(seed);
        
        // They should be identical (deterministic)
        assert_eq!(keypair1.secret_key, keypair2.secret_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_different_seeds_generate_different_keys() {
        let key_manager = KeyManager::new();
        
        let keypair1 = key_manager.generate_key_pair_hex(12345u64);
        let keypair2 = key_manager.generate_key_pair_hex(54321u64);
        
        // Different seeds should generate different keys
        assert_ne!(keypair1.secret_key, keypair2.secret_key);
        assert_ne!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_seeded_key_generation_roundtrip_ok() {
        let key_manager = KeyManager::new();
        let keypair = key_manager.generate_key_pair_hex(42u64);
        
        // The generated secret key should be a valid scalar
        let secret_scalar = key_manager.hex_to_scalar(&keypair.secret_key);
        assert!(secret_scalar.is_ok());
        
        // The generated public key should be a valid point
        let public_point = key_manager.hex_to_point(&keypair.public_key);
        assert!(public_point.is_ok());
    }
}