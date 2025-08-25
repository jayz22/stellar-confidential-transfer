use crate::types::{AccountKeys, KeyPair};
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

    /// Generate a single key pair from a seed
    pub fn generate_key_pair(&self, seed: u64) -> KeyPair {
        // Create a seeded RNG from the provided seed
        let mut rng = StdRng::seed_from_u64(seed);
        
        // Generate a cryptographically secure random scalar
        let secret = Scalar::random(&mut rng);
        let public = pubkey_from_secret_key(&secret);

        KeyPair {
            secret_key_hex: hex::encode(secret.to_bytes()),
            public_key_hex: hex::encode(public.compress().to_bytes()),
        }
    }

    /// Generate keys from seeds using the existing testutils functions (for backward compatibility)
    pub fn generate_keys_from_seeds(
        &self,
        alice_seed: u64,
        bob_seed: u64,
        auditor_seed: u64,
    ) -> AccountKeys {
        AccountKeys {
            alice: self.generate_key_pair(alice_seed),
            bob: self.generate_key_pair(bob_seed),
            auditor: self.generate_key_pair(auditor_seed),
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
        let keypair1 = key_manager.generate_key_pair(seed);
        let keypair2 = key_manager.generate_key_pair(seed);
        
        // They should be identical (deterministic)
        assert_eq!(keypair1.secret_key_hex, keypair2.secret_key_hex);
        assert_eq!(keypair1.public_key_hex, keypair2.public_key_hex);
    }

    #[test]
    fn test_different_seeds_generate_different_keys() {
        let key_manager = KeyManager::new();
        
        let keypair1 = key_manager.generate_key_pair(12345u64);
        let keypair2 = key_manager.generate_key_pair(54321u64);
        
        // Different seeds should generate different keys
        assert_ne!(keypair1.secret_key_hex, keypair2.secret_key_hex);
        assert_ne!(keypair1.public_key_hex, keypair2.public_key_hex);
    }

    #[test]
    fn test_seeded_key_generation_produces_valid_scalars() {
        let key_manager = KeyManager::new();
        let keypair = key_manager.generate_key_pair(42u64);
        
        // The generated secret key should be a valid scalar
        let secret_scalar = key_manager.hex_to_scalar(&keypair.secret_key_hex);
        assert!(secret_scalar.is_ok());
        
        // The generated public key should be a valid point
        let public_point = key_manager.hex_to_point(&keypair.public_key_hex);
        assert!(public_point.is_ok());
    }
}