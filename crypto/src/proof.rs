use crate::{
    arith::{
        basepoint, bytes_to_point, bytes_to_scalar, hash_to_point_base, new_scalar_from_sha2_512, new_scalar_from_u64, point_to_bytes, aggregate_scalar_chunks, aggregate_point_chunks
    },
    confidential_balance::*,
};
use crate::range_proof::{verify_new_balance_range_proof, verify_transfer_amount_range_proof, RangeProofBytes};
use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use soroban_sdk::{contracttype, BytesN, Env, Vec};


const FIAT_SHAMIR_NEW_BALANCE_SIGMA_DST: &[u8] =
    b"StellarConfidentialToken/NewBalanceProofFiatShamir";
const FIAT_SHAMIR_TRANSFER_SIGMA_DST: &[u8] = b"StellarConfidentialToken/TransferProofFiatShamir";


#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    SigmaProtocolVerifyFailed = 1,
    RangeProofVerificationFailed = 2,
    Unknown = 99,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct ScalarBytes(pub BytesN<32>);

impl ScalarBytes {
    pub fn from_scalar(s: &Scalar, e: &Env) -> ScalarBytes {
        ScalarBytes(BytesN::from_array(e, &s.to_bytes()))
    }
}

#[contracttype]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPubkeyBytes(BytesN<32>);

impl CompressedPubkeyBytes {
    pub fn to_point(&self) -> RistrettoPoint {
        bytes_to_point(&self.0.to_array())
    }

    pub fn from_point(e: &Env, pt: &RistrettoPoint) -> Self {
        CompressedPubkeyBytes(BytesN::from_array(e, &point_to_bytes(&pt)))
    }
}

/// Represents the proof structure for validating a withdrawal operation.
#[contracttype]
#[derive(Debug, Clone)]
pub struct NewBalanceProofBytes {
    /// Sigma proof ensuring that the withdrawal operation maintains balance integrity.
    pub sigma_proof: NewBalanceSigmaProofBytes,
    /// Range proof ensuring that the resulting balance chunks are normalized (i.e., within the 16-bit limit).
    pub zkrp_new_balance: RangeProofBytes,
}

/// Represents the proof structure for validating a transfer operation.
#[contracttype]
#[derive(Debug, Clone)]
pub struct TransferProofBytes {
    /// Sigma proof ensuring that the transfer operation maintains balance integrity and correctness.
    pub sigma_proof: TransferSigmaProofBytes,
    /// Range proof ensuring that the resulting balance chunks for the sender are normalized (i.e., within the 16-bit limit).
    pub zkrp_new_balance: RangeProofBytes,
    /// Range proof ensuring that the transferred amount chunks are normalized (i.e., within the 16-bit limit).
    pub zkrp_transfer_amount: RangeProofBytes,
}

//
// Helper structs
//

#[contracttype]
#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofXsBytes {
    // proves the relation: Σ C_i * 2^{16i} = Σ b_i 2^{16i}G + Σ sk 2^{16i} D_i
    pub x1: CompressedRistrettoBytes,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: CompressedRistrettoBytes,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<CompressedRistrettoBytes>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<CompressedRistrettoBytes>,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofAlphasBytes {
    pub a1s: Vec<ScalarBytes>, // hides the unencrypted amount chunks
    pub a2: ScalarBytes,       // hides dk
    pub a3: ScalarBytes,       // hides dk^-1
    pub a4s: Vec<ScalarBytes>, // hides new balance's encryption randomness (each chunk is encrypted with a different randomness parameter)
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofBytes {
    pub alphas: NormalizationSigmaProofAlphasBytes,
    pub xs: NormalizationSigmaProofXsBytes,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct NewBalanceSigmaProofXsBytes {
    // proves the relation: Σ C_i * 2^{16i} = Σ (b_i 2^{16i} - Opt(m))G + Σ sk 2^{16i} D_i
    // if m is None, this is just a normalization proof, otherwise it's a withdrawal proof
    pub x1: CompressedRistrettoBytes,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: CompressedRistrettoBytes,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<CompressedRistrettoBytes>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<CompressedRistrettoBytes>,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct NewBalanceSigmaProofAlphasBytes {
    // unencrypted amount chunks
    pub a1s: Vec<ScalarBytes>,
    // dk
    pub a2: ScalarBytes,
    // dk^-1
    pub a3: ScalarBytes,
    // encryption randomness
    pub a4s: Vec<ScalarBytes>,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct NewBalanceSigmaProofBytes {
    pub alphas: NewBalanceSigmaProofAlphasBytes,
    pub xs: NewBalanceSigmaProofXsBytes,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct TransferSigmaProofXsBytes {
    // Balance preservation commitment
    // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + (Σ(κ₆ᵢ·2¹⁶ⁱ) - Σ(κ₃ᵢ·2¹⁶ⁱ))·H + Σ(D_cur_i·2¹⁶ⁱ)·κ₂ - Σ(D_new_i·2¹⁶ⁱ)·κ₂
    pub x1: CompressedRistrettoBytes,
    // Sender decryption handles for new balance (8 chunks)
    // X₂ᵢ = κ₆ᵢ·sender_ek
    pub x2s: Vec<CompressedRistrettoBytes>,
    // Recipient decryption handles for transfer amount (4 chunks)
    // X₃ᵢ = κ₃ᵢ·recipient_ek
    pub x3s: Vec<CompressedRistrettoBytes>,
    // Transfer amount encryption correctness (4 chunks)
    // X₄ᵢ = κ₄ᵢ·G + κ₃ᵢ·H
    pub x4s: Vec<CompressedRistrettoBytes>,
    // Sender key-pair relationship: P = (sk)^-1 * H
    // X₅ = κ₅·H
    pub x5: CompressedRistrettoBytes,
    // New balance encryption correctness (8 chunks)
    // X₆ᵢ = κ₁ᵢ·G + κ₆ᵢ·H
    pub x6s: Vec<CompressedRistrettoBytes>,
    // Auditor decryption handles for transfer amount (4 chunks)
    // X₇ᵢ = κ₃ᵢ·auditor_ek
    pub x7s: Vec<CompressedRistrettoBytes>,
    // Sender decryption handles for sender amount (4 chunks)
    // X₈ᵢ = κ₃ᵢ·sender_ek
    pub x8s: Vec<CompressedRistrettoBytes>,
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct TransferSigmaProofAlphasBytes {
    pub a1s: Vec<ScalarBytes>, // New balance chunks: a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    pub a2: ScalarBytes,       // Sender decryption key: a₂ = κ₂ - ρ·sender_dk
    pub a3s: Vec<ScalarBytes>, // Transfer amount randomness: a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
    pub a4s: Vec<ScalarBytes>, // Transfer amount chunks: a₄ᵢ = κ₄ᵢ - ρ·mᵢ
    pub a5: ScalarBytes,       // Sender key inverse: a₅ = κ₅ - ρ·sender_dk^(-1)
    pub a6s: Vec<ScalarBytes>, // New balance randomness: a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ
}

#[contracttype]
#[derive(Debug, Clone)]
pub struct TransferSigmaProofBytes {
    pub alphas: TransferSigmaProofAlphasBytes,
    pub xs: TransferSigmaProofXsBytes,
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofXs {
    // proves the relation: Σ C_i * 2^{16i} = Σ b_i 2^{16i}G + Σ sk 2^{16i} D_i
    pub x1: RistrettoPoint,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: RistrettoPoint,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: [RistrettoPoint; BALANCE_CHUNKS],
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: [RistrettoPoint; BALANCE_CHUNKS],
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofAlphas {
    pub a1s: [Scalar; BALANCE_CHUNKS], // hides the unencrypted amount chunks
    pub a2: Scalar,       // hides dk
    pub a3: Scalar,       // hides dk^-1
    pub a4s: [Scalar; BALANCE_CHUNKS], // hides new balance's encryption randomness (each chunk is encrypted with a different randomness parameter)
}

#[derive(Debug, Clone)]
pub struct NewBalanceSigmaProofXs {
    pub x1: RistrettoPoint,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: RistrettoPoint,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: [RistrettoPoint; BALANCE_CHUNKS],
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: [RistrettoPoint; BALANCE_CHUNKS],
}

#[derive(Debug, Clone)]
pub struct NewBalanceSigmaProofAlphas {
    // unencrypted amount chunks
    pub a1s: [Scalar; BALANCE_CHUNKS],
    // dk
    pub a2: Scalar,
    // dk^-1
    pub a3: Scalar,
    // encryption randomness
    pub a4s: [Scalar; BALANCE_CHUNKS],
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofXs {
    // Balance preservation commitment
    // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + (Σ(κ₆ᵢ·2¹⁶ⁱ) - Σ(κ₃ᵢ·2¹⁶ⁱ))·H + Σ(D_cur_i·2¹⁶ⁱ)·κ₂ - Σ(D_new_i·2¹⁶ⁱ)·κ₂
    pub x1: RistrettoPoint,
    // Sender decryption handles for new balance (8 chunks)
    // X₂ᵢ = κ₆ᵢ·sender_ek
    pub x2s: [RistrettoPoint; BALANCE_CHUNKS],
    // Recipient decryption handles for transfer amount (4 chunks)
    // X₃ᵢ = κ₃ᵢ·recipient_ek
    pub x3s: [RistrettoPoint; AMOUNT_CHUNKS],
    // Transfer amount encryption correctness (4 chunks)
    // X₄ᵢ = κ₄ᵢ·G + κ₃ᵢ·H
    pub x4s: [RistrettoPoint; AMOUNT_CHUNKS],
    // Sender key-pair relationship: P = (sk)^-1 * H
    // X₅ = κ₅·H
    pub x5: RistrettoPoint,
    // New balance encryption correctness (8 chunks)
    // X₆ᵢ = κ₁ᵢ·G + κ₆ᵢ·H
    pub x6s: [RistrettoPoint; BALANCE_CHUNKS],
    // Auditor decryption handles for transfer amount (4 chunks)
    // X₇ᵢ = κ₃ᵢ·auditor_ek
    pub x7s: [RistrettoPoint; AMOUNT_CHUNKS],
    // Sender decryption handles for sender amount (4 chunks)
    // X₈ᵢ = κ₃ᵢ·sender_ek
    pub x8s: [RistrettoPoint; AMOUNT_CHUNKS],
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofAlphas {
    pub a1s: [Scalar; BALANCE_CHUNKS], // New balance chunks: a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    pub a2: Scalar,       // Sender decryption key: a₂ = κ₂ - ρ·sender_dk
    pub a3s: [Scalar; AMOUNT_CHUNKS], // Transfer amount randomness: a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
    pub a4s: [Scalar; AMOUNT_CHUNKS], // Transfer amount chunks: a₄ᵢ = κ₄ᵢ - ρ·mᵢ
    pub a5: Scalar,       // Sender key inverse: a₅ = κ₅ - ρ·sender_dk^(-1)
    pub a6s: [Scalar; BALANCE_CHUNKS], // New balance randomness: a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ
}

// Implementation of from_bytes methods for all Impl types
impl NewBalanceSigmaProofXs {
    pub fn from_bytes(xs: &NewBalanceSigmaProofXsBytes) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.0.to_array());
        let x2 = bytes_to_point(&xs.x2.0.to_array());

        let mut x3s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x3s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x3s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x3s[i] = point;
        });

        let mut x4s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x4s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x4s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x4s[i] = point;
        });

        Ok(Self { x1, x2, x3s, x4s })
    }

    pub fn to_bytes(&self, e: &Env) -> NewBalanceSigmaProofXsBytes {
        let x1 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x1)));
        let x2 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x2)));

        let mut x3s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x3s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x3s[i]))));
        }

        let mut x4s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x4s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x4s[i]))));
        }

        NewBalanceSigmaProofXsBytes { x1, x2, x3s, x4s }
    }
}

impl NewBalanceSigmaProofAlphas {
    pub fn from_bytes(alphas: &NewBalanceSigmaProofAlphasBytes) -> Result<Self, Error> {
        let mut a1s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a1s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a1s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s[i] = scalar;
        });

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());
        let a3 = bytes_to_scalar(&alphas.a3.0.to_array());

        let mut a4s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a4s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a4s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s[i] = scalar;
        });

        Ok(Self { a1s, a2, a3, a4s })
    }

    pub fn to_bytes(&self, e: &Env) -> NewBalanceSigmaProofAlphasBytes {
        let mut a1s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a1s.push_back(ScalarBytes::from_scalar(&self.a1s[i], e));
        }

        let a2 = ScalarBytes::from_scalar(&self.a2, e);
        let a3 = ScalarBytes::from_scalar(&self.a3, e);

        let mut a4s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a4s.push_back(ScalarBytes::from_scalar(&self.a4s[i], e));
        }

        NewBalanceSigmaProofAlphasBytes { a1s, a2, a3, a4s }
    }
}

impl NormalizationSigmaProofXs {
    pub fn from_bytes(xs: &NormalizationSigmaProofXsBytes) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.0.to_array());
        let x2 = bytes_to_point(&xs.x2.0.to_array());

        let mut x3s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x3s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x3s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x3s[i] = point;
        });

        let mut x4s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x4s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x4s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x4s[i] = point;
        });

        Ok(Self { x1, x2, x3s, x4s })
    }

    pub fn to_bytes(&self, e: &Env) -> NormalizationSigmaProofXsBytes {
        let x1 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x1)));
        let x2 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x2)));

        let mut x3s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x3s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x3s[i]))));
        }

        let mut x4s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x4s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x4s[i]))));
        }

        NormalizationSigmaProofXsBytes { x1, x2, x3s, x4s }
    }
}

impl NormalizationSigmaProofAlphas {
    pub fn from_bytes(alphas: &NormalizationSigmaProofAlphasBytes) -> Result<Self, Error> {
        let mut a1s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a1s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a1s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s[i] = scalar;
        });

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());
        let a3 = bytes_to_scalar(&alphas.a3.0.to_array());

        let mut a4s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a4s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a4s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s[i] = scalar;
        });

        Ok(Self { a1s, a2, a3, a4s })
    }

    pub fn to_bytes(&self, e: &Env) -> NormalizationSigmaProofAlphasBytes {
        let mut a1s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a1s.push_back(ScalarBytes::from_scalar(&self.a1s[i], e));
        }

        let a2 = ScalarBytes::from_scalar(&self.a2, e);
        let a3 = ScalarBytes::from_scalar(&self.a3, e);

        let mut a4s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a4s.push_back(ScalarBytes::from_scalar(&self.a4s[i], e));
        }

        NormalizationSigmaProofAlphasBytes { a1s, a2, a3, a4s }
    }
}

impl TransferSigmaProofXs {
    pub fn from_bytes(xs: &TransferSigmaProofXsBytes) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.0.to_array());

        let mut x2s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x2s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x2s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x2s[i] = point;
        });

        let mut x3s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        assert_eq!(xs.x3s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let x = xs.x3s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x3s[i] = point;
        });

        let mut x4s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        assert_eq!(xs.x4s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let x = xs.x4s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x4s[i] = point;
        });

        let x5 = bytes_to_point(&xs.x5.0.to_array());

        let mut x6s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        assert_eq!(xs.x6s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let x = xs.x6s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x6s[i] = point;
        });

        let mut x7s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        assert_eq!(xs.x7s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let x = xs.x7s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x7s[i] = point;
        });

        let mut x8s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        assert_eq!(xs.x8s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let x = xs.x8s.get(i as u32).unwrap();
            let point = bytes_to_point(&x.0.to_array());
            x8s[i] = point;
        });

        Ok(Self {
            x1,
            x2s,
            x3s,
            x4s,
            x5,
            x6s,
            x7s,
            x8s,
        })
    }

    pub fn to_bytes(&self, e: &Env) -> TransferSigmaProofXsBytes {
        let x1 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x1)));

        let mut x2s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x2s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x2s[i]))));
        }

        let mut x3s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            x3s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x3s[i]))));
        }

        let mut x4s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            x4s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x4s[i]))));
        }

        let x5 = CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x5)));

        let mut x6s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            x6s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x6s[i]))));
        }

        let mut x7s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            x7s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x7s[i]))));
        }

        let mut x8s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            x8s.push_back(CompressedRistrettoBytes(BytesN::from_array(e, &point_to_bytes(&self.x8s[i]))));
        }

        TransferSigmaProofXsBytes {
            x1,
            x2s,
            x3s,
            x4s,
            x5,
            x6s,
            x7s,
            x8s,
        }
    }
}

impl TransferSigmaProofAlphas {
    pub fn from_bytes(alphas: &TransferSigmaProofAlphasBytes) -> Result<Self, Error> {
        let mut a1s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a1s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a1s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s[i] = scalar;
        });

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());

        let mut a3s = [Scalar::ZERO; AMOUNT_CHUNKS];
        assert_eq!(alphas.a3s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let a = alphas.a3s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a3s[i] = scalar;
        });

        let mut a4s = [Scalar::ZERO; AMOUNT_CHUNKS];
        assert_eq!(alphas.a4s.len(), AMOUNT_CHUNKS as u32);
        (0..AMOUNT_CHUNKS).for_each(|i| {
            let a = alphas.a4s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s[i] = scalar;
        });

        let a5 = bytes_to_scalar(&alphas.a5.0.to_array());

        let mut a6s = [Scalar::ZERO; BALANCE_CHUNKS];
        assert_eq!(alphas.a6s.len(), BALANCE_CHUNKS as u32);
        (0..BALANCE_CHUNKS).for_each(|i| {
            let a = alphas.a6s.get(i as u32).unwrap();
            let scalar = bytes_to_scalar(&a.0.to_array());
            a6s[i] = scalar;
        });

        Ok(Self {
            a1s,
            a2,
            a3s,
            a4s,
            a5,
            a6s,
        })
    }

    pub fn to_bytes(&self, e: &Env) -> TransferSigmaProofAlphasBytes {
        let mut a1s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a1s.push_back(ScalarBytes::from_scalar(&self.a1s[i], e));
        }

        let a2 = ScalarBytes::from_scalar(&self.a2, e);

        let mut a3s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            a3s.push_back(ScalarBytes::from_scalar(&self.a3s[i], e));
        }

        let mut a4s = Vec::new(e);
        for i in 0..AMOUNT_CHUNKS {
            a4s.push_back(ScalarBytes::from_scalar(&self.a4s[i], e));
        }

        let a5 = ScalarBytes::from_scalar(&self.a5, e);

        let mut a6s = Vec::new(e);
        for i in 0..BALANCE_CHUNKS {
            a6s.push_back(ScalarBytes::from_scalar(&self.a6s[i], e));
        }

        TransferSigmaProofAlphasBytes {
            a1s,
            a2,
            a3s,
            a4s,
            a5,
            a6s,
        }
    }
}

//
// Proof verification functions
//

/// Verifies the validity of the `normalize` operation.
///
/// This function ensures that the provided proof (`NormalizationProof`) meets the following conditions:
/// 1. The current balance (`current_balance`) and new balance (`new_balance`) encrypt the same value
///    under the same provided encryption key (`ek`), verifying that the normalization process preserves the balance value.
/// 2. The new balance (`new_balance`) is properly normalized, with each chunk adhering to the range [0, 2^16),
///    as verified through the range proof in the normalization process.
///
/// If all conditions are satisfied, the proof validates the normalization; otherwise, the function causes an error.
pub fn verify_normalization_proof(
    ek: &CompressedPubkeyBytes,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    proof: &NewBalanceProofBytes,
) -> Result<(), Error> {
    verify_new_balance_sigma_proof(ek, None, current_balance, new_balance, &proof.sigma_proof)?;
    verify_new_balance_range_proof(&ConfidentialBalance::from_env_bytes(new_balance), &proof.zkrp_new_balance)?;
    Ok(())
}

/// Verifies the validity of the `withdraw` operation.
///
/// This function ensures that the provided proof (`WithdrawalProof`) meets the following conditions:
/// 1. The current balance (`current_balance`) and new balance (`new_balance`) encrypt the corresponding values
///    under the same encryption key (`ek`) before and after the withdrawal of the specified amount (`amount`), respectively.
/// 2. The relationship `new_balance = current_balance - amount` holds, verifying that the withdrawal amount is deducted correctly.
/// 3. The new balance (`new_balance`) is normalized, with each chunk adhering to the range [0, 2^16).
///
/// If all conditions are satisfied, the proof validates the withdrawal; otherwise, the function causes an error.
pub fn verify_withdrawal_proof(
    ek: &CompressedPubkeyBytes,
    amount: u64,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    proof: &NewBalanceProofBytes,
) -> Result<(), Error> {
    verify_new_balance_sigma_proof(ek, Some(amount), current_balance, new_balance, &proof.sigma_proof)?;
    verify_new_balance_range_proof(&ConfidentialBalance::from_env_bytes(new_balance), &proof.zkrp_new_balance)?;
    Ok(())
}

/// Verifies the validity of the `confidential_transfer` operation.
///
/// This function ensures that the provided proof (`TransferProof`) meets the following conditions:
/// 1. The transferred amount (`recipient_amount` and `sender_amount`) and the auditors' amounts
///    (`auditor_amounts`), if provided, encrypt the transfer value using the recipient's, sender's,
///    and auditors' encryption keys, repectively.
/// 2. The sender's current balance (`current_balance`) and new balance (`new_balance`) encrypt the corresponding values
///    under the sender's encryption key (`sender_ek`) before and after the transfer, respectively.
/// 3. The relationship `new_balance = current_balance - transfer_amount` is maintained, ensuring balance integrity.
/// 4. The transferred value (`recipient_amount`) is properly normalized, with each chunk adhering to the range [0, 2^16).
/// 5. The sender's new balance is normalized, with each chunk in `new_balance` also adhering to the range [0, 2^16).
///
/// If all conditions are satisfied, the proof validates the transfer; otherwise, the function causes an error.
pub fn verify_transfer_proof(
    sender_ek: &CompressedPubkeyBytes,
    recipient_ek: &CompressedPubkeyBytes,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    sender_amount: &ConfidentialAmountBytes,
    recipient_amount: &ConfidentialAmountBytes,
    auditor_ek: &CompressedPubkeyBytes,
    auditor_amount: &ConfidentialAmountBytes,
    proof: &TransferProofBytes,
) -> Result<(), Error> {
    verify_transfer_sigma_proof(
        sender_ek,
        recipient_ek,
        current_balance,
        new_balance,
        sender_amount,
        recipient_amount,
        auditor_ek,
        auditor_amount,
        &proof.sigma_proof,
    )?;
    verify_new_balance_range_proof(&ConfidentialBalance::from_env_bytes(new_balance), &proof.zkrp_new_balance)?;
    verify_transfer_amount_range_proof(&ConfidentialAmount::from_env_bytes(recipient_amount), &proof.zkrp_transfer_amount)?;
    Ok(())
}

//
// Verification functions implementations
//

/// Verifies the validity of the `NewBalanceSigmaProof`.
fn verify_new_balance_sigma_proof(
    ek: &CompressedPubkeyBytes,
    amount: Option<u64>, // if amount is `None`, it is equivalent to a NormalizationProof, otherwise, it's a WithdrawProof
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    proof: &NewBalanceSigmaProofBytes,
) -> Result<(), Error> {

    let rho = fiat_shamir_new_balance_sigma_proof_challenge(
        ek,
        amount,
        current_balance,
        new_balance,
        &proof.xs,
    );

    let ek = ek.to_point();
    let current_balance = ConfidentialBalance::from_env_bytes(current_balance);
    let new_balance = ConfidentialBalance::from_env_bytes(new_balance);
    let alphas = NewBalanceSigmaProofAlphas::from_bytes(&proof.alphas)?;
    let xs = NewBalanceSigmaProofXs::from_bytes(&proof.xs)?;
    
    // 1. Balance Preservation Formula
    //      X₁ = (Σ(a₁ᵢ·2¹⁶ⁱ) - ρ·Opt(m))·G + Σ(a₂·2¹⁶ⁱ·D_cur_i) + Σ(ρ·2¹⁶ⁱ·C_cur_i)
    let lhs = xs.x1;
    let mut scalar_g = aggregate_scalar_chunks(&alphas.a1s);
    if let Some(amount) = amount {
        let amount = new_scalar_from_u64(amount);
        scalar_g -= rho * amount;
    }
    let mut rhs = scalar_g * basepoint();

    let curr_ds = current_balance.get_decryption_handles();
    rhs += aggregate_point_chunks(&curr_ds) * alphas.a2;

    let curr_cs = current_balance.get_encrypted_balances();
    rhs += aggregate_point_chunks(&curr_cs) * rho;

    if lhs.ne(&rhs) {
        return Err(Error::SigmaProtocolVerifyFailed);
    }

    // 2. Key-Pair Relationship Formula
    //      X₂ = a₃·H + ρ·P
    let lhs = xs.x2;
    let rhs = alphas.a3 * hash_to_point_base() + rho * ek;
    if lhs.ne(&rhs) {
        return Err(Error::SigmaProtocolVerifyFailed);
    }

    // 3. Encryption Correctness Formulas (for each chunk i)
    //      X₃ᵢ = a₁ᵢ·G + a₄ᵢ·H + ρ·C_new_i
    let new_cs = new_balance.get_encrypted_balances();
    for i in 0..BALANCE_CHUNKS {
        let lhs = xs.x3s[i];
        let rhs = alphas.a1s[i] * &basepoint() + alphas.a4s[i] * &hash_to_point_base() + rho * new_cs[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }        
    }

    // 4. Decryption Handle Correctness Formulas (for each chunk i)
    //      X₄ᵢ = a₄ᵢ·P + ρ·D_new_i
    let new_ds = new_balance.get_decryption_handles();
    for i in 0..BALANCE_CHUNKS {
        let lhs = xs.x4s[i];
        let rhs = alphas.a4s[i] * ek + rho * new_ds[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }            
    }
    // Below are the actual forms of parameters contained in the proof, these were computed during proving and listed here for convenience 
    //
    // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + Σ(D_cur_i·2¹⁶ⁱ)·κ₂
    // X₂ = κ₃·H
    // X₃ᵢ = κ₁ᵢ·G + κ₄ᵢ·H
    // X₄ᵢ = κ₄ᵢ·P
    //
    // a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    // a₂ = κ₂ - ρ·dk
    // a₃ = κ₃ - ρ·dk^(-1)
    // a₄ᵢ = κ₄ᵢ - ρ·rᵢ

    Ok(())
}

/// Verifies the validity of the `TransferSigmaProof`.
fn verify_transfer_sigma_proof(
    sender_ek: &CompressedPubkeyBytes,
    recipient_ek: &CompressedPubkeyBytes,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    sender_amount: &ConfidentialAmountBytes,
    recipient_amount: &ConfidentialAmountBytes,
    auditor_ek: &CompressedPubkeyBytes,
    auditor_amount: &ConfidentialAmountBytes,
    proof: &TransferSigmaProofBytes,
) -> Result<(), Error> {
    let rho = fiat_shamir_transfer_sigma_proof_challenge(
        sender_ek,
        recipient_ek,
        current_balance,
        new_balance,
        sender_amount,
        recipient_amount,
        auditor_ek,
        auditor_amount,
        &proof.xs,
    );

    let sender_ek = sender_ek.to_point();
    let recipient_ek = recipient_ek.to_point();
    let auditor_ek = auditor_ek.to_point();

    let current_balance = ConfidentialBalance::from_env_bytes(current_balance);
    let new_balance = ConfidentialBalance::from_env_bytes(new_balance);

    let sender_amount = ConfidentialAmount::from_env_bytes(sender_amount);
    let recipient_amount = ConfidentialAmount::from_env_bytes(recipient_amount);
    let auditor_amount = ConfidentialAmount::from_env_bytes(auditor_amount);

    if !ConfidentialAmount::encrypted_amounts_are_equal(&sender_amount, &recipient_amount) || !ConfidentialAmount::encrypted_amounts_are_equal(&recipient_amount, &auditor_amount) {
        return Err(Error::SigmaProtocolVerifyFailed);
    }

    let alphas = TransferSigmaProofAlphas::from_bytes(&proof.alphas)?;
    let xs = TransferSigmaProofXs::from_bytes(&proof.xs)?;

    // 1. Balance Preservation Formula
    // X₁ = (Σ(a₁ᵢ·2¹⁶ⁱ)·G + Σ(a₆ᵢ·2¹⁶ⁱ)·H - Σ(a₃ᵢ·2¹⁶ⁱ)·H + Σ(a₂·2¹⁶ⁱ)·D_current_balance_i  - Σ(a₂·2¹⁶ⁱ)·D_new_balance_i + Σ(ρ·2¹⁶ⁱ)·C_current_balance_i - Σ(ρ·2¹⁶ⁱ)·C_transfer_amount_i)
    let lhs = xs.x1;
    let mut rhs = aggregate_scalar_chunks(&alphas.a1s) * basepoint();
    rhs += (aggregate_scalar_chunks(&alphas.a6s) - aggregate_scalar_chunks(&alphas.a3s)) * hash_to_point_base();
    
    let curr_balance_ds = current_balance.get_decryption_handles();
    let new_balance_ds = new_balance.get_decryption_handles();
    rhs += aggregate_point_chunks(&curr_balance_ds) * alphas.a2;
    rhs -= aggregate_point_chunks(&new_balance_ds) * alphas.a2;
    
    let curr_balance_cs = current_balance.get_encrypted_balances();
    let transfer_amount_cs = recipient_amount.get_encrypted_amounts();
    rhs += aggregate_point_chunks(&curr_balance_cs) * rho;
    rhs -= aggregate_point_chunks(&transfer_amount_cs) * rho;

    if lhs.ne(&rhs) {
        return Err(Error::SigmaProtocolVerifyFailed);
    }

    // 2. Sender New Balance Decryption Handle Correctness (for each chunk i)
    // X₂ᵢ = a₆ᵢ·P_sender + ρ·D_new_balance_i
    for i in 0..BALANCE_CHUNKS {
        let lhs = xs.x2s[i];
        let rhs = alphas.a6s[i] * sender_ek + rho * new_balance_ds[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    // 3. Recipient Transfer Amount Decryption Handle Correctness (for each chunk i)
    // X₃ᵢ = a₃ᵢ·P_recipient + ρ·D_recipient_amount_i
    let recipient_ds = recipient_amount.get_decryption_handles();
    for i in 0..AMOUNT_CHUNKS {
        let lhs = xs.x3s[i];
        let rhs = alphas.a3s[i] * recipient_ek + rho * recipient_ds[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    // 4. Transfer Amount Encryption Correctness (for each chunk i)
    // X₄ᵢ = a₄ᵢ·G + a₃ᵢ·H + ρ·C_transfer_amount_i
    for i in 0..AMOUNT_CHUNKS {
        let lhs = xs.x4s[i];
        let rhs = alphas.a4s[i] * basepoint() + alphas.a3s[i] * hash_to_point_base() + rho * transfer_amount_cs[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    // 5. Sender Key-Pair Relationship
    // X₅ = a₅·H + ρ·P_sender
    let lhs = xs.x5;
    let rhs = alphas.a5 * hash_to_point_base() + rho * sender_ek;
    if lhs.ne(&rhs) {
        return Err(Error::SigmaProtocolVerifyFailed);
    }

    // 6. New Balance Encryption Correctness (for each chunk i)
    // X₆ᵢ = a₁ᵢ·G + a₆ᵢ·H + ρ·C_new_balance_i
    let new_balance_cs = new_balance.get_encrypted_balances();
    for i in 0..BALANCE_CHUNKS {
        let lhs = xs.x6s[i];
        let rhs = alphas.a1s[i] * basepoint() + alphas.a6s[i] * hash_to_point_base() + rho * new_balance_cs[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    // 7. Auditor Transfer Amount Decryption Handle Correctness (for each chunk i)
    // X₇ᵢ = a₃ᵢ·P_auditor + ρ·D_auditor_amount_i
    let auditor_amount_ds = auditor_amount.get_decryption_handles();
    for i in 0..AMOUNT_CHUNKS {
        let lhs = xs.x7s[i];
        let rhs = alphas.a3s[i] * auditor_ek + rho * auditor_amount_ds[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    // 8. Sender Amount Decryption Handle Correctness (for each chunk i)
    // X₈ᵢ = a₃ᵢ·P_sender + ρ·D_sender_amount_i
    let sender_amount_ds = sender_amount.get_decryption_handles();
    for i in 0..AMOUNT_CHUNKS {
        let lhs = xs.x8s[i];
        let rhs = alphas.a3s[i] * sender_ek + rho * sender_amount_ds[i];
        if lhs.ne(&rhs) {
            return Err(Error::SigmaProtocolVerifyFailed);
        }
    }

    Ok(())
}

/// Derives the Fiat-Shamir challenge for the `NewBalanceSigmaProof`.
fn fiat_shamir_new_balance_sigma_proof_challenge(
    ek: &CompressedPubkeyBytes,
    amount: Option<u64>,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    proof_xs: &NewBalanceSigmaProofXsBytes,
) -> Scalar {
    // rho = H(DST, G, H, P, v_{1..4}, (C_cur, D_cur)_{1..8}, (C_new, D_new)_{1..8}, X_{1..18})
    let mut bytes = FIAT_SHAMIR_NEW_BALANCE_SIGMA_DST.to_vec();
    bytes.extend(basepoint().compress().to_bytes());
    bytes.extend(hash_to_point_base().compress().to_bytes());
    bytes.extend(ek.0.to_array());
    if let Some(amount) = amount {
        for chunk in split_into_chunk_bytes_u64(amount) {
            bytes.extend(chunk);
        }        
    }
    bytes.extend(current_balance.to_bytes());
    bytes.extend(new_balance.to_bytes());
    bytes.extend(&proof_xs.x1.to_bytes());
    bytes.extend(&proof_xs.x2.to_bytes());
    for x in &proof_xs.x3s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x4s {
        bytes.extend(x.to_bytes());
    }
    new_scalar_from_sha2_512(&bytes)
}

/// Derives the Fiat-Shamir challenge for the `TransferSigmaProof`.
fn fiat_shamir_transfer_sigma_proof_challenge(
    sender_ek: &CompressedPubkeyBytes,
    recipient_ek: &CompressedPubkeyBytes,
    current_balance: &ConfidentialBalanceBytes,
    new_balance: &ConfidentialBalanceBytes,
    sender_amount: &ConfidentialAmountBytes,
    recipient_amount: &ConfidentialAmountBytes,
    auditor_ek: &CompressedPubkeyBytes,
    auditor_amount: &ConfidentialAmountBytes,
    proof_xs: &TransferSigmaProofXsBytes,
) -> Scalar {
    // rho = H(DST, G, H, P_s, P_r, P_a, (C_cur, D_cur)_{1..8}, (C_v, D_v)_{1..4}, D_a_{1..4}, D_s_{1..4}, (C_new, D_new)_{1..8}, X_{1..34})
    let mut bytes = FIAT_SHAMIR_TRANSFER_SIGMA_DST.to_vec();

    bytes.extend(basepoint().compress().to_bytes());
    bytes.extend(hash_to_point_base().compress().to_bytes());
    bytes.extend(sender_ek.0.to_array());
    bytes.extend(recipient_ek.0.to_array());
    bytes.extend(auditor_ek.0.to_array());
    bytes.extend(current_balance.to_bytes());
    bytes.extend(recipient_amount.to_bytes());
    for EncryptedChunkBytes{ handle, .. } in &auditor_amount.0 {
        bytes.extend(handle.to_bytes());
    }
    for EncryptedChunkBytes{ handle, .. } in &sender_amount.0 {
        bytes.extend(handle.to_bytes());
    }
    bytes.extend(new_balance.to_bytes());
    bytes.extend(&proof_xs.x1.to_bytes());
    for x in &proof_xs.x2s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x3s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x4s {
        bytes.extend(x.to_bytes());
    }
    bytes.extend(&proof_xs.x5.to_bytes());
    for x in &proof_xs.x6s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x7s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x8s {
        bytes.extend(x.to_bytes());
    }

    new_scalar_from_sha2_512(&bytes)
}

#[cfg(any(test, feature="testutils"))]
pub mod testutils {
    use super::*;
    use crate::{arith::{basepoint_mul, point_mul, scalar_invert, scalar_mul, scalar_sub}, confidential_balance::testutils::{generate_amount_randomness, generate_balance_randomness}};
    use crate::range_proof::testutils::{prove_new_balance_range, prove_transfer_amount_range};
    use rand::rngs::OsRng;

    pub struct NewBalanceSigmaProofRandomness {
        // unencrypted amount chunks
        pub k1s: [Scalar; BALANCE_CHUNKS],
        // dk
        pub k2: Scalar,
        // dk^-1
        pub k3: Scalar,
        // encryption randomness
        pub k4s: [Scalar; BALANCE_CHUNKS],
    }
    pub struct TransferSigmaProofRandomness {
        pub k1s: [Scalar; BALANCE_CHUNKS], // New balance chunks: a₁ᵢ = κ₁ᵢ - ρ·bᵢ
        pub k2: Scalar,       // Sender decryption key: a₂ = κ₂ - ρ·sender_dk
        pub k3s: [Scalar; AMOUNT_CHUNKS], // Transfer amount randomness: a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
        pub k4s: [Scalar; AMOUNT_CHUNKS], // Transfer amount chunks: a₄ᵢ = κ₄ᵢ - ρ·mᵢ
        pub k5: Scalar,       // Sender key inverse: a₅ = κ₅ - ρ·sender_dk^(-1)
        pub k6s: [Scalar; BALANCE_CHUNKS], // New balance randomness: a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ
    }

    impl NewBalanceSigmaProofRandomness {
        fn generate() -> Self {
            let mut k1s = [Scalar::ZERO; BALANCE_CHUNKS];
            for i in 0..BALANCE_CHUNKS {
                k1s[i] = Scalar::random(&mut OsRng);
            }
            
            let mut k4s = [Scalar::ZERO; BALANCE_CHUNKS];
            for i in 0..BALANCE_CHUNKS {
                k4s[i] = Scalar::random(&mut OsRng);
            }
            
            Self {
                k1s,
                k2: Scalar::random(&mut OsRng),
                k3: Scalar::random(&mut OsRng),
                k4s,
            }
        }
    }
    impl TransferSigmaProofRandomness {
        fn generate() -> Self {
            let mut k1s = [Scalar::ZERO; BALANCE_CHUNKS];
            for i in 0..BALANCE_CHUNKS {
                k1s[i] = Scalar::random(&mut OsRng);
            }
            
            let mut k3s = [Scalar::ZERO; AMOUNT_CHUNKS];
            for i in 0..AMOUNT_CHUNKS {
                k3s[i] = Scalar::random(&mut OsRng);
            }
            
            let mut k4s = [Scalar::ZERO; AMOUNT_CHUNKS];
            for i in 0..AMOUNT_CHUNKS {
                k4s[i] = Scalar::random(&mut OsRng);
            }
            
            let mut k6s = [Scalar::ZERO; BALANCE_CHUNKS];
            for i in 0..BALANCE_CHUNKS {
                k6s[i] = Scalar::random(&mut OsRng);
            }
            
            Self {
                k1s,
                k2: Scalar::random(&mut OsRng),
                k3s,
                k4s,
                k5: Scalar::random(&mut OsRng),
                k6s,
            }
        }
    }

    /// Proves the normalization operation.
    pub fn prove_normalization(
        env: &Env,
        dk: &Scalar,
        ek: &RistrettoPoint,
        balance_u128: u128,
        current_balance: &ConfidentialBalance,
    ) -> (NewBalanceProofBytes, ConfidentialBalanceBytes) {
        prove_new_balance(env, dk, ek, None, balance_u128, current_balance)
    }

    /// Proves the withdrawal operation.
    pub fn prove_withdrawal(
        env: &Env,
        dk: &Scalar,
        ek: &RistrettoPoint,
        amount: u64,
        new_balance_u128: u128,
        current_balance: &ConfidentialBalance,
    ) -> (NewBalanceProofBytes, ConfidentialBalanceBytes) {
        prove_new_balance(env, dk, ek, Some(amount), new_balance_u128, current_balance)
    }
    
    fn prove_new_balance(
        env: &Env,
        dk: &Scalar,
        ek: &RistrettoPoint,
        amount: Option<u64>,
        new_balance_u128: u128,
        current_balance: &ConfidentialBalance,
    ) -> (NewBalanceProofBytes, ConfidentialBalanceBytes) {
        let new_balance_r = generate_balance_randomness();
        let new_balance = ConfidentialBalance::new_balance_from_u128(new_balance_u128, &new_balance_r, &ek);
        let new_balance_bytes = new_balance.to_env_bytes(&env);
        let sigma_r = NewBalanceSigmaProofRandomness::generate();

        let zkrp_new_balance = prove_new_balance_range(env, new_balance_u128, &new_balance_r).proof;

        // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + Σ(D_cur_i·2¹⁶ⁱ)·κ₂
        let scalar_g = aggregate_scalar_chunks(&sigma_r.k1s);
        let mut x1 = basepoint_mul(&scalar_g);
        let curr_ds = current_balance.get_decryption_handles();
        x1 += point_mul(&aggregate_point_chunks(&curr_ds), &sigma_r.k2);

        // X₂ = κ₃·H
        let x2 = point_mul(&hash_to_point_base(), &sigma_r.k3);

        // X₃ᵢ = κ₁ᵢ·G + κ₄ᵢ·H
        let mut x3s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            x3s[i] = basepoint_mul(&sigma_r.k1s[i]) + point_mul(&hash_to_point_base(), &sigma_r.k4s[i]);
        }

        // X₄ᵢ = κ₄ᵢ·P
        let mut x4s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            x4s[i] = point_mul(&ek, &sigma_r.k4s[i])
        }

        let proof_xs = NewBalanceSigmaProofXs {
            x1,
            x2,
            x3s,
            x4s
        };

        let proof_xs_bytes = proof_xs.to_bytes(&env);

        let rho = fiat_shamir_new_balance_sigma_proof_challenge(
            &CompressedPubkeyBytes::from_point(&env, ek),
            amount,
            &current_balance.to_env_bytes(&env),
            &new_balance_bytes,
            &proof_xs_bytes,
        );

        // create the commitments for each withness
        
        // a₁ᵢ = κ₁ᵢ - ρ·bᵢ
        let new_amount_chunks = split_into_chunks_u128(new_balance_u128);
        let mut a1s = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            a1s[i] = sigma_r.k1s[i] - rho * new_amount_chunks[i];
        }
        // a₂ = κ₂ - ρ·dk
        let a2 = scalar_sub(&sigma_r.k2, &scalar_mul(&rho, dk));
        // a₃ = κ₃ - ρ·dk^(-1)
        let a3 = scalar_sub(&sigma_r.k3, &scalar_mul(&rho, &scalar_invert(dk)));
        // a₄ᵢ = κ₄ᵢ - ρ·rᵢ
        let mut a4s = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            a4s[i] = scalar_sub(&sigma_r.k4s[i], &scalar_mul(&rho, &new_balance_r[i]));
        }
        let alphas = NewBalanceSigmaProofAlphas{ a1s, a2, a3, a4s };

        (
            NewBalanceProofBytes {
                sigma_proof: NewBalanceSigmaProofBytes {
                    xs: proof_xs_bytes,
                    alphas: alphas.to_bytes(&env),
                },
                zkrp_new_balance,
            },
            new_balance_bytes,
        )
    }

    /// Proves the transfer operation.
    pub fn prove_transfer(
        env: &Env,
        sender_dk: &Scalar,
        sender_ek: &RistrettoPoint,
        recipient_ek: &RistrettoPoint,
        amount_u64: u64,
        new_balance_u128: u128,
        current_balance: &ConfidentialBalance,
        auditor_ek: &RistrettoPoint,
    ) -> (
        TransferProofBytes,
        ConfidentialBalanceBytes,
        ConfidentialAmountBytes,
        ConfidentialAmountBytes,
        ConfidentialAmountBytes
    ) {
        let amount_r = generate_amount_randomness();
        let new_balance_r = generate_balance_randomness();
        let new_balance = ConfidentialBalance::new_balance_from_u128(new_balance_u128, &new_balance_r, &sender_ek);
        let new_balance_bytes = new_balance.to_env_bytes(&env);

        let sigma_r = TransferSigmaProofRandomness::generate();

        // encrypt the transfer amount 3 times: sender, recipient, auditors. All with the same randomness.
        let sender_amount = ConfidentialAmount::new_amount_from_u64(amount_u64, &amount_r, sender_ek);
        let recipient_amount = ConfidentialAmount::new_amount_from_u64(amount_u64, &amount_r, recipient_ek);
        let auditor_amount = ConfidentialAmount::new_amount_from_u64(amount_u64, &amount_r, auditor_ek);
        let sender_amount_bytes = sender_amount.to_env_bytes(&env);
        let recipient_amount_bytes = recipient_amount.to_env_bytes(&env);
        let auditor_amount_bytes = auditor_amount.to_env_bytes(&env);

        let zkrp_new_balance = prove_new_balance_range(env, new_balance_u128, &new_balance_r).proof;
        let zkrp_transfer_amount = prove_transfer_amount_range(env, amount_u64, &amount_r).proof;

        // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + (Σ(κ₆ᵢ·2¹⁶ⁱ) - Σ(κ₃ᵢ·2¹⁶ⁱ))·H + Σ(D_cur_i·2¹⁶ⁱ)·κ₂ - Σ(D_new_i·2¹⁶ⁱ)·κ₂
        let scalar_g = aggregate_scalar_chunks(&sigma_r.k1s);
        let mut x1 = basepoint_mul(&scalar_g);
        let scalar_h = scalar_sub(&aggregate_scalar_chunks(&sigma_r.k6s), &aggregate_scalar_chunks(&sigma_r.k3s));
        x1 += point_mul(&hash_to_point_base(), &scalar_h);
        
        let curr_balance_ds = current_balance.get_decryption_handles();
        let new_balance_ds = new_balance.get_decryption_handles();
        x1 += point_mul(&aggregate_point_chunks(&curr_balance_ds), &sigma_r.k2);
        x1 -= point_mul(&aggregate_point_chunks(&new_balance_ds), &sigma_r.k2);

        // X₂ᵢ = κ₆ᵢ·sender_ek
        let mut x2s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            x2s[i] = point_mul(sender_ek, &sigma_r.k6s[i]);
        }

        // X₃ᵢ = κ₃ᵢ·recipient_ek
        let mut x3s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            x3s[i] = point_mul(recipient_ek, &sigma_r.k3s[i]);
        }

        // X₄ᵢ = κ₄ᵢ·G + κ₃ᵢ·H
        let mut x4s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            x4s[i] = basepoint_mul(&sigma_r.k4s[i]) + point_mul(&hash_to_point_base(), &sigma_r.k3s[i]);
        }

        // X₅ = κ₅·H
        let x5 = point_mul(&hash_to_point_base(), &sigma_r.k5);

        // X₆ᵢ = κ₁ᵢ·G + κ₆ᵢ·H
        let mut x6s = [RistrettoPoint::identity(); BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            x6s[i] = basepoint_mul(&sigma_r.k1s[i]) + point_mul(&hash_to_point_base(), &sigma_r.k6s[i]);
        }

        // X₇ᵢ = κ₃ᵢ·auditor_ek
        let mut x7s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            x7s[i] = point_mul(auditor_ek, &sigma_r.k3s[i]);
        }

        // X₈ᵢ = κ₃ᵢ·sender_ek
        let mut x8s = [RistrettoPoint::identity(); AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            x8s[i] = point_mul(sender_ek, &sigma_r.k3s[i]);
        }

        let proof_xs = TransferSigmaProofXs {
            x1,
            x2s,
            x3s,
            x4s,
            x5,
            x6s,
            x7s,
            x8s
        };

        let proof_xs_bytes = proof_xs.to_bytes(&env);

        let rho = fiat_shamir_transfer_sigma_proof_challenge(
            &CompressedPubkeyBytes::from_point(&env, sender_ek),
            &CompressedPubkeyBytes::from_point(&env, recipient_ek),
            &current_balance.to_env_bytes(&env),
            &new_balance_bytes,
            &sender_amount_bytes,
            &recipient_amount_bytes,
            &CompressedPubkeyBytes::from_point(&env, auditor_ek),
            &auditor_amount_bytes,
            &proof_xs_bytes,
        );

        let amount_chunks = split_into_chunks_u64(amount_u64);
        let new_balance_chunks = split_into_chunks_u128(new_balance_u128);

        // a₁ᵢ = κ₁ᵢ - ρ·bᵢ                    (bᵢ = new balance chunks)
        let mut a1s = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            a1s[i] = scalar_sub(&sigma_r.k1s[i], &scalar_mul(&rho, &new_balance_chunks[i]));
        }
        // a₂ = κ₂ - ρ·sender_dk
        let a2 = scalar_sub(&sigma_r.k2, &scalar_mul(&rho, sender_dk));
        // a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
        let mut a3s = [Scalar::ZERO; AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            a3s[i] = scalar_sub(&sigma_r.k3s[i], &scalar_mul(&rho, &amount_r[i]));
        }
        // a₄ᵢ = κ₄ᵢ - ρ·mᵢ
        let mut a4s = [Scalar::ZERO; AMOUNT_CHUNKS];
        for i in 0..AMOUNT_CHUNKS {
            a4s[i] = scalar_sub(&sigma_r.k4s[i], &scalar_mul(&rho, &amount_chunks[i]));
        }
        // a₅ = κ₅ - ρ·sender_dk^(-1)
        let a5 = scalar_sub(&sigma_r.k5, &scalar_mul(&rho, &scalar_invert(sender_dk)));
        // a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ        (r_new_balanceᵢ = new balance randomness)
        let mut a6s = [Scalar::ZERO; BALANCE_CHUNKS];
        for i in 0..BALANCE_CHUNKS {
            a6s[i] = scalar_sub(&sigma_r.k6s[i], &scalar_mul(&rho, &new_balance_r[i]));
        }

        let alphas = TransferSigmaProofAlphas{ a1s, a2, a3s, a4s, a5, a6s };

        (
            TransferProofBytes {
                sigma_proof: TransferSigmaProofBytes {
                    xs: proof_xs_bytes,
                    alphas: alphas.to_bytes(&env),
                },
                zkrp_new_balance,
                zkrp_transfer_amount,
            },
            new_balance_bytes,
            sender_amount_bytes,
            recipient_amount_bytes,
            auditor_amount_bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::arith::pubkey_from_secret_key;
    use crate::confidential_balance::testutils::{generate_balance_randomness, new_balance_with_mismatched_decryption_handle};

    use super::*;
    use super::testutils::*;

    #[test]
    fn test_prove_normalization() {
        let env = Env::default();
        let dk = new_scalar_from_u64(123);
        let ek = pubkey_from_secret_key(&dk);

        {
            // correct normalization
            let balance = 100u128;
            let current_balance = ConfidentialBalance::new_balance_from_u128(balance, &generate_balance_randomness(), &ek);
            let (proof, new_balance) = prove_normalization(&env, &dk, &ek, balance, &current_balance);

            let res = verify_normalization_proof(&CompressedPubkeyBytes::from_point(&env, &ek), &current_balance.to_env_bytes(&env), &new_balance, &proof);
            assert!(res.is_ok())

            // TODO: add more non-trivial cases
            // E.g split the balance into non-uniform bits and normalize them again
        }
    }

    #[test]
    fn test_prove_withdrawal() {
        let env = Env::default();
        let dk = new_scalar_from_u64(123);
        let ek = pubkey_from_secret_key(&dk);

        {
            // correct transaction    
            let current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &ek);
            let amount = 100u64;
            let new_balance = 900u128;
    
            let (proof, new_balance) = prove_withdrawal(&env, &dk, &ek, amount, new_balance, &current_balance);
    
            let res = verify_withdrawal_proof(&CompressedPubkeyBytes::from_point(&env, &ek), amount, &current_balance.to_env_bytes(&env), &new_balance, &proof);
            assert!(res.is_ok())
        }

        {
            // wrong public key. 
            let wrong_ek = pubkey_from_secret_key(&new_scalar_from_u64(345));
            let current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &ek);
            let amount = 100u64;
            let new_balance = 900u128;

            let (proof, new_balance) = prove_withdrawal(&env, &dk, &ek, amount, new_balance, &current_balance);
    
            let res = verify_withdrawal_proof(&CompressedPubkeyBytes::from_point(&env, &wrong_ek), amount, &current_balance.to_env_bytes(&env), &new_balance, &proof);
            assert!(res.is_err())
        }

        {
            // wrong balance
            let wrong_ek = pubkey_from_secret_key(&new_scalar_from_u64(345));
            let current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &ek);
            let amount = 100u64;
            let new_balance = 901u128; // correct balance should be 900

            let (proof, new_balance) = prove_withdrawal(&env, &dk, &ek, amount, new_balance, &current_balance);
    
            let res = verify_withdrawal_proof(&CompressedPubkeyBytes::from_point(&env, &wrong_ek), amount, &current_balance.to_env_bytes(&env), &new_balance, &proof);
            assert!(res.is_err())            
        }

        {
            // wrong decryption handle
            let current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &ek);
            let amount = 100u64;
            let new_balance = 900u128;
    
            let (proof, new_balance) = prove_withdrawal(&env, &dk, &ek, amount, new_balance, &current_balance);
            
            let wrong_balance = new_balance_with_mismatched_decryption_handle(&new_balance, &ek);
            let res = verify_withdrawal_proof(&CompressedPubkeyBytes::from_point(&env, &ek), amount, &current_balance.to_env_bytes(&env), &wrong_balance, &proof);
            assert!(res.is_err())

        }
    }

    #[test]
    fn test_prove_transfer() {
        let env = Env::default();
        let sender_dk = &new_scalar_from_u64(123);
        let sender_ek = pubkey_from_secret_key(&sender_dk);
        let recipient_ek = pubkey_from_secret_key(&new_scalar_from_u64(456));
        let amount_u64 = 100u64;
        let new_balance_u128 = 900u128;
        let current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &sender_ek);
        let auditor_ek = pubkey_from_secret_key(&new_scalar_from_u64(789));

        let (proof, new_balance, sender_amount, recipient_amount, auditor_amounts) = prove_transfer(
            &env,
            &sender_dk,
            &sender_ek,
            &recipient_ek,
            amount_u64,
            new_balance_u128,
            &current_balance,
            &auditor_ek,
        );

        let res = verify_transfer_proof(&CompressedPubkeyBytes::from_point(&env, &sender_ek), &CompressedPubkeyBytes::from_point(&env, &recipient_ek), &current_balance.to_env_bytes(&env), &new_balance, &sender_amount, &recipient_amount, &CompressedPubkeyBytes::from_point(&env, &auditor_ek), &auditor_amounts, &proof);

        assert!(res.is_ok());

        {
            // Test 1: Amount and balances don't add up (Balance Preservation Formula failure)
            let wrong_new_balance_u128 = 950u128; // Should be 900, but using 950
            let wrong_current_balance = ConfidentialBalance::new_balance_from_u128(1000u128, &generate_balance_randomness(), &sender_ek);
            
            let (wrong_proof, wrong_new_balance, wrong_sender_amount, wrong_recipient_amount, wrong_auditor_amounts) = prove_transfer(
                &env,
                &sender_dk,
                &sender_ek,
                &recipient_ek,
                amount_u64,
                wrong_new_balance_u128,
                &wrong_current_balance,
                &auditor_ek,
            );

            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &current_balance.to_env_bytes(&env), // Using original current_balance
                &wrong_new_balance, 
                &wrong_sender_amount, 
                &wrong_recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &wrong_auditor_amounts, 
                &wrong_proof
            );
            
            assert!(res.is_err()); // Should fail balance preservation
        }

        {
            // Test 2: Wrong sender key (Key-Pair Relationship failure)
            let wrong_sender_dk = &new_scalar_from_u64(999);
            let wrong_sender_ek = pubkey_from_secret_key(&wrong_sender_dk);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &wrong_sender_ek), // Wrong sender key
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &current_balance.to_env_bytes(&env), 
                &new_balance, 
                &sender_amount, 
                &recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail sender key verification
        }

        {
            // Test 3: Wrong recipient key (Recipient Decryption Handle failure)
            let wrong_recipient_dk = &new_scalar_from_u64(999);
            let wrong_recipient_ek = pubkey_from_secret_key(&wrong_recipient_dk);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &wrong_recipient_ek), // Wrong recipient key
                &current_balance.to_env_bytes(&env), 
                &new_balance, 
                &sender_amount, 
                &recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail recipient verification
        }

        {
            // Test 4: Wrong auditor key (Auditor Decryption Handle failure)
            let wrong_auditor_dk = &new_scalar_from_u64(999);
            let wrong_auditor_ek = pubkey_from_secret_key(&wrong_auditor_dk);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &current_balance.to_env_bytes(&env), 
                &new_balance, 
                &sender_amount, 
                &recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &wrong_auditor_ek), // Wrong auditor key
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail auditor verification
        }

        {
            // Test 5: Mismatched transfer amounts (encrypted_amounts_are_equal failure)
            let different_amount_r = crate::confidential_balance::testutils::generate_amount_randomness();
            let wrong_recipient_amount = ConfidentialAmount::new_amount_from_u64(amount_u64 + 1, &different_amount_r, &recipient_ek); // Different amount
            let wrong_recipient_amount_bytes = wrong_recipient_amount.to_env_bytes(&env);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &current_balance.to_env_bytes(&env), 
                &new_balance, 
                &sender_amount, 
                &wrong_recipient_amount_bytes, // Mismatched amount
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail amount equality check
        }

        {
            // Test 6: Wrong current balance (used in proof vs verification mismatch)
            let wrong_current_balance_for_verification = ConfidentialBalance::new_balance_from_u128(2000u128, &generate_balance_randomness(), &sender_ek);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &wrong_current_balance_for_verification.to_env_bytes(&env), // Wrong current balance
                &new_balance, 
                &sender_amount, 
                &recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail verification
        }

        {
            // Test 7: Tampered new balance (New Balance Encryption Correctness failure)
            let tampered_new_balance = new_balance_with_mismatched_decryption_handle(&new_balance, &sender_ek);
            
            let res = verify_transfer_proof(
                &CompressedPubkeyBytes::from_point(&env, &sender_ek), 
                &CompressedPubkeyBytes::from_point(&env, &recipient_ek), 
                &current_balance.to_env_bytes(&env), 
                &tampered_new_balance, // Tampered new balance
                &sender_amount, 
                &recipient_amount, 
                &CompressedPubkeyBytes::from_point(&env, &auditor_ek), 
                &auditor_amounts, 
                &proof
            );
            
            assert!(res.is_err()); // Should fail new balance verification
        }
    }

}
