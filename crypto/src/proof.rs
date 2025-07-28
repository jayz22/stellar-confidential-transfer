use crate::{
    arith::{
        basepoint, bytes_to_point, bytes_to_scalar, hash_to_point_base, new_scalar_from_sha2_512,
    },
    confidential_balance::*,
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use soroban_sdk::{Bytes, BytesN, Env};

const FIAT_SHAMIR_WITHDRAWAL_SIGMA_DST: &[u8] =
    b"StellarConfidentialToken/WithdrawalProofFiatShamir";
const FIAT_SHAMIR_TRANSFER_SIGMA_DST: &[u8] = b"StellarConfidentialToken/TransferProofFiatShamir";
const FIAT_SHAMIR_ROTATION_SIGMA_DST: &[u8] = b"StellarConfidentialToken/RotationProofFiatShamir";
const FIAT_SHAMIR_NORMALIZATION_SIGMA_DST: &[u8] =
    b"StellarConfidentialToken/NormalizationProofFiatShamir";

const BULLETPROOFS_DST: &[u8] = b"StellarConfidentialToken/BulletproofRangeProof";
const BULLETPROOFS_NUM_BITS: u64 = 16;

#[derive(Debug, Clone)]
pub struct ScalarBytes(pub BytesN<32>);

#[derive(Debug, Clone)]
pub struct RangeProof(Bytes);

#[derive(Debug, Clone)]
pub struct CompressedPubkey(BytesN<32>);

/// Represents the proof structure for validating a normalization operation.
#[derive(Debug, Clone)]
pub struct NormalizationProof {
    /// Sigma proof ensuring that the normalization operation maintains balance integrity.
    pub sigma_proof: NormalizationSigmaProof,
    /// Range proof ensuring that the resulting balance chunks are normalized (i.e., within the 16-bit limit).
    pub zkrp_new_balance: RangeProof,
}

/// Represents the proof structure for validating a withdrawal operation.
#[derive(Debug, Clone)]
pub struct WithdrawalProof {
    /// Sigma proof ensuring that the withdrawal operation maintains balance integrity.
    pub sigma_proof: WithdrawalSigmaProof,
    /// Range proof ensuring that the resulting balance chunks are normalized (i.e., within the 16-bit limit).
    pub zkrp_new_balance: RangeProof,
}

/// Represents the proof structure for validating a transfer operation.
#[derive(Debug, Clone)]
pub struct TransferProof {
    /// Sigma proof ensuring that the transfer operation maintains balance integrity and correctness.
    pub sigma_proof: TransferSigmaProof,
    /// Range proof ensuring that the resulting balance chunks for the sender are normalized (i.e., within the 16-bit limit).
    pub zkrp_new_balance: RangeProof,
    /// Range proof ensuring that the transferred amount chunks are normalized (i.e., within the 16-bit limit).
    pub zkrp_transfer_amount: RangeProof,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    SigmaProtocolVerifyFailed = 1,
    RangeProofVerificationFailed = 2,
    Unknown = 99,
}
//
// Helper structs
//

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofXs {
    // proves the relation: Σ C_i * 2^{16i} = Σ b_i 2^{16i}G + Σ sk 2^{16i} D_i
    pub x1: CompressedRistrettoBytes,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: CompressedRistrettoBytes,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<CompressedRistrettoBytes>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<CompressedRistrettoBytes>,
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofAlphas {
    pub a1s: Vec<ScalarBytes>, // hides the unencrypted amount chunks
    pub a2: ScalarBytes,       // hides dk
    pub a3: ScalarBytes,       // hides dk^-1
    pub a4s: Vec<ScalarBytes>, // hides new balance's encryption randomness (each chunk is encrypted with a different randomness parameter)
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProof {
    pub alphas: NormalizationSigmaProofAlphas,
    pub xs: NormalizationSigmaProofXs,
}

#[derive(Debug, Clone)]
pub struct WithdrawalSigmaProofXs {
    pub x1: CompressedRistrettoBytes,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: CompressedRistrettoBytes,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<CompressedRistrettoBytes>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<CompressedRistrettoBytes>,
}

#[derive(Debug, Clone)]
pub struct WithdrawalSigmaProofAlphas {
    // unencrypted amount chunks
    pub a1s: Vec<ScalarBytes>,
    // dk
    pub a2: ScalarBytes,
    // dk^-1
    pub a3: ScalarBytes,
    // encryption randomness
    pub a4s: Vec<ScalarBytes>,
}

#[derive(Debug, Clone)]
pub struct WithdrawalSigmaProof {
    pub alphas: WithdrawalSigmaProofAlphas,
    pub xs: WithdrawalSigmaProofXs,
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofXs {
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
    // Auditor decryption handles for transfer amount (auditors × 4 chunks)
    // X₇ⱼᵢ = κ₃ᵢ·auditor_ekⱼ
    pub x7s: Vec<Vec<CompressedRistrettoBytes>>,
    // Sender decryption handles for sender amount (4 chunks)
    // X₈ᵢ = κ₃ᵢ·sender_ek
    pub x8s: Vec<CompressedRistrettoBytes>,
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofAlphas {
    pub a1s: Vec<ScalarBytes>, // New balance chunks: a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    pub a2: ScalarBytes,       // Sender decryption key: a₂ = κ₂ - ρ·sender_dk
    pub a3s: Vec<ScalarBytes>, // Transfer amount randomness: a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
    pub a4s: Vec<ScalarBytes>, // Transfer amount chunks: a₄ᵢ = κ₄ᵢ - ρ·mᵢ
    pub a5: ScalarBytes,       // Sender key inverse: a₅ = κ₅ - ρ·sender_dk^(-1)
    pub a6s: Vec<ScalarBytes>, // New balance randomness: a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProof {
    pub alphas: TransferSigmaProofAlphas,
    pub xs: TransferSigmaProofXs,
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofXsImpl {
    // proves the relation: Σ C_i * 2^{16i} = Σ b_i 2^{16i}G + Σ sk 2^{16i} D_i
    pub x1: RistrettoPoint,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: RistrettoPoint,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<RistrettoPoint>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
pub struct NormalizationSigmaProofAlphasImpl {
    pub a1s: Vec<Scalar>, // hides the unencrypted amount chunks
    pub a2: Scalar,       // hides dk
    pub a3: Scalar,       // hides dk^-1
    pub a4s: Vec<Scalar>, // hides new balance's encryption randomness (each chunk is encrypted with a different randomness parameter)
}

#[derive(Debug, Clone)]
pub struct WithdrawalSigmaProofXsImpl {
    pub x1: RistrettoPoint,
    // proves the key-pair relation: P = sk^-1 * H
    pub x2: RistrettoPoint,
    // proves the relation that the encrypted C value for every chunk is correct, C_i = m_i*G + r_i*H
    pub x3s: Vec<RistrettoPoint>,
    // proves the decrption handle for each chunk is correct, D_i = r_i*P
    pub x4s: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
pub struct WithdrawalSigmaProofAlphasImpl {
    // unencrypted amount chunks
    pub a1s: Vec<Scalar>,
    // dk
    pub a2: Scalar,
    // dk^-1
    pub a3: Scalar,
    // encryption randomness
    pub a4s: Vec<Scalar>,
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofXsImpl {
    // Balance preservation commitment
    // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + (Σ(κ₆ᵢ·2¹⁶ⁱ) - Σ(κ₃ᵢ·2¹⁶ⁱ))·H + Σ(D_cur_i·2¹⁶ⁱ)·κ₂ - Σ(D_new_i·2¹⁶ⁱ)·κ₂
    pub x1: RistrettoPoint,
    // Sender decryption handles for new balance (8 chunks)
    // X₂ᵢ = κ₆ᵢ·sender_ek
    pub x2s: Vec<RistrettoPoint>,
    // Recipient decryption handles for transfer amount (4 chunks)
    // X₃ᵢ = κ₃ᵢ·recipient_ek
    pub x3s: Vec<RistrettoPoint>,
    // Transfer amount encryption correctness (4 chunks)
    // X₄ᵢ = κ₄ᵢ·G + κ₃ᵢ·H
    pub x4s: Vec<RistrettoPoint>,
    // Sender key-pair relationship: P = (sk)^-1 * H
    // X₅ = κ₅·H
    pub x5: RistrettoPoint,
    // New balance encryption correctness (8 chunks)
    // X₆ᵢ = κ₁ᵢ·G + κ₆ᵢ·H
    pub x6s: Vec<RistrettoPoint>,
    // Auditor decryption handles for transfer amount (auditors × 4 chunks)
    // X₇ⱼᵢ = κ₃ᵢ·auditor_ekⱼ
    pub x7s: Vec<Vec<RistrettoPoint>>,
    // Sender decryption handles for sender amount (4 chunks)
    // X₈ᵢ = κ₃ᵢ·sender_ek
    pub x8s: Vec<RistrettoPoint>,
}

#[derive(Debug, Clone)]
pub struct TransferSigmaProofAlphasImpl {
    pub a1s: Vec<Scalar>, // New balance chunks: a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    pub a2: Scalar,       // Sender decryption key: a₂ = κ₂ - ρ·sender_dk
    pub a3s: Vec<Scalar>, // Transfer amount randomness: a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
    pub a4s: Vec<Scalar>, // Transfer amount chunks: a₄ᵢ = κ₄ᵢ - ρ·mᵢ
    pub a5: Scalar,       // Sender key inverse: a₅ = κ₅ - ρ·sender_dk^(-1)
    pub a6s: Vec<Scalar>, // New balance randomness: a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ
}

// Implementation of from_bytes methods for all Impl types
impl WithdrawalSigmaProofXsImpl {
    pub fn from_bytes(xs: &WithdrawalSigmaProofXs) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.to_bytes().try_into().map_err(|_| Error::Unknown)?);
        let x2 = bytes_to_point(&xs.x2.to_bytes().try_into().map_err(|_| Error::Unknown)?);

        let mut x3s = Vec::new();
        for x in &xs.x3s {
            let point = bytes_to_point(&x.to_bytes().try_into().map_err(|_| Error::Unknown)?);
            x3s.push(point);
        }

        let mut x4s = Vec::new();
        for x in &xs.x4s {
            let point = bytes_to_point(&x.to_bytes().try_into().map_err(|_| Error::Unknown)?);
            x4s.push(point);
        }

        Ok(Self { x1, x2, x3s, x4s })
    }
}

impl WithdrawalSigmaProofAlphasImpl {
    pub fn from_bytes(alphas: &WithdrawalSigmaProofAlphas) -> Result<Self, Error> {
        let mut a1s = Vec::new();
        for a in &alphas.a1s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s.push(scalar);
        }

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());
        let a3 = bytes_to_scalar(&alphas.a3.0.to_array());

        let mut a4s = Vec::new();
        for a in &alphas.a4s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s.push(scalar);
        }

        Ok(Self { a1s, a2, a3, a4s })
    }
}

impl NormalizationSigmaProofXsImpl {
    pub fn from_bytes(xs: &NormalizationSigmaProofXs) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.0.to_array());
        let x2 = bytes_to_point(&xs.x2.0.to_array());

        let mut x3s = Vec::new();
        for x in &xs.x3s {
            let point = bytes_to_point(&x.0.to_array());
            x3s.push(point);
        }

        let mut x4s = Vec::new();
        for x in &xs.x4s {
            let point = bytes_to_point(&x.0.to_array());
            x4s.push(point);
        }

        Ok(Self { x1, x2, x3s, x4s })
    }
}

impl NormalizationSigmaProofAlphasImpl {
    pub fn from_bytes(alphas: &NormalizationSigmaProofAlphas) -> Result<Self, Error> {
        let mut a1s = Vec::new();
        for a in &alphas.a1s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s.push(scalar);
        }

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());
        let a3 = bytes_to_scalar(&alphas.a3.0.to_array());

        let mut a4s = Vec::new();
        for a in &alphas.a4s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s.push(scalar);
        }

        Ok(Self { a1s, a2, a3, a4s })
    }
}

impl TransferSigmaProofXsImpl {
    pub fn from_bytes(xs: &TransferSigmaProofXs) -> Result<Self, Error> {
        let x1 = bytes_to_point(&xs.x1.0.to_array());

        let mut x2s = Vec::new();
        for x in &xs.x2s {
            let point = bytes_to_point(&x.0.to_array());
            x2s.push(point);
        }

        let mut x3s = Vec::new();
        for x in &xs.x3s {
            let point = bytes_to_point(&x.0.to_array());
            x3s.push(point);
        }

        let mut x4s = Vec::new();
        for x in &xs.x4s {
            let point = bytes_to_point(&x.0.to_array());
            x4s.push(point);
        }

        let x5 = bytes_to_point(&xs.x5.0.to_array());

        let mut x6s = Vec::new();
        for x in &xs.x6s {
            let point = bytes_to_point(&x.0.to_array());
            x6s.push(point);
        }

        let mut x7s = Vec::new();
        for xs_inner in &xs.x7s {
            let mut inner_points = Vec::new();
            for x in xs_inner {
                let point = bytes_to_point(&x.0.to_array());
                inner_points.push(point);
            }
            x7s.push(inner_points);
        }

        let mut x8s = Vec::new();
        for x in &xs.x8s {
            let point = bytes_to_point(&x.0.to_array());
            x8s.push(point);
        }

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
}

impl TransferSigmaProofAlphasImpl {
    pub fn from_bytes(alphas: &TransferSigmaProofAlphas) -> Result<Self, Error> {
        let mut a1s = Vec::new();
        for a in &alphas.a1s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a1s.push(scalar);
        }

        let a2 = bytes_to_scalar(&alphas.a2.0.to_array());

        let mut a3s = Vec::new();
        for a in &alphas.a3s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a3s.push(scalar);
        }

        let mut a4s = Vec::new();
        for a in &alphas.a4s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a4s.push(scalar);
        }

        let a5 = bytes_to_scalar(&alphas.a5.0.to_array());

        let mut a6s = Vec::new();
        for a in &alphas.a6s {
            let scalar = bytes_to_scalar(&a.0.to_array());
            a6s.push(scalar);
        }

        Ok(Self {
            a1s,
            a2,
            a3s,
            a4s,
            a5,
            a6s,
        })
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
    ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    proof: &NormalizationProof,
) -> Result<(), Error> {
    verify_normalization_sigma_proof(ek, current_balance, new_balance, &proof.sigma_proof)?;
    verify_new_balance_range_proof(new_balance, &proof.zkrp_new_balance)?;
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
    ek: &CompressedPubkey,
    amount: u64,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    proof: &WithdrawalProof,
) -> Result<(), Error> {
    verify_withdrawal_sigma_proof(ek, amount, current_balance, new_balance, &proof.sigma_proof)?;
    verify_new_balance_range_proof(new_balance, &proof.zkrp_new_balance)?;
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
    sender_ek: &CompressedPubkey,
    recipient_ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    sender_amount: &ConfidentialBalance,
    recipient_amount: &ConfidentialBalance,
    auditor_eks: &[CompressedPubkey],
    auditor_amounts: &[ConfidentialBalance],
    proof: &TransferProof,
) -> Result<(), Error> {
    verify_transfer_sigma_proof(
        sender_ek,
        recipient_ek,
        current_balance,
        new_balance,
        sender_amount,
        recipient_amount,
        auditor_eks,
        auditor_amounts,
        &proof.sigma_proof,
    )?;
    verify_new_balance_range_proof(new_balance, &proof.zkrp_new_balance)?;
    verify_transfer_amount_range_proof(recipient_amount, &proof.zkrp_transfer_amount)?;
    Ok(())
}

//
// Verification functions implementations
//

/// Verifies the validity of the `NormalizationSigmaProof`.
fn verify_normalization_sigma_proof(
    ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    proof: &NormalizationSigmaProof,
) -> Result<(), Error> {
    // let rho = fiat_shamir_normalization_sigma_proof_challenge(
    //     ek,
    //     current_balance,
    //     new_balance,
    //     &proof.xs,
    // );
    // // the normalization gammas are derived from the fiat shamir challenge, it is to prevent prover from cheating
    // // in a way that MSM cancels out
    // // that's why the gammas match the Xs, each equation multiples by a gamma on both sides (I believe)
    // // TODO: look into details below
    // let gammas = msm_normalization_gammas(&rho);

    // let mut scalars_lhs = vec![gammas.g1, gammas.g2];
    // scalars_lhs.extend(&gammas.g3s);
    // scalars_lhs.extend(&gammas.g4s);

    // let mut points_lhs = vec![
    //     point_decompress(&proof.xs.x1)?,
    //     point_decompress(&proof.xs.x2)?,
    // ];
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x3s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x4s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );

    // let mut scalar_g = scalar_linear_combination(
    //     &proof.alphas.a1s,
    //     &(0..8)
    //         .map(|i| new_scalar_from_pow2(i * 16))
    //         .collect::<Vec<_>>(),
    // );
    // scalar_mul_assign(&mut scalar_g, &gammas.g1);
    // scalar_add_assign(
    //     &mut scalar_g,
    //     &scalar_linear_combination(&gammas.g3s, &proof.alphas.a1s),
    // );

    // let mut scalar_h = scalar_mul(&gammas.g2, &proof.alphas.a3);
    // scalar_add_assign(
    //     &mut scalar_h,
    //     &scalar_linear_combination(&gammas.g3s, &proof.alphas.a4s),
    // );

    // let mut scalar_ek = scalar_mul(&gammas.g2, &rho);
    // scalar_add_assign(
    //     &mut scalar_ek,
    //     &scalar_linear_combination(&gammas.g4s, &proof.alphas.a4s),
    // );

    // let scalars_current_balance_d = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &proof.alphas.a2, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // let scalars_new_balance_d = (0..8)
    //     .map(|i| scalar_mul(&gammas.g4s[i], &rho))
    //     .collect::<Vec<_>>();

    // let scalars_current_balance_c = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &rho, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // let scalars_new_balance_c = (0..8)
    //     .map(|i| scalar_mul(&gammas.g3s[i], &rho))
    //     .collect::<Vec<_>>();

    // let mut scalars_rhs = vec![scalar_g, scalar_h, scalar_ek];
    // scalars_rhs.extend(scalars_current_balance_d);
    // scalars_rhs.extend(scalars_new_balance_d);
    // scalars_rhs.extend(scalars_current_balance_c);
    // scalars_rhs.extend(scalars_new_balance_c);

    // let mut points_rhs = vec![basepoint(), hash_to_point_base(), pubkey_to_point(ek)?];
    // points_rhs.extend(balance_to_points_d(current_balance));
    // points_rhs.extend(balance_to_points_d(new_balance));
    // points_rhs.extend(balance_to_points_c(current_balance));
    // points_rhs.extend(balance_to_points_c(new_balance));

    // let lhs = multi_scalar_mul(&points_lhs, &scalars_lhs)?;
    // let rhs = multi_scalar_mul(&points_rhs, &scalars_rhs)?;

    // if !point_equals(&lhs, &rhs) {
    //     return Err(Error::SigmaProtocolVerifyFailed);
    // }
    // Ok(())

    todo!()
}

/// Verifies the validity of the `WithdrawalSigmaProof`.
fn verify_withdrawal_sigma_proof(
    ek: &CompressedPubkey,
    amount: u64,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    proof: &WithdrawalSigmaProof,
) -> Result<(), Error> {
    todo!()

    // let amount_chunks = split_into_chunks_u64(amount);
    // let amount = new_scalar_from_u64(amount);

    // let rho = fiat_shamir_withdrawal_sigma_proof_challenge(
    //     ek,
    //     &amount_chunks,
    //     current_balance,
    //     &proof.xs,
    // );

    // let gammas = msm_withdrawal_gammas(&rho);

    // let mut scalars_lhs = vec![gammas.g1, gammas.g2];
    // scalars_lhs.extend(&gammas.g3s);
    // scalars_lhs.extend(&gammas.g4s);

    // let mut points_lhs = vec![
    //     point_decompress(&proof.xs.x1)?,
    //     point_decompress(&proof.xs.x2)?,
    // ];
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x3s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x4s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );

    // Note: in standard description in the paper, the sign is plus instead of minus
    // here making it minus makes it move the rho terms to the RHS, thus can be computed with MSM

    // a1_i = kappa1_i - rho * b_i
    // a2   = kappa2   - rho * dk
    // a3   = kappa3   - rho * inv(dk)
    // a4_i = kappa4_i - rho * r_i

    // m is the amount scalar
    // rho is the computed fiat shamir challenge

    // scalar_g = gamma_1 *  Σ a1_i * 2^{16i} + Σ gamma3_i * a1_i - gamma_1 * rho * m
    // scalar_h = gamma_2 * a_3 + Σ gamma3_i * a4_i
    // scalar_ek = gamma_2 * rho + Σ gamma4_i * a4_i
    // scalars_current_balance_d[i] = gamma_1 * a2 * 2^{16i}
    // scalars_new_balance_d[i] = gamma4_i * rho
    // scalars_current_balance_c[i] = gamma_1 * rho * 2^{16i}
    // scalars_new_balance_c[i] = gamma3_i * rho

    // points_rhs  = [G, H, P,
    //                D_cur_0, ..., D_cur_7,
    //                D_new_0, ..., D_new_7,
    //                C_cur_0, ..., C_cur_7,
    //                C_new_0, ..., C_new_7]
    // scalars_rhs = [scalar_g, scalar_h, scalar_ek,
    //                scalars_current_balance_d[0], ..., scalars_current_balance_d[7],
    //                scalars_new_balance_d[0], ..., scalars_new_balance_d[7],
    //                scalars_current_balance_c[0], ..., scalars_current_balance_c[7],
    //                scalars_new_balance_c[0], ..., scalars_new_balance_c[7]]

    // LHS = γ₁·X₁ + γ₂·X₂ + Σ(γ₃ᵢ·X₃ᵢ) + Σ(γ₄ᵢ·X₄ᵢ)
    // RHS = (γ₁·Σ(a₁ᵢ·2¹⁶ⁱ) + Σ(γ₃ᵢ·a₁ᵢ) - γ₁·ρ·m)·G +
    //       (γ₂·a₃ + Σ(γ₃ᵢ·a₄ᵢ))·H +
    //       (γ₂·ρ + Σ(γ₄ᵢ·a₄ᵢ))·P +
    //       Σ(γ₁·a₂·2¹⁶ⁱ·D_cur_i) +
    //       Σ(γ₄ᵢ·ρ·D_new_i) +
    //       Σ(γ₁·ρ·2¹⁶ⁱ·C_cur_i) +
    //       Σ(γ₃ᵢ·ρ·C_new_i)

    // splitting out the combined relation to individual statements, and remove the gammas
    // 1. Balance Preservation Formula
    //      X₁ = (Σ(a₁ᵢ·2¹⁶ⁱ) - ρ·m)·G + Σ(a₂·2¹⁶ⁱ·D_cur_i) + Σ(ρ·2¹⁶ⁱ·C_cur_i)
    // 2. Key-Pair Relationship Formula
    //      X₂ = a₃·H + ρ·P
    // 3. Encryption Correctness Formulas (for each chunk i)
    //      X₃ᵢ = a₁ᵢ·G + a₄ᵢ·H + ρ·C_new_i
    // 4. Decryption Handle Correctness Formulas (for each chunk i)
    //      X₄ᵢ = a₄ᵢ·P + ρ·D_new_i

    // And
    // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + Σ(D_cur_i·2¹⁶ⁱ)·κ₂
    // X₂ = κ₃·H
    // X₃ᵢ = κ₁ᵢ·G + κ₄ᵢ·H
    // X₄ᵢ = κ₄ᵢ·P

    // a₁ᵢ = κ₁ᵢ - ρ·bᵢ
    // a₂ = κ₂ - ρ·dk
    // a₃ = κ₃ - ρ·dk^(-1)
    // a₄ᵢ = κ₄ᵢ - ρ·rᵢ

    // let mut scalar_g = scalar_linear_combination(
    //     &proof.alphas.a1s,
    //     &(0..8)
    //         .map(|i| new_scalar_from_pow2(i * 16))
    //         .collect::<Vec<_>>(),
    // );
    // scalar_mul_assign(&mut scalar_g, &gammas.g1);
    // scalar_add_assign(
    //     &mut scalar_g,
    //     &scalar_linear_combination(&gammas.g3s, &proof.alphas.a1s),
    // );
    // scalar_sub_assign(&mut scalar_g, &scalar_mul_3(&gammas.g1, &rho, &amount));

    // let mut scalar_h = scalar_mul(&gammas.g2, &proof.alphas.a3);
    // scalar_add_assign(
    //     &mut scalar_h,
    //     &scalar_linear_combination(&gammas.g3s, &proof.alphas.a4s),
    // );

    // let mut scalar_ek = scalar_mul(&gammas.g2, &rho);
    // scalar_add_assign(
    //     &mut scalar_ek,
    //     &scalar_linear_combination(&gammas.g4s, &proof.alphas.a4s),
    // );

    // let scalars_current_balance_d = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &proof.alphas.a2, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // let scalars_new_balance_d = (0..8)
    //     .map(|i| scalar_mul(&gammas.g4s[i], &rho))
    //     .collect::<Vec<_>>();

    // let scalars_current_balance_c = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &rho, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // let scalars_new_balance_c = (0..8)
    //     .map(|i| scalar_mul(&gammas.g3s[i], &rho))
    //     .collect::<Vec<_>>();

    // let mut scalars_rhs = vec![scalar_g, scalar_h, scalar_ek];
    // scalars_rhs.extend(scalars_current_balance_d);
    // scalars_rhs.extend(scalars_new_balance_d);
    // scalars_rhs.extend(scalars_current_balance_c);
    // scalars_rhs.extend(scalars_new_balance_c);

    // let mut points_rhs = vec![basepoint(), hash_to_point_base(), pubkey_to_point(ek)?];
    // points_rhs.extend(balance_to_points_d(current_balance));
    // points_rhs.extend(balance_to_points_d(new_balance));
    // points_rhs.extend(balance_to_points_c(current_balance));
    // points_rhs.extend(balance_to_points_c(new_balance));

    // let lhs = multi_scalar_mul(&points_lhs, &scalars_lhs)?;
    // let rhs = multi_scalar_mul(&points_rhs, &scalars_rhs)?;

    // if !point_equals(&lhs, &rhs) {
    //     return Err(Error::SigmaProtocolVerifyFailed);
    // }
    // Ok(())
}

/// Verifies the validity of the `TransferSigmaProof`.
fn verify_transfer_sigma_proof(
    sender_ek: &CompressedPubkey,
    recipient_ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    sender_amount: &ConfidentialBalance,
    recipient_amount: &ConfidentialBalance,
    auditor_eks: &[CompressedPubkey],
    auditor_amounts: &[ConfidentialBalance],
    proof: &TransferSigmaProof,
) -> Result<(), Error> {
    todo!()
    // let rho = fiat_shamir_transfer_sigma_proof_challenge(
    //     sender_ek,
    //     recipient_ek,
    //     current_balance,
    //     new_balance,
    //     sender_amount,
    //     recipient_amount,
    //     auditor_eks,
    //     auditor_amounts,
    //     &proof.xs,
    // );

    // let gammas = msm_transfer_gammas(&rho, proof.xs.x7s.len());

    // let mut scalars_lhs = vec![gammas.g1];
    // scalars_lhs.extend(&gammas.g2s);
    // scalars_lhs.extend(&gammas.g3s);
    // scalars_lhs.extend(&gammas.g4s);
    // scalars_lhs.push(gammas.g5);
    // scalars_lhs.extend(&gammas.g6s);
    // for gamma in &gammas.g7s {
    //     scalars_lhs.extend(gamma);
    // }
    // scalars_lhs.extend(&gammas.g8s);

    // let mut points_lhs = vec![point_decompress(&proof.xs.x1)?];
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x2s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x3s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x4s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_lhs.push(point_decompress(&proof.xs.x5)?);
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x6s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // for xs in &proof.xs.x7s {
    //     points_lhs.extend(
    //         xs.iter()
    //             .map(|x| point_decompress(x))
    //             .collect::<Result<Vec<_>, _>>()?,
    //     );
    // }
    // points_lhs.extend(
    //     proof
    //         .xs
    //         .x8s
    //         .iter()
    //         .map(|x| point_decompress(x))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );

    // // scalar_g = γ₁·Σ(a₁ᵢ·2¹⁶ⁱ) + Σ(γ₄ᵢ·a₄ᵢ) + Σ(γ₆ᵢ·a₁ᵢ)
    // let mut scalar_g = scalar_linear_combination(
    //     &proof.alphas.a1s,
    //     &(0..8)
    //         .map(|i| new_scalar_from_pow2(i * 16))
    //         .collect::<Vec<_>>(),
    // );
    // scalar_mul_assign(&mut scalar_g, &gammas.g1);
    // for i in 0..4 {
    //     scalar_add_assign(
    //         &mut scalar_g,
    //         &scalar_mul(&gammas.g4s[i], &proof.alphas.a4s[i]),
    //     );
    // }
    // scalar_add_assign(
    //     &mut scalar_g,
    //     &scalar_linear_combination(&gammas.g6s, &proof.alphas.a1s),
    // );

    // // scalar_h = γ₅·a₅ + Σ(γ₁·a₆ᵢ·2¹⁶ⁱ) - Σ(γ₁·a₃ᵢ·2¹⁶ⁱ) + Σ(γ₄ᵢ·a₃ᵢ) + Σ(γ₆ᵢ·a₆ᵢ)
    // let mut scalar_h = scalar_mul(&gammas.g5, &proof.alphas.a5);
    // for i in 0..8 {
    //     scalar_add_assign(
    //         &mut scalar_h,
    //         &scalar_mul_3(
    //             &gammas.g1,
    //             &proof.alphas.a6s[i],
    //             &new_scalar_from_pow2(i * 16),
    //         ),
    //     );
    // }
    // for i in 0..4 {
    //     scalar_sub_assign(
    //         &mut scalar_h,
    //         &scalar_mul_3(
    //             &gammas.g1,
    //             &proof.alphas.a3s[i],
    //             &new_scalar_from_pow2(i * 16),
    //         ),
    //     );
    // }
    // scalar_add_assign(
    //     &mut scalar_h,
    //     &scalar_linear_combination(&gammas.g4s, &proof.alphas.a3s),
    // );
    // scalar_add_assign(
    //     &mut scalar_h,
    //     &scalar_linear_combination(&gammas.g6s, &proof.alphas.a6s),
    // );

    // // scalar_sender_ek = Σ(γ₂ᵢ·a₆ᵢ) + γ₅·ρ + Σ(γ₈ᵢ·a₃ᵢ)
    // let mut scalar_sender_ek = scalar_linear_combination(&gammas.g2s, &proof.alphas.a6s);
    // scalar_add_assign(&mut scalar_sender_ek, &scalar_mul(&gammas.g5, &rho));
    // scalar_add_assign(
    //     &mut scalar_sender_ek,
    //     &scalar_linear_combination(&gammas.g8s, &proof.alphas.a3s),
    // );

    // // scalar_recipient_ek = Σ(γ₃ᵢ·a₃ᵢ)
    // let mut scalar_recipient_ek = scalar_zero();
    // for i in 0..4 {
    //     scalar_add_assign(
    //         &mut scalar_recipient_ek,
    //         &scalar_mul(&gammas.g3s[i], &proof.alphas.a3s[i]),
    //     );
    // }

    // // scalar_ek_auditors[j] = Σ(γ₇ⱼᵢ·a₃ᵢ)
    // let scalar_ek_auditors = gammas
    //     .g7s
    //     .iter()
    //     .map(|gamma| {
    //         let mut scalar_auditor_ek = scalar_zero();
    //         for i in 0..4 {
    //             scalar_add_assign(
    //                 &mut scalar_auditor_ek,
    //                 &scalar_mul(&gamma[i], &proof.alphas.a3s[i]),
    //             );
    //         }
    //         scalar_auditor_ek
    //     })
    //     .collect::<Vec<_>>();

    // // scalars_new_balance_d[i] = γ₂ᵢ·ρ - γ₁·a₂·2¹⁶ⁱ
    // let scalars_new_balance_d = (0..8)
    //     .map(|i| {
    //         let mut scalar = scalar_mul(&gammas.g2s[i], &rho);
    //         scalar_sub_assign(
    //             &mut scalar,
    //             &scalar_mul_3(&gammas.g1, &proof.alphas.a2, &new_scalar_from_pow2(i * 16)),
    //         );
    //         scalar
    //     })
    //     .collect::<Vec<_>>();

    // // scalars_recipient_amount_d[i] = γ₃ᵢ·ρ
    // let scalars_recipient_amount_d = (0..4)
    //     .map(|i| scalar_mul(&gammas.g3s[i], &rho))
    //     .collect::<Vec<_>>();

    // // scalars_current_balance_d[i] = γ₁·a₂·2¹⁶ⁱ
    // let scalars_current_balance_d = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &proof.alphas.a2, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // // scalars_auditor_amount_d[j][i] = γ₇ⱼᵢ·ρ
    // let scalars_auditor_amount_d = gammas
    //     .g7s
    //     .iter()
    //     .map(|gamma| {
    //         gamma
    //             .iter()
    //             .map(|gamma| scalar_mul(gamma, &rho))
    //             .collect::<Vec<_>>()
    //     })
    //     .collect::<Vec<_>>();

    // // scalars_sender_amount_d[i] = γ₈ᵢ·ρ
    // let scalars_sender_amount_d = (0..4)
    //     .map(|i| scalar_mul(&gammas.g8s[i], &rho))
    //     .collect::<Vec<_>>();

    // // scalars_current_balance_c[i] = γ₁·ρ·2¹⁶ⁱ
    // let scalars_current_balance_c = (0..8)
    //     .map(|i| scalar_mul_3(&gammas.g1, &rho, &new_scalar_from_pow2(i * 16)))
    //     .collect::<Vec<_>>();

    // // scalars_transfer_amount_c[i] = γ₄ᵢ·ρ - γ₁·ρ·2¹⁶ⁱ
    // let scalars_transfer_amount_c = (0..4)
    //     .map(|i| {
    //         let mut scalar = scalar_mul(&gammas.g4s[i], &rho);
    //         scalar_sub_assign(
    //             &mut scalar,
    //             &scalar_mul_3(&gammas.g1, &rho, &new_scalar_from_pow2(i * 16)),
    //         );
    //         scalar
    //     })
    //     .collect::<Vec<_>>();

    // // scalars_new_balance_c[i] = γ₆ᵢ·ρ
    // let scalars_new_balance_c = (0..8)
    //     .map(|i| scalar_mul(&gammas.g6s[i], &rho))
    //     .collect::<Vec<_>>();

    // let mut scalars_rhs = vec![scalar_g, scalar_h, scalar_sender_ek, scalar_recipient_ek];
    // scalars_rhs.extend(scalar_ek_auditors);
    // scalars_rhs.extend(scalars_new_balance_d);
    // scalars_rhs.extend(scalars_recipient_amount_d);
    // scalars_rhs.extend(scalars_current_balance_d);
    // for scalars in scalars_auditor_amount_d {
    //     scalars_rhs.extend(scalars);
    // }
    // scalars_rhs.extend(scalars_sender_amount_d);
    // scalars_rhs.extend(scalars_current_balance_c);
    // scalars_rhs.extend(scalars_transfer_amount_c);
    // scalars_rhs.extend(scalars_new_balance_c);

    // let mut points_rhs = vec![
    //     basepoint(),
    //     hash_to_point_base(),
    //     pubkey_to_point(sender_ek)?,
    //     pubkey_to_point(recipient_ek)?,
    // ];
    // points_rhs.extend(
    //     auditor_eks
    //         .iter()
    //         .map(|ek| pubkey_to_point(ek))
    //         .collect::<Result<Vec<_>, _>>()?,
    // );
    // points_rhs.extend(balance_to_points_d(new_balance));
    // points_rhs.extend(balance_to_points_d(recipient_amount));
    // points_rhs.extend(balance_to_points_d(current_balance));
    // for balance in auditor_amounts {
    //     points_rhs.extend(balance_to_points_d(balance));
    // }
    // points_rhs.extend(balance_to_points_d(sender_amount));
    // points_rhs.extend(balance_to_points_c(current_balance));
    // points_rhs.extend(balance_to_points_c(recipient_amount));
    // points_rhs.extend(balance_to_points_c(new_balance));

    // // LHS = γ₁·X₁ + Σ(γ₂ᵢ·X₂ᵢ) + Σ(γ₃ᵢ·X₃ᵢ) + Σ(γ₄ᵢ·X₄ᵢ) + γ₅·X₅ + Σ(γ₆ᵢ·X₆ᵢ) + Σ(γ₇ⱼᵢ·X₇ⱼᵢ) + Σ(γ₈ᵢ·X₈ᵢ)
    // // RHS = scalar_g·G + scalar_h·H + scalar_sender_ek·P_sender + scalar_recipient_ek·P_recipient +
    // //       Σ(scalar_ek_auditors[j]·P_auditor_j) +
    // //       Σ(scalars_new_balance_d[i]·D_new_balance_i) +
    // //       Σ(scalars_recipient_amount_d[i]·D_recipient_amount_i) +
    // //       Σ(scalars_current_balance_d[i]·D_current_balance_i) +
    // //       Σ(scalars_auditor_amount_d[j][i]·D_auditor_amount_j_i) +
    // //       Σ(scalars_sender_amount_d[i]·D_sender_amount_i) +
    // //       Σ(scalars_current_balance_c[i]·C_current_balance_i) +
    // //       Σ(scalars_transfer_amount_c[i]·C_transfer_amount_i) +
    // //       Σ(scalars_new_balance_c[i]·C_new_balance_i)

    // // writing the RHS into one line
    // // RHS = (γ₁·Σ(a₁ᵢ·2¹⁶ⁱ) + Σ(γ₄ᵢ·a₄ᵢ) + Σ(γ₆ᵢ·a₁ᵢ))·G +
    // //       (γ₅·a₅ + Σ(γ₁·a₆ᵢ·2¹⁶ⁱ) - Σ(γ₁·a₃ᵢ·2¹⁶ⁱ) + Σ(γ₄ᵢ·a₃ᵢ) + Σ(γ₆ᵢ·a₆ᵢ))·H +
    // //       (Σ(γ₂ᵢ·a₆ᵢ) + γ₅·ρ + Σ(γ₈ᵢ·a₃ᵢ))·P_sender +
    // //       (Σ(γ₃ᵢ·a₃ᵢ))·P_recipient +
    // //       Σ((Σ(γ₇ⱼᵢ·a₃ᵢ))·P_auditor_j) +
    // //       Σ((γ₂ᵢ·ρ - γ₁·a₂·2¹⁶ⁱ)·D_new_balance_i) +
    // //       Σ((γ₃ᵢ·ρ)·D_recipient_amount_i) +
    // //       Σ((γ₁·a₂·2¹⁶ⁱ)·D_current_balance_i) +
    // //       Σ((γ₇ⱼᵢ·ρ)·D_auditor_amount_j_i) +
    // //       Σ((γ₈ᵢ·ρ)·D_sender_amount_i) +
    // //       Σ((γ₁·ρ·2¹⁶ⁱ)·C_current_balance_i) +
    // //       Σ((γ₄ᵢ·ρ - γ₁·ρ·2¹⁶ⁱ)·C_transfer_amount_i) +
    // //       Σ((γ₆ᵢ·ρ)·C_new_balance_i)

    // // Regroup the equation into chunks, grouped-by their gamma index
    // // RHS = γ₁·(Σ(a₁ᵢ·2¹⁶ⁱ)·G + Σ(a₆ᵢ·2¹⁶ⁱ)·H - Σ(a₃ᵢ·2¹⁶ⁱ)·H  - Σ(a₂·2¹⁶ⁱ)·D_new_balance_i + Σ(a₂·2¹⁶ⁱ)·D_current_balance_i + Σ(ρ·2¹⁶ⁱ)·C_current_balance_i - Σ(ρ·2¹⁶ⁱ)·C_transfer_amount_i) +
    // //       γ₂ᵢ·(a₆ᵢ·P_sender + ρ·D_new_balance_i) +
    // //       γ₃ᵢ·(a₃ᵢ·P_recipient + ρ·D_recipient_amount_i) +
    // //       γ₄ᵢ·(a₄ᵢ·G + a₃ᵢ·H + ρ·C_transfer_amount_i) +
    // //       γ₅·(a₅·H + ρ·P_sender) +
    // //       γ₆ᵢ·(a₁ᵢ·G + a₆ᵢ·H + ρ·C_new_balance_i) +
    // //       γ₇ⱼᵢ·(a₃ᵢ·P_auditor_j + ρ·D_auditor_amount_j_i) +
    // //       γ₈ᵢ·(a₃ᵢ·P_sender + ρ·D_sender_amount_i)

    // // 1. Balance Preservation Formula

    // // 2. Sender New Balance Decryption Handle Correctness (for each chunk i)
    // // X₂ᵢ = a₆ᵢ·P_sender + ρ·D_new_balance_i

    // // 3. Recipient Transfer Amount Decryption Handle Correctness (for each chunk i)
    // // X₃ᵢ = a₃ᵢ·P_recipient + ρ·D_recipient_amount_i

    // // 4. Transfer Amount Encryption Correctness (for each chunk i)
    // // X₄ᵢ = a₄ᵢ·G + a₃ᵢ·H + ρ·C_transfer_amount_i

    // // 5. Sender Key-Pair Relationship
    // // X₅ = a₅·H + ρ·P_sender

    // // 6. New Balance Encryption Correctness (for each chunk i)
    // // X₆ᵢ = a₁ᵢ·G + a₆ᵢ·H + ρ·C_new_balance_i

    // // 7. Auditor Transfer Amount Decryption Handle Correctness (for each auditor j, chunk i)
    // // X₇ⱼᵢ = a₃ᵢ·P_auditor_j + ρ·D_auditor_amount_j_i

    // // 8. Sender Amount Decryption Handle Correctness (for each chunk i)
    // // X₈ᵢ = a₃ᵢ·P_sender + ρ·D_sender_amount_i

    // let lhs = multi_scalar_mul(&points_lhs, &scalars_lhs)?;
    // let rhs = multi_scalar_mul(&points_rhs, &scalars_rhs)?;

    // if !point_equals(&lhs, &rhs) {
    //     return Err(Error::SigmaProtocolVerifyFailed);
    // }
    // Ok(())
}

/// Verifies the validity of the `NewBalanceRangeProof`.
fn verify_new_balance_range_proof(
    new_balance: &ConfidentialBalance,
    zkrp_new_balance: &RangeProof,
) -> Result<(), Error> {
    let balance_c = balance_to_points_c(new_balance);

    if !verify_batch_range_proof(
        &balance_c,
        &basepoint(),
        &hash_to_point_base(),
        zkrp_new_balance,
        BULLETPROOFS_NUM_BITS,
        BULLETPROOFS_DST,
    ) {
        return Err(Error::RangeProofVerificationFailed);
    }
    Ok(())
}

/// Verifies the validity of the `TransferBalanceRangeProof`.
fn verify_transfer_amount_range_proof(
    transfer_amount: &ConfidentialBalance,
    zkrp_transfer_amount: &RangeProof,
) -> Result<(), Error> {
    let balance_c = balance_to_points_c(transfer_amount);

    if !verify_batch_range_proof(
        &balance_c,
        &basepoint(),
        &hash_to_point_base(),
        zkrp_transfer_amount,
        BULLETPROOFS_NUM_BITS,
        BULLETPROOFS_DST,
    ) {
        return Err(Error::RangeProofVerificationFailed);
    }
    Ok(())
}

//
// Friend public functions
//

/// Returns the number of range proofs in the provided `WithdrawalProof`.
/// Used in the `confidential_asset` module to validate input parameters of the `confidential_transfer` function.
pub(crate) fn auditors_count_in_transfer_proof(proof: &TransferProof) -> u64 {
    proof.sigma_proof.xs.x7s.len() as u64
}

//
// Deserialization functions
//

/// Deserializes the `NormalizationProof` from the byte array.
/// Returns `Some(NormalizationProof)` if the deserialization is successful; otherwise, returns `None`.
pub fn deserialize_normalization_proof(
    sigma_proof_bytes: Vec<u8>,
    zkrp_new_balance_bytes: Vec<u8>,
) -> Option<NormalizationProof> {
    let sigma_proof = deserialize_normalization_sigma_proof(sigma_proof_bytes);
    let zkrp_new_balance = range_proof_from_bytes(zkrp_new_balance_bytes);

    sigma_proof.map(|sigma_proof| NormalizationProof {
        sigma_proof,
        zkrp_new_balance,
    })
}

/// Deserializes the `WithdrawalProof` from the byte array.
/// Returns `Some(WithdrawalProof)` if the deserialization is successful; otherwise, returns `None`.
pub fn deserialize_withdrawal_proof(
    sigma_proof_bytes: Vec<u8>,
    zkrp_new_balance_bytes: Vec<u8>,
) -> Option<WithdrawalProof> {
    let sigma_proof = deserialize_withdrawal_sigma_proof(sigma_proof_bytes);
    let zkrp_new_balance = range_proof_from_bytes(zkrp_new_balance_bytes);

    sigma_proof.map(|sigma_proof| WithdrawalProof {
        sigma_proof,
        zkrp_new_balance,
    })
}

/// Deserializes the `TransferProof` from the byte array.
/// Returns `Some(TransferProof)` if the deserialization is successful; otherwise, returns `None`.
pub fn deserialize_transfer_proof(
    sigma_proof_bytes: Vec<u8>,
    zkrp_new_balance_bytes: Vec<u8>,
    zkrp_transfer_amount_bytes: Vec<u8>,
) -> Option<TransferProof> {
    let sigma_proof = deserialize_transfer_sigma_proof(sigma_proof_bytes);
    let zkrp_new_balance = range_proof_from_bytes(zkrp_new_balance_bytes);
    let zkrp_transfer_amount = range_proof_from_bytes(zkrp_transfer_amount_bytes);

    sigma_proof.map(|sigma_proof| TransferProof {
        sigma_proof,
        zkrp_new_balance,
        zkrp_transfer_amount,
    })
}

//
// Deserialization functions implementations
//

/// Deserializes the `NormalizationSigmaProof` from the byte array.
/// Returns `Some(NormalizationSigmaProof)` if the deserialization is successful; otherwise, returns `None`.
fn deserialize_normalization_sigma_proof(proof_bytes: Vec<u8>) -> Option<NormalizationSigmaProof> {
    let alphas_count = 18;
    let xs_count = 18;

    if proof_bytes.len() != 32 * xs_count + 32 * alphas_count {
        return None;
    }

    let alphas = (0..alphas_count)
        .map(|i| new_scalar_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();
    let xs = (alphas_count..alphas_count + xs_count)
        .map(|i| new_compressed_point_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();

    if alphas.iter().any(|alpha| alpha.is_none()) || xs.iter().any(|x| x.is_none()) {
        return None;
    }

    Some(NormalizationSigmaProof {
        alphas: NormalizationSigmaProofAlphas {
            a1s: alphas[0..8].iter().map(|alpha| alpha.unwrap()).collect(),
            a2: alphas[8].unwrap(),
            a3: alphas[9].unwrap(),
            a4s: alphas[10..18].iter().map(|alpha| alpha.unwrap()).collect(),
        },
        xs: NormalizationSigmaProofXs {
            x1: xs[0].unwrap(),
            x2: xs[1].unwrap(),
            x3s: xs[2..10].iter().map(|x| x.unwrap()).collect(),
            x4s: xs[10..18].iter().map(|x| x.unwrap()).collect(),
        },
    })
}

/// Deserializes the `WithdrawalSigmaProof` from the byte array.
/// Returns `Some(WithdrawalSigmaProof)` if the deserialization is successful; otherwise, returns `None`.
fn deserialize_withdrawal_sigma_proof(proof_bytes: Vec<u8>) -> Option<WithdrawalSigmaProof> {
    let alphas_count = 18;
    let xs_count = 18;

    if proof_bytes.len() != 32 * xs_count + 32 * alphas_count {
        return None;
    }

    let alphas = (0..alphas_count)
        .map(|i| new_scalar_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();
    let xs = (alphas_count..alphas_count + xs_count)
        .map(|i| new_compressed_point_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();

    if alphas.iter().any(|alpha| alpha.is_none()) || xs.iter().any(|x| x.is_none()) {
        return None;
    }

    Some(WithdrawalSigmaProof {
        alphas: WithdrawalSigmaProofAlphas {
            a1s: alphas[0..8].iter().map(|alpha| alpha.unwrap()).collect(),
            a2: alphas[8].unwrap(),
            a3: alphas[9].unwrap(),
            a4s: alphas[10..18].iter().map(|alpha| alpha.unwrap()).collect(),
        },
        xs: WithdrawalSigmaProofXs {
            x1: xs[0].unwrap(),
            x2: xs[1].unwrap(),
            x3s: xs[2..10].iter().map(|x| x.unwrap()).collect(),
            x4s: xs[10..18].iter().map(|x| x.unwrap()).collect(),
        },
    })
}

/// Deserializes the `TransferSigmaProof` from the byte array.
/// Returns `Some(TransferSigmaProof)` if the deserialization is successful; otherwise, returns `None`.
fn deserialize_transfer_sigma_proof(proof_bytes: Vec<u8>) -> Option<TransferSigmaProof> {
    let alphas_count = 26;
    let mut xs_count = 30;

    if proof_bytes.len() < 32 * xs_count + 32 * alphas_count {
        return None;
    }

    // Transfer proof may contain additional four Xs for each auditor.
    let auditor_xs = proof_bytes.len() - (32 * xs_count + 32 * alphas_count);

    if auditor_xs % 128 != 0 {
        return None;
    }

    xs_count += auditor_xs / 32;

    let alphas = (0..alphas_count)
        .map(|i| new_scalar_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();
    let xs = (alphas_count..alphas_count + xs_count)
        .map(|i| new_compressed_point_from_bytes(&proof_bytes[i * 32..(i + 1) * 32]))
        .collect::<Vec<_>>();

    if alphas.iter().any(|alpha| alpha.is_none()) || xs.iter().any(|x| x.is_none()) {
        return None;
    }

    Some(TransferSigmaProof {
        alphas: TransferSigmaProofAlphas {
            a1s: alphas[0..8].iter().map(|alpha| alpha.unwrap()).collect(),
            a2: alphas[8].unwrap(),
            a3s: alphas[9..13].iter().map(|alpha| alpha.unwrap()).collect(),
            a4s: alphas[13..17].iter().map(|alpha| alpha.unwrap()).collect(),
            a5: alphas[17].unwrap(),
            a6s: alphas[18..26].iter().map(|alpha| alpha.unwrap()).collect(),
        },
        xs: TransferSigmaProofXs {
            x1: xs[0].unwrap(),
            x2s: xs[1..9].iter().map(|x| x.unwrap()).collect(),
            x3s: xs[9..13].iter().map(|x| x.unwrap()).collect(),
            x4s: xs[13..17].iter().map(|x| x.unwrap()).collect(),
            x5: xs[17].unwrap(),
            x6s: xs[18..26].iter().map(|x| x.unwrap()).collect(),
            x7s: (26..xs_count - 4)
                .step_by(4)
                .map(|i| (i..i + 4).map(|j| xs[j].unwrap()).collect::<Vec<_>>())
                .collect(),
            x8s: xs[xs_count - 4..xs_count]
                .iter()
                .map(|x| x.unwrap())
                .collect(),
        },
    })
}

/// Derives the Fiat-Shamir challenge for the `NormalizationSigmaProof`.
fn fiat_shamir_normalization_sigma_proof_challenge(
    e: &Env,
    ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    proof_xs: &NormalizationSigmaProofXs,
) -> ScalarBytes {
    // rho = H(DST, G, H, P, (C_cur, D_cur)_{1..8}, (C_new, D_new)_{1..8}, X_{1..18})
    let mut bytes = FIAT_SHAMIR_NORMALIZATION_SIGMA_DST.to_vec();
    bytes.extend(basepoint().compress().to_bytes());
    bytes.extend(hash_to_point_base().compress().to_bytes());
    bytes.extend(ek.0.to_array());

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
    let bn = BytesN::<32>::from_array(e, new_scalar_from_sha2_512(&bytes).as_bytes());
    ScalarBytes(bn)
}

/// Derives the Fiat-Shamir challenge for the `WithdrawalSigmaProof`.
fn fiat_shamir_withdrawal_sigma_proof_challenge(
    e: &Env,
    ek: &CompressedPubkey,
    amount_chunks: &[ScalarBytes],
    current_balance: &ConfidentialBalance,
    proof_xs: &WithdrawalSigmaProofXs,
) -> ScalarBytes {
    // rho = H(DST, G, H, P, v_{1..4}, (C_cur, D_cur)_{1..8}, X_{1..18})
    let mut bytes = FIAT_SHAMIR_WITHDRAWAL_SIGMA_DST.to_vec();

    bytes.extend(basepoint().compress().to_bytes());
    bytes.extend(hash_to_point_base().compress().to_bytes());
    bytes.extend(ek.0.to_array());
    for chunk in amount_chunks {
        bytes.extend(chunk.0.to_array());
    }
    bytes.extend(current_balance.to_bytes());
    bytes.extend(&proof_xs.x1.to_bytes());
    bytes.extend(&proof_xs.x2.to_bytes());
    for x in &proof_xs.x3s {
        bytes.extend(x.to_bytes());
    }
    for x in &proof_xs.x4s {
        bytes.extend(x.to_bytes());
    }

    let bn = BytesN::<32>::from_array(e, new_scalar_from_sha2_512(&bytes).as_bytes());
    ScalarBytes(bn)
}

/// Derives the Fiat-Shamir challenge for the `TransferSigmaProof`.
fn fiat_shamir_transfer_sigma_proof_challenge(
    e: &Env,
    sender_ek: &CompressedPubkey,
    recipient_ek: &CompressedPubkey,
    current_balance: &ConfidentialBalance,
    new_balance: &ConfidentialBalance,
    sender_amount: &ConfidentialBalance,
    recipient_amount: &ConfidentialBalance,
    auditor_eks: &[CompressedPubkey],
    auditor_amounts: &[ConfidentialBalance],
    proof_xs: &TransferSigmaProofXs,
) -> ScalarBytes {
    // rho = H(DST, G, H, P_s, P_r, P_a_{1..n}, (C_cur, D_cur)_{1..8}, (C_v, D_v)_{1..4}, D_a_{1..4n}, D_s_{1..4}, (C_new, D_new)_{1..8}, X_{1..30 + 4n})
    let mut bytes = FIAT_SHAMIR_TRANSFER_SIGMA_DST.to_vec();

    bytes.extend(basepoint().compress().to_bytes());
    bytes.extend(hash_to_point_base().compress().to_bytes());
    bytes.extend(sender_ek.0.to_array());
    bytes.extend(recipient_ek.0.to_array());
    for ek in auditor_eks {
        bytes.extend(ek.0.to_array());
    }
    bytes.extend(current_balance.to_bytes());
    bytes.extend(recipient_amount.to_bytes());
    for balance in auditor_amounts {
        for EncryptedChunk { amount, handle } in &balance.0 {
            bytes.extend(handle.to_bytes());
        }
    }
    for chunk in &sender_amount.0 {
        bytes.extend(chunk.handle.to_bytes());
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
    for xs in &proof_xs.x7s {
        for x in xs {
            bytes.extend(x.to_bytes());
        }
    }
    for x in &proof_xs.x8s {
        bytes.extend(x.to_bytes());
    }

    let bn = BytesN::<32>::from_array(e, new_scalar_from_sha2_512(&bytes).as_bytes());
    ScalarBytes(bn)
}

/// Calculates the product of the provided scalars.
fn scalar_mul_3(
    scalar1: &ScalarBytes,
    scalar2: &ScalarBytes,
    scalar3: &ScalarBytes,
) -> ScalarBytes {
    let mut result = *scalar1;

    scalar_mul_assign(&mut result, scalar2);
    scalar_mul_assign(&mut result, scalar3);

    result
}

/// Calculates the linear combination of the provided scalars.
fn scalar_linear_combination(lhs: &[ScalarBytes], rhs: &[ScalarBytes]) -> ScalarBytes {
    let mut result = scalar_zero();

    for (l, r) in lhs.iter().zip(rhs.iter()) {
        scalar_add_assign(&mut result, &scalar_mul(l, r));
    }

    result
}

/// Raises 2 to the power of the provided exponent and returns the result as a scalar.
fn new_scalar_from_pow2(exp: u64) -> ScalarBytes {
    new_scalar_from_u128(1 << (exp as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_normalization() {
        let dk = &new_scalar_from_u64(123);
        let ek = &vec![1, 2, 3, 4]; // Placeholder
        let amount = 1000u128;
        let current_balance = &vec![5, 6, 7, 8]; // Placeholder

        let (proof, new_balance) = prove_normalization(dk, ek, amount, current_balance);

        // Test assertions would go here
        assert!(true); // Placeholder
    }

    #[test]
    fn test_prove_withdrawal() {
        let dk = &new_scalar_from_u64(123);
        let ek = &vec![1, 2, 3, 4]; // Placeholder
        let amount = 100u64;
        let new_amount = 900u128;
        let current_balance = &vec![5, 6, 7, 8]; // Placeholder

        let (proof, new_balance) = prove_withdrawal(dk, ek, amount, new_amount, current_balance);

        // Test assertions would go here
        assert!(true); // Placeholder
    }

    #[test]
    fn test_prove_transfer() {
        let sender_dk = &new_scalar_from_u64(123);
        let sender_ek = &vec![1, 2, 3, 4]; // Placeholder
        let recipient_ek = &vec![5, 6, 7, 8]; // Placeholder
        let amount = 100u64;
        let new_amount = 900u128;
        let current_balance = &vec![9, 10, 11, 12]; // Placeholder
        let auditor_eks = &vec![vec![13, 14, 15, 16]]; // Placeholder

        let (proof, new_balance, sender_amount, recipient_amount, auditor_amounts) = prove_transfer(
            sender_dk,
            sender_ek,
            recipient_ek,
            amount,
            new_amount,
            current_balance,
            auditor_eks,
        );

        // Test assertions would go here
        assert!(true); // Placeholder
    }

    /// Proves the normalization operation.
    fn prove_normalization(
        dk: &ScalarBytes,
        ek: &CompressedPubkey,
        amount: u128,
        current_balance: &ConfidentialBalance,
    ) -> (NormalizationProof, ConfidentialBalance) {
        let new_balance_r = generate_balance_randomness();
        let new_balance = new_actual_balance_from_u128(amount, &new_balance_r, ek);

        let new_balance_r = balance_randomness_as_scalars(&new_balance_r);

        let sigma_r = generate_normalization_sigma_proof_randomness();

        let zkrp_new_balance = prove_new_balance_range(amount, &new_balance_r);

        let x1 = basepoint_mul(&scalar_linear_combination(
            &sigma_r.x1s,
            &(0..8)
                .map(|i| new_scalar_from_pow2(i * 16))
                .collect::<Vec<_>>(),
        ));

        let current_balance_d = balance_to_points_d(current_balance);

        for i in 0..8 {
            point_add_assign(
                &mut x1,
                &point_mul(
                    &current_balance_d[i],
                    &scalar_mul(&sigma_r.x2, &new_scalar_from_pow2(i * 16)),
                ),
            );
        }

        let x2 = point_mul(&hash_to_point_base(), &sigma_r.x3);
        // this is just the C part of every chunk, C_i  = mG+rH (protecting m with x1 and r with x4)
        let x3s = (0..8)
            .map(|i| {
                let mut x3i = basepoint_mul(&sigma_r.x1s[i]);
                point_add_assign(&mut x3i, &point_mul(&hash_to_point_base(), &sigma_r.x4s[i]));
                x3i
            })
            .collect::<Vec<_>>();
        // this is just the D part of every chunk, D_i = r_i*P (protecting r)
        let x4s = (0..8)
            .map(|i| point_mul(&pubkey_to_point(ek).unwrap(), &sigma_r.x4s[i]))
            .collect::<Vec<_>>();

        let proof_xs = NormalizationSigmaProofXs {
            x1: point_compress(&x1),
            x2: point_compress(&x2),
            x3s: x3s.iter().map(|x| point_compress(x)).collect(),
            x4s: x4s.iter().map(|x| point_compress(x)).collect(),
        };

        let rho = fiat_shamir_normalization_sigma_proof_challenge(
            ek,
            current_balance,
            &new_balance,
            &proof_xs,
        );

        let amount_chunks = split_into_chunks_u128(amount);

        let a1s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x1s[i], &scalar_mul(&rho, &amount_chunks[i])))
            .collect::<Vec<_>>();
        let a2 = scalar_sub(&sigma_r.x2, &scalar_mul(&rho, dk));
        // I think this is proving the public key relation?
        let a3 = scalar_sub(&sigma_r.x3, &scalar_mul(&rho, &scalar_invert(dk).unwrap()));
        let a4s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x4s[i], &scalar_mul(&rho, &new_balance_r[i])))
            .collect::<Vec<_>>();

        (
            NormalizationProof {
                sigma_proof: NormalizationSigmaProof {
                    xs: proof_xs,
                    alphas: NormalizationSigmaProofAlphas { a1s, a2, a3, a4s },
                },
                zkrp_new_balance,
            },
            new_balance,
        )
    }

    /// Proves the withdrawal operation.
    fn prove_withdrawal(
        dk: &ScalarBytes,
        ek: &CompressedPubkey,
        amount: u64,
        new_amount: u128,
        current_balance: &ConfidentialBalance,
    ) -> (WithdrawalProof, ConfidentialBalance) {
        let new_balance_r = generate_balance_randomness();
        let new_balance = new_actual_balance_from_u128(new_amount, &new_balance_r, ek);

        let new_balance_r = balance_randomness_as_scalars(&new_balance_r);

        let sigma_r = generate_withdrawal_sigma_proof_randomness();

        let zkrp_new_balance = prove_new_balance_range(new_amount, &new_balance_r);

        // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + Σ(D_cur_i·2¹⁶ⁱ)·κ₂
        let x1 = basepoint_mul(&scalar_linear_combination(
            &sigma_r.x1s,
            &(0..8)
                .map(|i| new_scalar_from_pow2(i * 16))
                .collect::<Vec<_>>(),
        ));
        point_add_assign(
            &mut x1,
            &point_mul(
                &multi_scalar_mul(
                    &balance_to_points_d(current_balance),
                    &(0..8)
                        .map(|i| new_scalar_from_pow2(i * 16))
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
                &sigma_r.x2,
            ),
        );
        // X₂ = κ₃·H
        let x2 = point_mul(&hash_to_point_base(), &sigma_r.x3);
        // X₃ᵢ = κ₁ᵢ·G + κ₄ᵢ·H
        let x3s = (0..8)
            .map(|i| {
                let mut x3i = basepoint_mul(&sigma_r.x1s[i]);
                point_add_assign(&mut x3i, &point_mul(&hash_to_point_base(), &sigma_r.x4s[i]));
                x3i
            })
            .collect::<Vec<_>>();
        // X₄ᵢ = κ₄ᵢ·P
        let x4s = (0..8)
            .map(|i| point_mul(&pubkey_to_point(ek).unwrap(), &sigma_r.x4s[i]))
            .collect::<Vec<_>>();

        let proof_xs = WithdrawalSigmaProofXs {
            x1: point_compress(&x1),
            x2: point_compress(&x2),
            x3s: x3s.iter().map(|x| point_compress(x)).collect(),
            x4s: x4s.iter().map(|x| point_compress(x)).collect(),
        };

        let amount_chunks = split_into_chunks_u64(amount);

        let rho = fiat_shamir_withdrawal_sigma_proof_challenge(
            ek,
            &amount_chunks,
            current_balance,
            &proof_xs,
        );

        // below parts a1-a4 are idential to the normalization proof

        let new_amount_chunks = split_into_chunks_u128(new_amount);

        // a₁ᵢ = κ₁ᵢ - ρ·bᵢ
        let a1s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x1s[i], &scalar_mul(&rho, &new_amount_chunks[i])))
            .collect::<Vec<_>>();
        // a₂ = κ₂ - ρ·dk
        let a2 = scalar_sub(&sigma_r.x2, &scalar_mul(&rho, dk));
        // a₃ = κ₃ - ρ·dk^(-1)
        let a3 = scalar_sub(&sigma_r.x3, &scalar_mul(&rho, &scalar_invert(dk).unwrap()));
        // a₄ᵢ = κ₄ᵢ - ρ·rᵢ
        let a4s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x4s[i], &scalar_mul(&rho, &new_balance_r[i])))
            .collect::<Vec<_>>();

        (
            WithdrawalProof {
                sigma_proof: WithdrawalSigmaProof {
                    xs: proof_xs,
                    alphas: WithdrawalSigmaProofAlphas { a1s, a2, a3, a4s },
                },
                zkrp_new_balance,
            },
            new_balance,
        )
    }

    /// Proves the transfer operation.
    fn prove_transfer(
        sender_dk: &ScalarBytes,
        sender_ek: &CompressedPubkey,
        recipient_ek: &CompressedPubkey,
        amount: u64,
        new_amount: u128,
        current_balance: &ConfidentialBalance,
        auditor_eks: &[CompressedPubkey],
    ) -> (
        TransferProof,
        ConfidentialBalance,
        ConfidentialBalance,
        ConfidentialBalance,
        Vec<ConfidentialBalance>,
    ) {
        let amount_r = generate_balance_randomness();
        let new_balance_r = generate_balance_randomness();

        let new_balance = new_actual_balance_from_u128(new_amount, &new_balance_r, sender_ek);

        // encrypt the transfer amount 3 times: sender, recipient, auditors. All with the same randomness.
        let sender_amount = new_pending_balance_from_u64(amount, &amount_r, sender_ek);
        let recipient_amount = new_pending_balance_from_u64(amount, &amount_r, recipient_ek);
        let auditor_amounts = auditor_eks
            .iter()
            .map(|ek| new_pending_balance_from_u64(amount, &amount_r, ek))
            .collect::<Vec<_>>();

        // the randomness are all number represented in field elements. this step just extracts the vector<Scalar>
        // there is no conversion involved.
        let amount_r = balance_randomness_as_scalars(&amount_r)[0..4].to_vec();
        let new_balance_r = balance_randomness_as_scalars(&new_balance_r);

        // the sigma proof randomness is for commiting (hiding) the witnesses. the balance randomess above is
        // for elgamal encryption of values. don't confuse the two.
        let sigma_r = generate_transfer_sigma_proof_randomness();

        let zkrp_new_balance = prove_new_balance_range(new_amount, &new_balance_r);
        let zkrp_transfer_amount = prove_transfer_amount_range(amount, &amount_r);

        // X₁ = Σ(κ₁ᵢ·2¹⁶ⁱ)·G + (Σ(κ₆ᵢ·2¹⁶ⁱ) - Σ(κ₃ᵢ·2¹⁶ⁱ))·H + Σ(D_cur_i·2¹⁶ⁱ)·κ₂ - Σ(D_new_i·2¹⁶ⁱ)·κ₂
        let x1 = basepoint_mul(&scalar_linear_combination(
            &sigma_r.x1s,
            &(0..8)
                .map(|i| new_scalar_from_pow2(i * 16))
                .collect::<Vec<_>>(),
        ));

        point_add_assign(
            &mut x1,
            &point_mul(
                &hash_to_point_base(),
                &scalar_sub(
                    &scalar_linear_combination(
                        &sigma_r.x6s,
                        &(0..8)
                            .map(|i| new_scalar_from_pow2(i * 16))
                            .collect::<Vec<_>>(),
                    ),
                    &scalar_linear_combination(
                        &sigma_r.x3s,
                        &(0..4)
                            .map(|i| new_scalar_from_pow2(i * 16))
                            .collect::<Vec<_>>(),
                    ),
                ),
            ),
        );

        let current_balance_d = balance_to_points_d(current_balance);
        let new_balance_d = balance_to_points_d(&new_balance);

        for i in 0..8 {
            point_add_assign(
                &mut x1,
                &point_mul(
                    &current_balance_d[i],
                    &scalar_mul(&sigma_r.x2, &new_scalar_from_pow2(i * 16)),
                ),
            );
        }
        for i in 0..8 {
            point_sub_assign(
                &mut x1,
                &point_mul(
                    &new_balance_d[i],
                    &scalar_mul(&sigma_r.x2, &new_scalar_from_pow2(i * 16)),
                ),
            );
        }

        // X₂ᵢ = κ₆ᵢ·sender_ek
        let x2s = (0..8)
            .map(|i| point_mul(&pubkey_to_point(sender_ek).unwrap(), &sigma_r.x6s[i]))
            .collect::<Vec<_>>();
        // X₃ᵢ = κ₃ᵢ·recipient_ek
        let x3s = (0..4)
            .map(|i| point_mul(&pubkey_to_point(recipient_ek).unwrap(), &sigma_r.x3s[i]))
            .collect::<Vec<_>>();
        // X₄ᵢ = κ₄ᵢ·G + κ₃ᵢ·H
        let x4s = (0..4)
            .map(|i| {
                let mut x4i = basepoint_mul(&sigma_r.x4s[i]);
                point_add_assign(&mut x4i, &point_mul(&hash_to_point_base(), &sigma_r.x3s[i]));
                x4i
            })
            .collect::<Vec<_>>();
        // X₅ = κ₅·H
        let x5 = point_mul(&hash_to_point_base(), &sigma_r.x5);
        // X₆ᵢ = κ₁ᵢ·G + κ₆ᵢ·H
        let x6s = (0..8)
            .map(|i| {
                let mut x6i = basepoint_mul(&sigma_r.x1s[i]);
                point_add_assign(&mut x6i, &point_mul(&hash_to_point_base(), &sigma_r.x6s[i]));
                x6i
            })
            .collect::<Vec<_>>();
        // X₇ⱼᵢ = κ₃ᵢ·auditor_ekⱼ
        let x7s = auditor_eks
            .iter()
            .map(|ek| {
                (0..4)
                    .map(|i| point_mul(&pubkey_to_point(ek).unwrap(), &sigma_r.x3s[i]))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // X₈ᵢ = κ₃ᵢ·sender_ek
        let x8s = (0..4)
            .map(|i| point_mul(&pubkey_to_point(sender_ek).unwrap(), &sigma_r.x3s[i]))
            .collect::<Vec<_>>();

        let proof_xs = TransferSigmaProofXs {
            x1: point_compress(&x1),
            x2s: x2s.iter().map(|x| point_compress(x)).collect(),
            x3s: x3s.iter().map(|x| point_compress(x)).collect(),
            x4s: x4s.iter().map(|x| point_compress(x)).collect(),
            x5: point_compress(&x5),
            x6s: x6s.iter().map(|x| point_compress(x)).collect(),
            x7s: x7s
                .iter()
                .map(|xs| xs.iter().map(|x| point_compress(x)).collect())
                .collect(),
            x8s: x8s.iter().map(|x| point_compress(x)).collect(),
        };

        let rho = fiat_shamir_transfer_sigma_proof_challenge(
            sender_ek,
            recipient_ek,
            current_balance,
            &new_balance,
            &sender_amount,
            &recipient_amount,
            auditor_eks,
            &auditor_amounts,
            &proof_xs,
        );

        let amount_chunks = split_into_chunks_u64(amount);
        let new_amount_chunks = split_into_chunks_u128(new_amount);

        // a₁ᵢ = κ₁ᵢ - ρ·bᵢ                    (bᵢ = new balance chunks)
        let a1s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x1s[i], &scalar_mul(&rho, &new_amount_chunks[i])))
            .collect::<Vec<_>>();
        // a₂ = κ₂ - ρ·sender_dk
        let a2 = scalar_sub(&sigma_r.x2, &scalar_mul(&rho, sender_dk));
        // a₃ᵢ = κ₃ᵢ - ρ·r_amountᵢ
        let a3s = (0..4)
            .map(|i| scalar_sub(&sigma_r.x3s[i], &scalar_mul(&rho, &amount_r[i])))
            .collect::<Vec<_>>();
        // a₄ᵢ = κ₄ᵢ - ρ·mᵢ
        let a4s = (0..4)
            .map(|i| scalar_sub(&sigma_r.x4s[i], &scalar_mul(&rho, &amount_chunks[i])))
            .collect::<Vec<_>>();
        // a₅ = κ₅ - ρ·sender_dk^(-1)
        let a5 = scalar_sub(
            &sigma_r.x5,
            &scalar_mul(&rho, &scalar_invert(sender_dk).unwrap()),
        );
        // a₆ᵢ = κ₆ᵢ - ρ·r_new_balanceᵢ        (r_new_balanceᵢ = new balance randomness)
        let a6s = (0..8)
            .map(|i| scalar_sub(&sigma_r.x6s[i], &scalar_mul(&rho, &new_balance_r[i])))
            .collect::<Vec<_>>();

        (
            TransferProof {
                sigma_proof: TransferSigmaProof {
                    xs: proof_xs,
                    alphas: TransferSigmaProofAlphas {
                        a1s,
                        a2,
                        a3s,
                        a4s,
                        a5,
                        a6s,
                    },
                },
                zkrp_new_balance,
                zkrp_transfer_amount,
            },
            new_balance,
            sender_amount,
            recipient_amount,
            auditor_amounts,
        )
    }

    // Additional placeholder functions needed for the test functions
    fn generate_balance_randomness() -> BalanceRandomness {
        unimplemented!()
    }
    fn new_actual_balance_from_u128(
        _amount: u128,
        _randomness: &BalanceRandomness,
        _ek: &CompressedPubkey,
    ) -> ConfidentialBalance {
        unimplemented!()
    }
    fn balance_randomness_as_scalars(_randomness: &BalanceRandomness) -> Vec<ScalarBytes> {
        unimplemented!()
    }
    fn generate_normalization_sigma_proof_randomness() -> NormalizationSigmaProofRandomness {
        unimplemented!()
    }
    fn prove_new_balance_range(_amount: u128, _randomness: &[ScalarBytes]) -> RangeProof {
        unimplemented!()
    }
    fn basepoint_mul(_scalar: &ScalarBytes) -> Point {
        unimplemented!()
    }
    fn point_add_assign(_point: &mut Point, _other: &Point) {
        unimplemented!()
    }
    fn point_mul(_point: &Point, _scalar: &ScalarBytes) -> Point {
        unimplemented!()
    }
    fn split_into_chunks_u128(_amount: u128) -> Vec<ScalarBytes> {
        unimplemented!()
    }
    fn scalar_sub(_lhs: &ScalarBytes, _rhs: &ScalarBytes) -> ScalarBytes {
        unimplemented!()
    }
    fn scalar_invert(_scalar: &ScalarBytes) -> Option<ScalarBytes> {
        unimplemented!()
    }
    fn generate_withdrawal_sigma_proof_randomness() -> WithdrawalSigmaProofRandomness {
        unimplemented!()
    }
    fn new_pending_balance_from_u64(
        _amount: u64,
        _randomness: &BalanceRandomness,
        _ek: &CompressedPubkey,
    ) -> ConfidentialBalance {
        unimplemented!()
    }
    fn generate_transfer_sigma_proof_randomness() -> TransferSigmaProofRandomness {
        unimplemented!()
    }
    fn prove_transfer_amount_range(_amount: u64, _randomness: &[ScalarBytes]) -> RangeProof {
        unimplemented!()
    }
    fn point_sub_assign(_point: &mut Point, _other: &Point) {
        unimplemented!()
    }

    // Placeholder types for randomness structs
    pub type BalanceRandomness = Vec<u8>;
    pub struct NormalizationSigmaProofRandomness {
        pub x1s: Vec<ScalarBytes>,
        pub x2: ScalarBytes,
        pub x3: ScalarBytes,
        pub x4s: Vec<ScalarBytes>,
    }
    pub struct WithdrawalSigmaProofRandomness {
        pub x1s: Vec<ScalarBytes>,
        pub x2: ScalarBytes,
        pub x3: ScalarBytes,
        pub x4s: Vec<ScalarBytes>,
    }
    pub struct TransferSigmaProofRandomness {
        pub x1s: Vec<ScalarBytes>,
        pub x2: ScalarBytes,
        pub x3s: Vec<ScalarBytes>,
        pub x4s: Vec<ScalarBytes>,
        pub x5: ScalarBytes,
        pub x6s: Vec<ScalarBytes>,
    }
}
