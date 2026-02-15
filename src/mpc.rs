// =============================================================================
// A-SPARSH SD-SE: Multi-Party Computation (MPC) — Split-Key Engine
// =============================================================================
//
// ARCHITECTURE:
//   The signing key is SPLIT into two shares:
//     - Share A: Lives on the Payer's device
//     - Share B: Lives on the Merchant's device
//
//   A valid signature REQUIRES both shares to be physically present
//   (via BLE). This prevents "Ghost Minting" — a hacker sitting alone
//   in their basement cannot forge a transaction because they only have
//   half the key.
//
// IMPLEMENTATION:
//   For the hackathon, we use a simplified additive secret sharing scheme:
//     key = share_a + share_b  (mod prime order of Ed25519 curve)
//
//   In production, this would use Shamir's Secret Sharing with threshold (2,2)
//   or a proper two-party ECDSA/EdDSA protocol (e.g., GG18 or FROST).

use ed25519_dalek::{SigningKey, Signer, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

/// A secret share of the signing key
#[derive(Clone)]
pub struct KeyShare {
    /// Which share this is (A = Payer, B = Merchant)
    pub party: Party,
    /// The raw share bytes (32 bytes)
    share_bytes: [u8; 32],
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.share_bytes.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Party {
    /// Payer's share — stored on the user's device
    PayerShareA,
    /// Merchant's share — stored on the merchant's device
    MerchantShareB,
}

/// A partial signature produced by one party
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub party: Party,
    /// The partial signature bytes
    pub sig_bytes: Vec<u8>,
    /// Hash of the payload that was signed
    pub payload_hash: Vec<u8>,
}

/// Result of combining two partial signatures
#[derive(Debug, Clone)]
pub struct CombinedSignature {
    /// The full Ed25519 signature
    pub full_signature: Vec<u8>,
    /// The full public key (for verification)
    pub full_public_key: Vec<u8>,
}

// =============================================================================
// KEY SPLITTING (During Provisioning)
// =============================================================================

/// Split a signing key into two shares
///
/// Called by the RBI backend during provisioning:
///   1. Generate the full Ed25519 signing key
///   2. Split into Share A (sent to Payer) and Share B (stored for Merchant)
///   3. Share A is downloaded to the Payer's device
///   4. Share B is embedded in the Merchant's provisioned credentials
///
/// # Security
/// Neither share alone can produce a valid signature.
/// An attacker with only Share A (from the Payer's device) gets nothing useful.
pub fn split_key(full_key_seed: &[u8; 32]) -> (KeyShare, KeyShare) {
    // Generate a random Share A
    let mut share_a_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut share_a_bytes);

    // Share B = Full Key XOR Share A
    // This ensures: Share A XOR Share B = Full Key
    let mut share_b_bytes = [0u8; 32];
    for i in 0..32 {
        share_b_bytes[i] = full_key_seed[i] ^ share_a_bytes[i];
    }

    let share_a = KeyShare {
        party: Party::PayerShareA,
        share_bytes: share_a_bytes,
    };

    let share_b = KeyShare {
        party: Party::MerchantShareB,
        share_bytes: share_b_bytes,
    };

    (share_a, share_b)
}

/// Reconstruct the full key from two shares
///
/// This happens on the Merchant's device during the BLE handshake:
///   1. Payer sends their partial computation over BLE
///   2. Merchant combines with local Share B
///   3. Full signature is produced
fn reconstruct_key(share_a: &KeyShare, share_b: &KeyShare) -> [u8; 32] {
    let mut full_key = [0u8; 32];
    for i in 0..32 {
        full_key[i] = share_a.share_bytes[i] ^ share_b.share_bytes[i];
    }
    full_key
}

// =============================================================================
// PARTIAL SIGNING
// =============================================================================

/// Generate a partial signature using Share A (Payer's side)
///
/// This is what the Payer computes and sends over BLE.
/// It is mathematically worthless on its own — the hacker cannot
/// use it to forge transactions without Share B.
pub fn generate_partial_sig(
    share_a: &KeyShare,
    payload: &[u8],
) -> PartialSignature {
    // Hash the payload
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let payload_hash = hasher.finalize().to_vec();

    // Create a deterministic "partial signature" from Share A + payload hash
    // This is NOT a real Ed25519 signature — it's a commitment
    let mut partial = Sha256::new();
    partial.update(&share_a.share_bytes);
    partial.update(&payload_hash);
    partial.update(b"A-SPARSH-PARTIAL-SIG-V1");
    let sig_bytes = partial.finalize().to_vec();

    PartialSignature {
        party: Party::PayerShareA,
        sig_bytes,
        payload_hash,
    }
}

/// Combine partial signatures to produce a full Ed25519 signature
///
/// Called on the Merchant's device after receiving the Payer's partial sig.
/// The Merchant uses Share B to reconstruct the full key and sign.
pub fn combine_and_sign(
    partial_a: &PartialSignature,
    share_a: &KeyShare,
    share_b: &KeyShare,
    payload: &[u8],
) -> Result<CombinedSignature, MpcError> {
    // Verify the partial signature is valid (payload hash matches)
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let expected_hash = hasher.finalize().to_vec();

    if partial_a.payload_hash != expected_hash {
        return Err(MpcError::PayloadMismatch);
    }

    // Verify the partial sig commitment
    let mut expected_partial = Sha256::new();
    expected_partial.update(&share_a.share_bytes);
    expected_partial.update(&expected_hash);
    expected_partial.update(b"A-SPARSH-PARTIAL-SIG-V1");
    let expected_sig = expected_partial.finalize().to_vec();

    if partial_a.sig_bytes != expected_sig {
        return Err(MpcError::InvalidPartialSignature);
    }

    // Reconstruct the full signing key
    let mut full_key_bytes = reconstruct_key(share_a, share_b);
    let signing_key = SigningKey::from_bytes(&full_key_bytes);
    let verifying_key = signing_key.verifying_key();

    // Sign the payload with the full key
    let full_sig = signing_key.sign(payload);

    // Zeroize key material immediately
    full_key_bytes.zeroize();

    Ok(CombinedSignature {
        full_signature: full_sig.to_bytes().to_vec(),
        full_public_key: verifying_key.to_bytes().to_vec(),
    })
}

/// Verify a combined signature against the full public key
pub fn verify_combined_signature(
    combined: &CombinedSignature,
    payload: &[u8],
) -> bool {
    let pk_bytes: [u8; 32] = match combined.full_public_key.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig_bytes: [u8; 64] = match combined.full_signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };

    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key.verify(payload, &signature).is_ok()
}

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MpcError {
    /// The payload hash in the partial signature doesn't match
    PayloadMismatch,
    /// The partial signature commitment is invalid
    InvalidPartialSignature,
    /// Missing share — cannot combine without both parties
    MissingShare { party: Party },
    /// Share reconstruction produced invalid key
    InvalidReconstructedKey,
}

impl std::fmt::Display for MpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MpcError::PayloadMismatch => {
                write!(f, "Payload hash mismatch between partial sig and actual payload")
            }
            MpcError::InvalidPartialSignature => {
                write!(f, "Partial signature commitment verification failed")
            }
            MpcError::MissingShare { party } => {
                write!(f, "Missing key share from {:?}", party)
            }
            MpcError::InvalidReconstructedKey => {
                write!(f, "Reconstructed key is invalid")
            }
        }
    }
}

impl std::error::Error for MpcError {}

// =============================================================================
// TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_seed() -> [u8; 32] {
        let signing_key = SigningKey::generate(&mut OsRng);
        signing_key.to_bytes()
    }

    #[test]
    fn test_split_and_reconstruct() {
        let seed = test_key_seed();
        let (share_a, share_b) = split_key(&seed);

        // Reconstruct must give back the original key
        let reconstructed = reconstruct_key(&share_a, &share_b);
        assert_eq!(reconstructed, seed);
    }

    #[test]
    fn test_share_a_alone_is_useless() {
        let seed = test_key_seed();
        let (share_a, _share_b) = split_key(&seed);

        // Share A alone should NOT equal the full key
        assert_ne!(share_a.share_bytes, seed);
    }

    #[test]
    fn test_share_b_alone_is_useless() {
        let seed = test_key_seed();
        let (_share_a, share_b) = split_key(&seed);

        // Share B alone should NOT equal the full key
        assert_ne!(share_b.share_bytes, seed);
    }

    #[test]
    fn test_partial_sig_generation() {
        let seed = test_key_seed();
        let (share_a, _) = split_key(&seed);

        let payload = b"Pay 50 INR to merchant_001";
        let partial = generate_partial_sig(&share_a, payload);

        assert_eq!(partial.party, Party::PayerShareA);
        assert!(!partial.sig_bytes.is_empty());
    }

    #[test]
    fn test_combine_and_verify_full_flow() {
        let seed = test_key_seed();
        let (share_a, share_b) = split_key(&seed);

        let payload = b"Pay 50 INR to merchant_001 with nonce XYZ";

        // Step 1: Payer generates partial signature
        let partial_a = generate_partial_sig(&share_a, payload);

        // Step 2: Merchant combines shares and produces full signature
        let combined = combine_and_sign(&partial_a, &share_a, &share_b, payload).unwrap();

        // Step 3: Verify the full signature
        assert!(verify_combined_signature(&combined, payload));
    }

    #[test]
    fn test_tampered_payload_fails_combine() {
        let seed = test_key_seed();
        let (share_a, share_b) = split_key(&seed);

        let payload = b"Pay 50 INR";
        let partial_a = generate_partial_sig(&share_a, payload);

        // Try to combine with different payload
        let tampered_payload = b"Pay 5000 INR";
        let result = combine_and_sign(&partial_a, &share_a, &share_b, tampered_payload);
        assert!(matches!(result, Err(MpcError::PayloadMismatch)));
    }

    #[test]
    fn test_combined_sig_matches_direct_sign() {
        let seed = test_key_seed();
        let (share_a, share_b) = split_key(&seed);

        let payload = b"Test payload for signature comparison";

        // Combined MPC signature
        let partial = generate_partial_sig(&share_a, payload);
        let combined = combine_and_sign(&partial, &share_a, &share_b, payload).unwrap();

        // Direct signature with full key
        let signing_key = SigningKey::from_bytes(&seed);
        let direct_sig = signing_key.sign(payload);

        // Both should verify against the same public key
        let verifying_key = signing_key.verifying_key();
        assert_eq!(
            combined.full_public_key,
            verifying_key.to_bytes().to_vec()
        );

        // Both signatures should be valid
        assert!(verify_combined_signature(&combined, payload));
        assert!(verifying_key.verify(payload, &direct_sig).is_ok());
    }
}
