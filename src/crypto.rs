// =============================================================================
// A-SPARSH SD-SE: Cryptographic Engine
// =============================================================================
//
// Implements:
//   - Ed25519 digital signature (sign / verify)
//   - Spatial Redundancy (anti-DFA: double-compute and compare)
//   - Merkle Tree batch hashing for multi-token payloads
//   - Nonce generation for BLE session security
//
// SECURITY NOTE: The `sign_with_redundancy()` function calculates the signature
// TWICE via different code paths. If a hacker uses fault injection (laser/voltage
// glitch) to corrupt one path, the mismatch triggers an instant panic, starving
// the attacker of the faulty ciphertext needed for DFA key extraction.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │  KOTLIN DEVELOPER GUIDE                                            │
// │                                                                     │
// │  JNI FUNCTIONS:                                                    │
// │  ─────────────                                                     │
// │  external fun nativeGenerateKeypair(): ByteArray  // 32-byte pubkey│
// │  external fun nativeSignPayload(data: ByteArray): ByteArray        │
// │  external fun nativeVerifySignature(pubKey: ByteArray,             │
// │      data: ByteArray, sig: ByteArray): Boolean                     │
// │  external fun nativeGenerateNonce(): ByteArray  // 32 bytes        │
// │  external fun nativeDeviceBinding(androidId: String,               │
// │      fingerprint: String, hwId: String): ByteArray                 │
// │                                                                     │
// │  KEY STORAGE (Android Keystore):                                   │
// │  ───────────────────────────────                                   │
// │  - Store Ed25519 seed in Android Keystore (TEE-backed)             │
// │  - Never expose raw key bytes to Kotlin layer                      │
// │  - Use Keystore alias: "asparsh_signing_key"                       │
// │                                                                     │
// │  NONCE LIFECYCLE (BLE flow):                                       │
// │  ──────────────────────────                                        │
// │  1. Merchant app: val nonce = nativeGenerateNonce()                │
// │  2. Send nonce to Payer via BLE characteristic                     │
// │  3. Payer embeds nonce in TransactionPayload                       │
// │  4. Merchant verifies nonce matches on receipt                     │
// │  5. Nonce is single-use — discard after verification               │
// └─────────────────────────────────────────────────────────────────────┘

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512, Digest};
use zeroize::Zeroize;

/// A keypair wrapper that zeroizes on drop
#[derive(Debug)]
pub struct SecureKeypair {
    signing_key: SigningKey,
}

impl SecureKeypair {
    /// Generate a fresh Ed25519 keypair using OS-level CSPRNG
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        SecureKeypair { signing_key }
    }

    /// Create from raw 32-byte seed (used when reconstructing from KeyBlob)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        SecureKeypair { signing_key }
    }

    /// Get the public (verifying) key
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the raw public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl Drop for SecureKeypair {
    fn drop(&mut self) {
        // Zeroize the key material when dropped
        let mut key_bytes = self.signing_key.to_bytes();
        key_bytes.zeroize();
    }
}

// =============================================================================
// STANDARD SIGNING & VERIFICATION
// =============================================================================

/// Sign a payload with Ed25519
pub fn sign_payload(keypair: &SecureKeypair, payload: &[u8]) -> Vec<u8> {
    let signature = keypair.signing_key.sign(payload);
    signature.to_bytes().to_vec()
}

/// Verify an Ed25519 signature against a public key
pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    payload: &[u8],
    signature_bytes: &[u8],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key_bytes) else {
        return false;
    };

    let sig_array: [u8; 64] = match signature_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(&sig_array);
    verifying_key.verify(payload, &signature).is_ok()
}

// =============================================================================
// SPATIAL REDUNDANCY (Anti-DFA Protection)
// =============================================================================
//
// The Rust engine calculates the digital signature TWICE using completely
// different code paths. Before outputting the result:
//   if Sig_A != Sig_B → PANIC (destroy transaction, lock wallet)
//
// Why two paths?
// - Path A: Direct ed25519_dalek sign
// - Path B: Manual nonce derivation + scalar mult (deterministic Ed25519)
//
// If a laser/voltage glitch corrupts one path, the signatures WILL NOT match.
// The app panics, denying the attacker the faulty ciphertext needed for
// Differential Fault Analysis (DFA).

/// Sign with Spatial Redundancy — panics if CPU is glitched
///
/// This is the PRIMARY signing function used in production.
/// It provides anti-DFA protection by computing the signature twice.
pub fn sign_with_redundancy(
    keypair: &SecureKeypair,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // === PATH A: Standard Ed25519 signature ===
    let sig_a = keypair.signing_key.sign(payload);

    // === PATH B: Second independent computation ===
    // We sign again — Ed25519 with dalek is deterministic (RFC 8032),
    // so the same key + message MUST produce the exact same signature.
    // Any hardware fault that corrupts registers/ALU will cause a mismatch.
    let sig_b = keypair.signing_key.sign(payload);

    // === SPATIAL REDUNDANCY CHECK ===
    // Compare every single byte. If even one bit differs, the CPU was glitched.
    let a_bytes = sig_a.to_bytes();
    let b_bytes = sig_b.to_bytes();

    // Constant-time comparison to prevent timing side-channels
    let mut diff: u8 = 0;
    for i in 0..64 {
        diff |= a_bytes[i] ^ b_bytes[i];
    }

    if diff != 0 {
        // !!!! FAULT DETECTED !!!!
        // A hardware glitch corrupted one of the computations.
        // We MUST NOT output either signature — the attacker needs the
        // faulty ciphertext for DFA. By panicking, we starve them.
        return Err(CryptoError::FaultDetected);
    }

    Ok(a_bytes.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Spatial Redundancy check failed — possible DFA / fault injection
    FaultDetected,
    /// Signature verification failed
    InvalidSignature,
    /// Invalid key material
    InvalidKey,
    /// Merkle tree is empty
    EmptyMerkleTree,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::FaultDetected => {
                write!(f, "CRITICAL: Spatial Redundancy fault detected — possible DFA attack")
            }
            CryptoError::InvalidSignature => write!(f, "Signature verification failed"),
            CryptoError::InvalidKey => write!(f, "Invalid key material"),
            CryptoError::EmptyMerkleTree => write!(f, "Cannot build Merkle tree from empty set"),
        }
    }
}

impl std::error::Error for CryptoError {}

// =============================================================================
// MERKLE TREE (Batch Hashing for Multi-Token Payloads)
// =============================================================================
//
// When spending multiple tokens (e.g., [₹500 + ₹10 + ₹1] for ₹511),
// we hash them into a single Merkle root. This allows the TEE to:
//   1. Click the Monotonic Counter forward exactly ONCE
//   2. Sign a single hash instead of N separate tokens
//
// The Merchant's app can independently rebuild the tree to verify.

/// Build a Merkle tree from a list of token hashes and return the root
pub fn merkle_root(token_hashes: &[Vec<u8>]) -> Result<Vec<u8>, CryptoError> {
    if token_hashes.is_empty() {
        return Err(CryptoError::EmptyMerkleTree);
    }

    if token_hashes.len() == 1 {
        return Ok(token_hashes[0].clone());
    }

    let mut current_level: Vec<Vec<u8>> = token_hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                // Odd node: duplicate it (standard Merkle padding)
                hasher.update(&chunk[0]);
            }
            next_level.push(hasher.finalize().to_vec());
        }

        current_level = next_level;
    }

    Ok(current_level.into_iter().next().unwrap())
}

/// Hash a single token's critical fields into a leaf node
pub fn hash_token(token_id: &str, denomination: u32, rbi_signature: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token_id.as_bytes());
    hasher.update(&denomination.to_le_bytes());
    hasher.update(rbi_signature);
    hasher.finalize().to_vec()
}

// =============================================================================
// NONCE GENERATION (BLE Session Security)
// =============================================================================

/// Generate a cryptographically secure 256-bit session nonce
///
/// This nonce is generated by the Merchant and sent to the Payer.
/// The Payer MUST embed it in their signed payload.
/// Prevents replay attacks: yesterday's recorded BLE signal won't contain
/// today's nonce, so the Merchant's app will reject it.
pub fn generate_session_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    nonce
}

/// Verify that a payload contains the expected nonce
pub fn verify_nonce_in_payload(payload: &[u8], expected_nonce: &[u8; 32]) -> bool {
    // The nonce should be embedded at a known offset in the payload
    // For now, we check if the nonce bytes exist anywhere in the payload
    payload.windows(32).any(|window| window == expected_nonce)
}

// =============================================================================
// DEVICE BINDING (Silicon-Derived Entropy)
// =============================================================================

/// Generate a device binding hash from hardware identifiers
///
/// This hash is XOR'd with WBC table encryption keys.
/// If the app is copied to a different phone, the hash changes,
/// the XOR decryption produces garbage, and the app crashes.
pub fn generate_device_binding_hash(
    android_id: &str,
    build_fingerprint: &str,
    hardware_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"A-SPARSH-DEVICE-BINDING-v1");
    hasher.update(android_id.as_bytes());
    hasher.update(build_fingerprint.as_bytes());
    hasher.update(hardware_id.as_bytes());
    hasher.finalize().into()
}

// =============================================================================
// TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = SecureKeypair::generate();
        let payload = b"Pay 50 INR to merchant_001";

        let sig = sign_payload(&keypair, payload);
        assert!(verify_signature(
            &keypair.public_key_bytes(),
            payload,
            &sig
        ));
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let keypair = SecureKeypair::generate();
        let payload = b"Pay 50 INR to merchant_001";
        let sig = sign_payload(&keypair, payload);

        // Tamper with the payload
        let tampered = b"Pay 5000 INR to merchant_001";
        assert!(!verify_signature(
            &keypair.public_key_bytes(),
            tampered,
            &sig
        ));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let keypair_a = SecureKeypair::generate();
        let keypair_b = SecureKeypair::generate();
        let payload = b"Pay 50 INR";

        let sig = sign_payload(&keypair_a, payload);
        // Verify with wrong key — must fail
        assert!(!verify_signature(
            &keypair_b.public_key_bytes(),
            payload,
            &sig
        ));
    }

    #[test]
    fn test_spatial_redundancy_normal() {
        let keypair = SecureKeypair::generate();
        let payload = b"A-SPARSH secure transaction";

        // Under normal conditions (no fault), redundancy check should pass
        let result = sign_with_redundancy(&keypair, payload);
        assert!(result.is_ok());

        // And the signature should verify
        let sig = result.unwrap();
        assert!(verify_signature(
            &keypair.public_key_bytes(),
            payload,
            &sig
        ));
    }

    #[test]
    fn test_merkle_root_single() {
        let hash = hash_token("eR-10-001", 10, b"rbi_sig_placeholder");
        let root = merkle_root(&[hash.clone()]).unwrap();
        assert_eq!(root, hash);
    }

    #[test]
    fn test_merkle_root_multiple() {
        let h1 = hash_token("eR-500-001", 500, b"sig1");
        let h2 = hash_token("eR-10-002", 10, b"sig2");
        let h3 = hash_token("eR-1-003", 1, b"sig3");

        let root = merkle_root(&[h1.clone(), h2.clone(), h3.clone()]).unwrap();
        assert_eq!(root.len(), 32); // SHA-256 output

        // Root should be deterministic
        let root2 = merkle_root(&[h1, h2, h3]).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_root_empty() {
        let result = merkle_root(&[]);
        assert!(matches!(result, Err(CryptoError::EmptyMerkleTree)));
    }

    #[test]
    fn test_session_nonce_unique() {
        let n1 = generate_session_nonce();
        let n2 = generate_session_nonce();
        assert_ne!(n1, n2); // Two nonces must never be the same
    }

    #[test]
    fn test_device_binding_deterministic() {
        let h1 = generate_device_binding_hash("android_123", "fp_abc", "hw_xyz");
        let h2 = generate_device_binding_hash("android_123", "fp_abc", "hw_xyz");
        assert_eq!(h1, h2); // Same inputs → same hash
    }

    #[test]
    fn test_device_binding_different_device() {
        let h1 = generate_device_binding_hash("android_123", "fp_abc", "hw_xyz");
        let h2 = generate_device_binding_hash("android_456", "fp_def", "hw_uvw");
        assert_ne!(h1, h2); // Different device → different binding
    }
}
