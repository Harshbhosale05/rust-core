// =============================================================================
// A-SPARSH: Software-Defined Secure Element (SD-SE) Core Library
// =============================================================================
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │                     A-SPARSH SD-SE ENGINE                          │
// │       Agnostic Secure Payment Architecture for Resilient          │
// │                      Settlements                                   │
// │                                                                    │
// │  7-LAYER ZERO-TRUST ARCHITECTURE                                  │
// │  ┌─────────────────────────────────────────────────────────────┐  │
// │  │ Layer 1: Envelope Encryption (TEE AES-256 wrapping)        │  │
// │  │ Layer 2: White-Box Crypto + ORAM (key never in RAM)        │  │
// │  │ Layer 3: Monotonic Ratcheting (anti-rollback)              │  │
// │  │ Layer 4: Spatial Redundancy (anti-DFA double-compute)      │  │
// │  │ Layer 5: Split-Key / MPC (anti-ghost-minting)              │  │
// │  │ Layer 6: Dynamic Air-Gap (BLE nonces, anti-replay)         │  │
// │  │ Layer 7: One-Show Identity + Gossip (anti-fraud trap)      │  │
// │  └─────────────────────────────────────────────────────────────┘  │
// │                                                                    │
// │  Tech: Rust → Android NDK (JNI) → Kotlin App                     │
// │  Target: Android 6.0+, ARM/x86, budget ₹5000 phones              │
// └─────────────────────────────────────────────────────────────────────┘
//
// Module hierarchy:
//   lib.rs           - Public API & JNI entry points
//   ├── utxo.rs      - Smart Coin Selection (3 settlement methods)
//   ├── crypto.rs     - Ed25519, Merkle Tree, Nonces, Device Binding
//   ├── wbc.rs        - White-Box Cryptography engine (LUT + ORAM)
//   ├── mpc.rs        - Multi-Party Computation (Split-Key)
//   └── transaction.rs - Transaction orchestrator & Gossip sync

pub mod utxo;
pub mod crypto;
pub mod wbc;
pub mod mpc;
pub mod transaction;

// Re-export key types for convenience
pub use crypto::{SecureKeypair, CryptoError};
pub use mpc::{KeyShare, Party, MpcError};
pub use utxo::{TokenEntry, TokenStatus, UtxoSelection, SettlementMethod, UtxoError, PaymentSuggestion};
pub use wbc::{WbcMagazine, WbcError};
pub use transaction::{
    TransactionPayload, TransactionAck, OfflineState, TransactionError,
    GossipBatch, PendingChange, ChangeStatus, ChangeToken,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "A-SPARSH SD-SE Core";

// =============================================================================
// HIGH-LEVEL PUBLIC API
// =============================================================================
//
// These functions provide a clean interface for the Kotlin app (via JNI)
// or for direct Rust consumers.

/// Initialize the SD-SE engine
///
/// Called once when the app starts. Returns the engine configuration.
pub fn init_engine() -> EngineConfig {
    EngineConfig {
        version: VERSION.to_string(),
        max_offline_txns: transaction::OFFLINE_VELOCITY_LIMIT,
        max_offline_spend: transaction::OFFLINE_SPEND_LIMIT,
        magazine_size: wbc::MAGAZINE_SIZE as u32,
        oram_dummy_count: wbc::ORAM_DUMMY_COUNT as u32,
    }
}

/// Engine configuration (returned by init_engine)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineConfig {
    pub version: String,
    pub max_offline_txns: u32,
    pub max_offline_spend: u32,
    pub magazine_size: u32,
    pub oram_dummy_count: u32,
}

/// Quick self-test to verify the cryptographic engine is not tampered
///
/// Runs a sign/verify roundtrip. If this fails, the native library
/// was corrupted or the CPU is compromised.
pub fn self_test() -> bool {
    let keypair = SecureKeypair::generate();
    let test_payload = b"A-SPARSH-SELF-TEST-PAYLOAD";

    // Test basic sign/verify
    let sig = crypto::sign_payload(&keypair, test_payload);
    if !crypto::verify_signature(&keypair.public_key_bytes(), test_payload, &sig) {
        return false;
    }

    // Test spatial redundancy
    if crypto::sign_with_redundancy(&keypair, test_payload).is_err() {
        return false;
    }

    // Test UTXO selection
    let tokens = vec![
        TokenEntry {
            token_id: "test-1".into(),
            denomination: 10,
            rbi_signature: vec![0u8; 64],
            status: TokenStatus::Unspent,
        },
    ];
    if utxo::select_utxos(10, &tokens).is_err() {
        return false;
    }

    true
}

// ... (JNI Bridge omitted for brevity, will touch later if needed)

#[cfg(test)]
mod tests {
    use super::*;

    // ...

    #[test]
    fn test_end_to_end_offline_payment() {
        // ... (setup code)
        let rbi_keypair = SecureKeypair::generate(); // We use this now!

        // Payer's wallet:
        let wallet = vec![
            TokenEntry { token_id: "eR-500-001".into(), denomination: 500, rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-50-001".into(), denomination: 50,  rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-10-001".into(), denomination: 10,  rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-10-002".into(), denomination: 10,  rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-5-001".into(),  denomination: 5,   rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-2-001".into(),  denomination: 2,   rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-1-001".into(),  denomination: 1,   rbi_signature: vec![0u8; 64], status: TokenStatus::Unspent },
        ];

        // --- SETUP: Provision both parties ---
        let payer_keypair = SecureKeypair::generate();
        let merchant_keypair = SecureKeypair::generate();

        // Split the signing key
        let (share_a, share_b) = mpc::split_key(&payer_keypair.public_key_bytes());

        let mut offline_state = OfflineState::new();

        // --- STEP 1: Merchant generates session nonce ---
        let nonce = crypto::generate_session_nonce();

        // --- STEP 2: Payer prepares payment ---
        let (selection, mut payload) = transaction::prepare_payment(
            50, &wallet, &nonce, "payer_device_001", 100, &offline_state,
        ).unwrap();

        assert_eq!(selection.method, SettlementMethod::ExactMatch);
        assert_eq!(payload.total_amount, 50);

        // --- STEP 3: Payer signs with Spatial Redundancy ---
        transaction::sign_payment(&mut payload, &payer_keypair, &share_a).unwrap();
        assert!(!payload.payer_partial_sig.is_empty());

        // --- STEP 4: Merchant verifies ---
        let verified = transaction::verify_payment(
            &payload,
            &payer_keypair.public_key_bytes(),
            &nonce,
            &rbi_keypair.public_key_bytes(), // Pass RBI key
        ).unwrap();
        assert!(verified);

        // ...
    }
}
