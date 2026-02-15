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
pub use utxo::{TokenEntry, TokenStatus, UtxoSelection, SettlementMethod, UtxoError};
pub use wbc::{WbcMagazine, WbcError};
pub use transaction::{
    TransactionPayload, TransactionAck, OfflineState, TransactionError,
    GossipBatch,
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
            status: TokenStatus::Unspent,
        },
    ];
    if utxo::select_utxos(10, &tokens).is_err() {
        return false;
    }

    true
}

// =============================================================================
// JNI BRIDGE (Android NDK Interface)
// =============================================================================
//
// These functions are exported as C symbols for the Android Kotlin app
// to call via JNI. They accept/return JSON strings for simplicity.
//
// In production, we would use Protocol Buffers for serialization,
// but JSON is clearer for debugging and development.

#[cfg(target_os = "android")]
mod android_jni {
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::jstring;
    use serde_json;

    use crate::*;

    /// JNI: Initialize the engine and return config as JSON
    #[no_mangle]
    pub extern "system" fn Java_com_asparsh_bridge_RustCore_initEngine(
        mut env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let config = init_engine();
        let json = serde_json::to_string(&config).unwrap_or_default();
        env.new_string(json).unwrap().into_raw()
    }

    /// JNI: Run self-test
    #[no_mangle]
    pub extern "system" fn Java_com_asparsh_bridge_RustCore_selfTest(
        _env: JNIEnv,
        _class: JClass,
    ) -> bool {
        self_test()
    }

    /// JNI: Select optimal UTXOs for a payment amount
    ///
    /// Input: JSON {"amount": 511, "tokens": [...]}
    /// Output: JSON UtxoSelection
    #[no_mangle]
    pub extern "system" fn Java_com_asparsh_bridge_RustCore_selectUtxos(
        mut env: JNIEnv,
        _class: JClass,
        input_json: JString,
    ) -> jstring {
        let input: String = env.get_string(&input_json).unwrap().into();

        #[derive(serde::Deserialize)]
        struct SelectInput {
            amount: u32,
            tokens: Vec<TokenEntry>,
        }

        let result = match serde_json::from_str::<SelectInput>(&input) {
            Ok(req) => match utxo::select_utxos(req.amount, &req.tokens) {
                Ok(selection) => serde_json::to_string(&selection).unwrap_or_default(),
                Err(e) => format!("{{\"error\": \"{}\"}}", e),
            },
            Err(e) => format!("{{\"error\": \"Invalid input: {}\"}}", e),
        };

        env.new_string(result).unwrap().into_raw()
    }

    /// JNI: Generate a session nonce (for Merchant mode)
    #[no_mangle]
    pub extern "system" fn Java_com_asparsh_bridge_RustCore_generateNonce(
        mut env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let nonce = crypto::generate_session_nonce();
        let hex = hex::encode(nonce);
        env.new_string(hex).unwrap().into_raw()
    }

    /// JNI: Generate device binding hash
    #[no_mangle]
    pub extern "system" fn Java_com_asparsh_bridge_RustCore_generateDeviceHash(
        mut env: JNIEnv,
        _class: JClass,
        android_id: JString,
        build_fingerprint: JString,
        hardware_id: JString,
    ) -> jstring {
        let aid: String = env.get_string(&android_id).unwrap().into();
        let bfp: String = env.get_string(&build_fingerprint).unwrap().into();
        let hwid: String = env.get_string(&hardware_id).unwrap().into();

        let hash = crypto::generate_device_binding_hash(&aid, &bfp, &hwid);
        let hex = hex::encode(hash);
        env.new_string(hex).unwrap().into_raw()
    }
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_init() {
        let config = init_engine();
        assert_eq!(config.max_offline_txns, 5);
        assert_eq!(config.max_offline_spend, 2000);
        assert_eq!(config.magazine_size, 50);
    }

    #[test]
    fn test_self_test_passes() {
        assert!(self_test());
    }

    #[test]
    fn test_end_to_end_offline_payment() {
        // =====================================================
        // FULL END-TO-END TEST: User pays ₹50 to Merchant
        // Simulates the complete 7-step protocol
        // =====================================================

        // --- SETUP: Provision both parties ---
        let rbi_keypair = SecureKeypair::generate();
        let payer_keypair = SecureKeypair::generate();
        let merchant_keypair = SecureKeypair::generate();

        // Split the signing key
        let (share_a, share_b) = mpc::split_key(&payer_keypair.public_key_bytes());

        // Payer's wallet: 1x₹500, 1x₹50, 2x₹10, 1x₹5, 1x₹2, 1x₹1
        let wallet = vec![
            TokenEntry { token_id: "eR-500-001".into(), denomination: 500, status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-50-001".into(), denomination: 50,  status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-10-001".into(), denomination: 10,  status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-10-002".into(), denomination: 10,  status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-5-001".into(),  denomination: 5,   status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-2-001".into(),  denomination: 2,   status: TokenStatus::Unspent },
            TokenEntry { token_id: "eR-1-001".into(),  denomination: 1,   status: TokenStatus::Unspent },
        ];

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
        ).unwrap();
        assert!(verified);

        // --- STEP 5: Merchant generates ACK ---
        let ack = transaction::generate_ack(
            &payload, "merchant_device_001", &merchant_keypair, vec![],
        ).unwrap();
        assert!(ack.accepted);

        // --- STEP 6: Record transaction ---
        offline_state.record_transaction(payload);
        offline_state.record_ack(ack);

        assert_eq!(offline_state.offline_tx_count, 1);
        assert_eq!(offline_state.offline_spend_total, 50);

        // --- STEP 7: Build Gossip batch ---
        let batch = transaction::build_gossip_batch(
            &offline_state, "payer_device_001", 101, &payer_keypair,
        ).unwrap();

        assert_eq!(batch.transactions.len(), 1);
        assert!(!batch.batch_signature.is_empty());

        // SUCCESS: Complete offline payment lifecycle!
    }
}
