// =============================================================================
// A-SPARSH SD-SE: Transaction Engine
// =============================================================================
//
// The orchestrator that ties together:
//   - UTXO selection (picking the right digital notes)
//   - WBC engine (signing through White-Box tables)
//   - MPC (Split-Key partial signatures)
//   - Crypto (Merkle tree, nonces, spatial redundancy)
//
// This module handles the complete offline transaction lifecycle:
//   1. Prepare a payment (select tokens, build payload)
//   2. Sign the payment (WBC + Spatial Redundancy)
//   3. Verify incoming payments
//   4. Handle Bidirectional Swap (offline change)
//   5. Generate Gossip sync logs

use crate::crypto::{
    self, CryptoError, SecureKeypair, generate_session_nonce,
    hash_token, merkle_root, sign_with_redundancy, verify_signature,
};
use crate::mpc::{self, KeyShare, PartialSignature, CombinedSignature, Party};
use crate::utxo::{self, TokenEntry, TokenStatus, UtxoSelection, SettlementMethod, UtxoError};

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Maximum number of offline transactions before requiring online refresh
pub const OFFLINE_VELOCITY_LIMIT: u32 = 5;

/// Maximum offline spend before requiring online sync (₹2,000)
pub const OFFLINE_SPEND_LIMIT: u32 = 2000;

// =============================================================================
// TRANSACTION PAYLOAD
// =============================================================================

/// A complete transaction ready for BLE transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPayload {
    /// Unique transaction ID
    pub tx_id: String,
    /// Tokens being transferred
    pub token_ids: Vec<String>,
    /// Total amount being paid
    pub total_amount: u32,
    /// Denominations breakdown
    pub denominations: Vec<u32>,
    /// Merkle root of all token hashes
    pub merkle_root: Vec<u8>,
    /// Session nonce from Merchant (anti-replay)
    pub session_nonce: Vec<u8>,
    /// Payer's partial signature (Share A)
    pub payer_partial_sig: Vec<u8>,
    /// Payer's device fingerprint hash
    pub payer_device_id: String,
    /// TEE monotonic counter state at time of signing
    pub counter_state: u64,
    /// Timestamp of transaction creation
    pub timestamp: u64,
    /// Chain history (for audit trail)
    pub chain_history: Vec<ChainEntry>,
    /// Overpayment amount (for Bidirectional Swap)
    pub overpayment: u32,
}

/// A single entry in the chain-of-ownership history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub from_device_id: String,
    pub to_device_id: String,
    pub amount: u32,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// Transaction acknowledgement from Merchant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAck {
    pub tx_id: String,
    pub merchant_device_id: String,
    pub combined_signature: Vec<u8>,
    pub timestamp: u64,
    /// Change tokens (Bidirectional Swap)
    pub change_tokens: Vec<ChangeToken>,
    pub accepted: bool,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeToken {
    pub token_id: String,
    pub denomination: u32,
    pub signature: Vec<u8>,
}

// =============================================================================
// OFFLINE WALLET STATE
// =============================================================================

/// Tracks the offline spending state for velocity limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineState {
    /// Number of offline transactions since last sync
    pub offline_tx_count: u32,
    /// Total amount spent offline since last sync
    pub offline_spend_total: u32,
    /// Last online sync timestamp
    pub last_sync_timestamp: u64,
    /// Queue of pending transactions awaiting gossip upload
    pub pending_sync: Vec<TransactionPayload>,
    /// Queue of received acks awaiting gossip upload
    pub received_acks: Vec<TransactionAck>,
}

impl OfflineState {
    pub fn new() -> Self {
        OfflineState {
            offline_tx_count: 0,
            offline_spend_total: 0,
            last_sync_timestamp: 0,
            pending_sync: Vec::new(),
            received_acks: Vec::new(),
        }
    }

    /// Check if velocity limits allow another transaction
    pub fn can_transact(&self, amount: u32) -> Result<(), TransactionError> {
        if self.offline_tx_count >= OFFLINE_VELOCITY_LIMIT {
            return Err(TransactionError::VelocityLimitExceeded {
                max_txns: OFFLINE_VELOCITY_LIMIT,
                current: self.offline_tx_count,
            });
        }

        if self.offline_spend_total + amount > OFFLINE_SPEND_LIMIT {
            return Err(TransactionError::SpendLimitExceeded {
                max_amount: OFFLINE_SPEND_LIMIT,
                current: self.offline_spend_total,
                requested: amount,
            });
        }

        Ok(())
    }

    /// Record a completed transaction
    pub fn record_transaction(&mut self, payload: TransactionPayload) {
        self.offline_tx_count += 1;
        self.offline_spend_total += payload.total_amount;
        self.pending_sync.push(payload);
    }

    /// Record a received acknowledgement
    pub fn record_ack(&mut self, ack: TransactionAck) {
        self.received_acks.push(ack);
    }

    /// Reset state after successful online sync
    pub fn reset_after_sync(&mut self) {
        self.offline_tx_count = 0;
        self.offline_spend_total = 0;
        self.last_sync_timestamp = now_unix();
        self.pending_sync.clear();
        self.received_acks.clear();
    }
}

// =============================================================================
// TRANSACTION ENGINE
// =============================================================================

/// Prepare a payment: select tokens and build the unsigned payload
pub fn prepare_payment(
    amount: u32,
    available_tokens: &[TokenEntry],
    merchant_nonce: &[u8; 32],
    payer_device_id: &str,
    counter_state: u64,
    offline_state: &OfflineState,
) -> Result<(UtxoSelection, TransactionPayload), TransactionError> {
    // Check velocity limits
    offline_state.can_transact(amount)?;

    // Select optimal tokens
    let selection = utxo::select_utxos(amount, available_tokens)
        .map_err(TransactionError::UtxoError)?;

    // Build Merkle tree from selected tokens
    let token_hashes: Vec<Vec<u8>> = selection
        .selected_tokens
        .iter()
        .map(|t| hash_token(&t.token_id, t.denomination, &[]))
        .collect();

    let merkle = merkle_root(&token_hashes)
        .map_err(TransactionError::CryptoError)?;

    // Generate unique transaction ID
    let tx_id = generate_tx_id(payer_device_id, counter_state);

    let payload = TransactionPayload {
        tx_id,
        token_ids: selection.selected_tokens.iter().map(|t| t.token_id.clone()).collect(),
        total_amount: selection.selected_total,
        denominations: selection.selected_tokens.iter().map(|t| t.denomination).collect(),
        merkle_root: merkle,
        session_nonce: merchant_nonce.to_vec(),
        payer_partial_sig: Vec::new(), // Filled after signing
        payer_device_id: payer_device_id.to_string(),
        counter_state,
        timestamp: now_unix(),
        chain_history: Vec::new(),
        overpayment: selection.overpayment,
    };

    Ok((selection, payload))
}

/// Sign a prepared payment payload using the WBC engine
///
/// This is where the 7-Layer security model comes together:
///   1. WBC table (key never in RAM)
///   2. Spatial Redundancy (anti-DFA double-compute)
///   3. MPC partial signature (Share A only)
pub fn sign_payment(
    payload: &mut TransactionPayload,
    keypair: &SecureKeypair,
    share_a: &KeyShare,
) -> Result<(), TransactionError> {
    // Serialize the critical fields for signing
    let sign_data = build_signing_data(payload);

    // Sign with Spatial Redundancy (anti-DFA)
    let signature = sign_with_redundancy(keypair, &sign_data)
        .map_err(TransactionError::CryptoError)?;

    // Generate MPC partial signature (Share A)
    let partial = mpc::generate_partial_sig(share_a, &sign_data);

    // Update payload with signatures
    payload.payer_partial_sig = partial.sig_bytes;

    Ok(())
}

/// Verify a received payment on the Merchant's side
pub fn verify_payment(
    payload: &TransactionPayload,
    payer_public_key: &[u8; 32],
    expected_nonce: &[u8; 32],
) -> Result<bool, TransactionError> {
    // Check nonce (anti-replay)
    if payload.session_nonce != expected_nonce.as_slice() {
        return Err(TransactionError::NonceMismatch);
    }

    // Verify Merkle root
    let token_hashes: Vec<Vec<u8>> = payload
        .token_ids
        .iter()
        .zip(payload.denominations.iter())
        .map(|(id, &denom)| hash_token(id, denom, &[]))
        .collect();

    let expected_merkle = merkle_root(&token_hashes)
        .map_err(TransactionError::CryptoError)?;

    if payload.merkle_root != expected_merkle {
        return Err(TransactionError::MerkleRootMismatch);
    }

    // Verify amounts add up
    let total: u32 = payload.denominations.iter().sum();
    if total != payload.total_amount {
        return Err(TransactionError::AmountMismatch {
            declared: payload.total_amount,
            actual: total,
        });
    }

    Ok(true)
}

/// Generate a Merchant Acknowledgement
pub fn generate_ack(
    payload: &TransactionPayload,
    merchant_device_id: &str,
    merchant_keypair: &SecureKeypair,
    change_tokens: Vec<ChangeToken>,
) -> Result<TransactionAck, TransactionError> {
    // Sign the acknowledgement
    let ack_data = format!(
        "ACK:{}:{}:{}",
        payload.tx_id, payload.total_amount, payload.timestamp
    );

    let sig = sign_with_redundancy(merchant_keypair, ack_data.as_bytes())
        .map_err(TransactionError::CryptoError)?;

    Ok(TransactionAck {
        tx_id: payload.tx_id.clone(),
        merchant_device_id: merchant_device_id.to_string(),
        combined_signature: sig,
        timestamp: now_unix(),
        change_tokens,
        accepted: true,
        rejection_reason: None,
    })
}

// =============================================================================
// GOSSIP SYNC LOG
// =============================================================================

/// A batch of offline transactions ready for Gossip upload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipBatch {
    pub device_id: String,
    pub transactions: Vec<TransactionPayload>,
    pub acks: Vec<TransactionAck>,
    pub current_counter: u64,
    pub batch_timestamp: u64,
    /// HMAC signature over the entire batch (for tamper detection)
    pub batch_signature: Vec<u8>,
}

/// Build a Gossip sync batch from offline state
pub fn build_gossip_batch(
    offline_state: &OfflineState,
    device_id: &str,
    current_counter: u64,
    signing_keypair: &SecureKeypair,
) -> Result<GossipBatch, TransactionError> {
    let mut batch = GossipBatch {
        device_id: device_id.to_string(),
        transactions: offline_state.pending_sync.clone(),
        acks: offline_state.received_acks.clone(),
        current_counter,
        batch_timestamp: now_unix(),
        batch_signature: Vec::new(),
    };

    // Sign the batch
    let batch_data = serde_json::to_vec(&batch)
        .map_err(|_| TransactionError::SerializationError)?;

    let sig = sign_with_redundancy(signing_keypair, &batch_data)
        .map_err(TransactionError::CryptoError)?;

    batch.batch_signature = sig;

    Ok(batch)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Build the byte array to be signed (deterministic ordering)
fn build_signing_data(payload: &TransactionPayload) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(payload.tx_id.as_bytes());
    data.extend(&payload.total_amount.to_le_bytes());
    data.extend(&payload.merkle_root);
    data.extend(&payload.session_nonce);
    data.extend(&payload.counter_state.to_le_bytes());
    data.extend(payload.payer_device_id.as_bytes());
    data.extend(&payload.timestamp.to_le_bytes());
    data
}

/// Generate a unique transaction ID
fn generate_tx_id(device_id: &str, counter: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(&counter.to_le_bytes());
    hasher.update(&now_unix().to_le_bytes());
    let hash = hasher.finalize();
    format!("tx-{}", hex::encode(&hash[..16]))
}

/// Get current Unix timestamp
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Clone)]
pub enum TransactionError {
    /// UTXO selection error
    UtxoError(UtxoError),
    /// Cryptographic error
    CryptoError(CryptoError),
    /// Session nonce does not match
    NonceMismatch,
    /// Merkle root verification failed
    MerkleRootMismatch,
    /// Declared amount doesn't match token sum
    AmountMismatch { declared: u32, actual: u32 },
    /// Offline transaction velocity limit exceeded
    VelocityLimitExceeded { max_txns: u32, current: u32 },
    /// Offline spend limit exceeded
    SpendLimitExceeded { max_amount: u32, current: u32, requested: u32 },
    /// Transaction expired
    TransactionExpired,
    /// Serialization error
    SerializationError,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionError::UtxoError(e) => write!(f, "UTXO error: {}", e),
            TransactionError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            TransactionError::NonceMismatch => write!(f, "Session nonce mismatch — possible replay attack"),
            TransactionError::MerkleRootMismatch => write!(f, "Merkle root verification failed — tokens tampered"),
            TransactionError::AmountMismatch { declared, actual } => {
                write!(f, "Amount mismatch: declared ₹{} but tokens sum to ₹{}", declared, actual)
            }
            TransactionError::VelocityLimitExceeded { max_txns, current } => {
                write!(f, "Velocity limit: max {} offline txns, already at {}", max_txns, current)
            }
            TransactionError::SpendLimitExceeded { max_amount, current, requested } => {
                write!(f, "Spend limit: max ₹{}, spent ₹{}, requesting ₹{}", max_amount, current, requested)
            }
            TransactionError::TransactionExpired => write!(f, "Transaction has expired"),
            TransactionError::SerializationError => write!(f, "Payload serialization error"),
        }
    }
}

impl std::error::Error for TransactionError {}

// =============================================================================
// TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo::TokenEntry;

    fn make_token(id: &str, denom: u32) -> TokenEntry {
        TokenEntry {
            token_id: id.to_string(),
            denomination: denom,
            status: TokenStatus::Unspent,
        }
    }

    fn test_wallet() -> Vec<TokenEntry> {
        vec![
            make_token("eR-500-001", 500),
            make_token("eR-100-001", 100),
            make_token("eR-50-001", 50),
            make_token("eR-10-001", 10),
            make_token("eR-10-002", 10),
            make_token("eR-5-001", 5),
            make_token("eR-2-001", 2),
            make_token("eR-2-002", 2),
            make_token("eR-1-001", 1),
        ]
    }

    #[test]
    fn test_prepare_payment_exact() {
        let tokens = test_wallet();
        let nonce = generate_session_nonce();
        let state = OfflineState::new();

        let (selection, payload) = prepare_payment(
            50, &tokens, &nonce, "device_001", 100, &state,
        ).unwrap();

        assert_eq!(selection.method, SettlementMethod::ExactMatch);
        assert_eq!(payload.total_amount, 50);
        assert_eq!(payload.overpayment, 0);
    }

    #[test]
    fn test_prepare_payment_overpay() {
        // Only large denominations available
        let tokens = vec![
            make_token("eR-500-001", 500),
            make_token("eR-20-001", 20),
        ];
        let nonce = generate_session_nonce();
        let state = OfflineState::new();

        let (selection, payload) = prepare_payment(
            511, &tokens, &nonce, "device_001", 100, &state,
        ).unwrap();

        assert_eq!(selection.method, SettlementMethod::BidirectionalSwap);
        assert_eq!(payload.overpayment, 9);
    }

    #[test]
    fn test_velocity_limit() {
        let tokens = test_wallet();
        let nonce = generate_session_nonce();
        let mut state = OfflineState::new();
        state.offline_tx_count = OFFLINE_VELOCITY_LIMIT; // Already at limit

        let result = prepare_payment(50, &tokens, &nonce, "device_001", 100, &state);
        assert!(matches!(result, Err(TransactionError::VelocityLimitExceeded { .. })));
    }

    #[test]
    fn test_spend_limit() {
        let tokens = test_wallet();
        let nonce = generate_session_nonce();
        let mut state = OfflineState::new();
        state.offline_spend_total = 1900; // ₹1900 already spent

        // Trying to spend ₹500 more (would exceed ₹2000 limit)
        let result = prepare_payment(500, &tokens, &nonce, "device_001", 100, &state);
        assert!(matches!(result, Err(TransactionError::SpendLimitExceeded { .. })));
    }

    #[test]
    fn test_verify_payment_nonce_mismatch() {
        let tokens = test_wallet();
        let nonce = generate_session_nonce();
        let state = OfflineState::new();

        let (_, payload) = prepare_payment(
            50, &tokens, &nonce, "device_001", 100, &state,
        ).unwrap();

        // Verify with different nonce — should fail (anti-replay)
        let wrong_nonce = generate_session_nonce();
        let result = verify_payment(&payload, &[0u8; 32], &wrong_nonce);
        assert!(matches!(result, Err(TransactionError::NonceMismatch)));
    }

    #[test]
    fn test_full_payment_flow() {
        let tokens = test_wallet();
        let mut state = OfflineState::new();

        // Step 1: Merchant generates nonce
        let nonce = generate_session_nonce();

        // Step 2: Payer prepares payment
        let (selection, mut payload) = prepare_payment(
            50, &tokens, &nonce, "payer_001", 100, &state,
        ).unwrap();

        // Step 3: Payer signs
        let keypair = SecureKeypair::generate();
        let full_seed = keypair.public_key_bytes(); // Using pub key as seed for test
        let (share_a, _share_b) = mpc::split_key(&full_seed);
        sign_payment(&mut payload, &keypair, &share_a).unwrap();

        // Step 4: Verify
        let verified = verify_payment(&payload, &keypair.public_key_bytes(), &nonce);
        assert!(verified.is_ok());

        // Step 5: Generate ack
        let merchant_keypair = SecureKeypair::generate();
        let ack = generate_ack(&payload, "merchant_001", &merchant_keypair, vec![]).unwrap();
        assert!(ack.accepted);

        // Step 6: Record transaction
        state.record_transaction(payload);
        state.record_ack(ack);
        assert_eq!(state.offline_tx_count, 1);
        assert_eq!(state.offline_spend_total, 50);
    }

    #[test]
    fn test_gossip_batch() {
        let mut state = OfflineState::new();
        let tokens = test_wallet();
        let nonce = generate_session_nonce();

        let (_, payload) = prepare_payment(
            10, &tokens, &nonce, "device_001", 100, &state,
        ).unwrap();
        state.record_transaction(payload);

        let keypair = SecureKeypair::generate();
        let batch = build_gossip_batch(&state, "device_001", 101, &keypair).unwrap();

        assert_eq!(batch.transactions.len(), 1);
        assert!(!batch.batch_signature.is_empty());
    }
}
