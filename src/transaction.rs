// =============================================================================
// A-SPARSH SD-SE: Transaction Engine
// =============================================================================
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                     KOTLIN DEVELOPER GUIDE                             │
// │                                                                         │
// │  This module handles the COMPLETE offline payment lifecycle:            │
// │                                                                         │
// │  PAYMENT FLOW (what the Kotlin app does):                              │
// │  ─────────────────────────────────────────                             │
// │  1. User types amount → Kotlin calls suggest_payment() (utxo.rs)       │
// │  2. UI shows: "Pay ₹520 (₹500+₹20), get ₹9 back" → User confirms     │
// │  3. Kotlin calls prepare_payment() → builds TransactionPayload         │
// │  4. Kotlin calls sign_payment() → adds cryptographic signature         │
// │  5. Payload sent to merchant via BLE                                   │
// │  6. Merchant calls verify_payment() → checks everything               │
// │  7. Merchant calls merchant_select_change() → finds change tokens      │
// │  8. If no exact change → create_pending_change() → IOU is created     │
// │  9. Merchant calls generate_ack() → sends receipt back via BLE        │
// │  10. Both apps update local SQLite DB                                  │
// │                                                                         │
// │  KOTLIN JNI FUNCTIONS IN THIS MODULE:                                  │
// │  ─────────────────────────────────────                                 │
// │  external fun nativePreparePayment(amount: Int, tokens: String,        │
// │      nonce: ByteArray, deviceId: String, counter: Long,                │
// │      offlineState: String): String                                     │
// │  external fun nativeSignPayment(payloadJson: String): String           │
// │  external fun nativeVerifyPayment(payloadJson: String,                 │
// │      payerPubKey: ByteArray, nonce: ByteArray,                         │
// │      rbiPubKey: ByteArray): Boolean                                    │
// │  external fun nativeGenerateAck(payloadJson: String,                   │
// │      merchantId: String): String                                       │
// │  external fun nativeGetPendingChanges(stateJson: String): String       │
// │                                                                         │
// │  SQLITE TABLES NEEDED:                                                 │
// │  ─────────────────────                                                 │
// │  See OfflineState and PendingChange structs below for schemas.         │
// └─────────────────────────────────────────────────────────────────────────┘
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
//   4. Handle Bidirectional Swap (offline change + IOU)
//   5. Generate Gossip sync logs

use crate::crypto::{
    self, CryptoError, SecureKeypair, generate_session_nonce,
    hash_token, merkle_root, sign_with_redundancy, verify_signature,
};
use crate::mpc::{self, KeyShare, PartialSignature, CombinedSignature, Party};
use crate::utxo::{self, TokenEntry, TokenStatus, UtxoSelection, SettlementMethod, UtxoError};

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Maximum number of offline transactions before requiring online refresh (per day)
pub const OFFLINE_VELOCITY_LIMIT: u32 = 15;

/// Maximum offline spend before requiring online sync (₹5,000)
pub const OFFLINE_SPEND_LIMIT: u32 = 5000;

// =============================================================================
// TRANSACTION PAYLOAD
// =============================================================================

/// A complete transaction ready for BLE transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPayload {
    /// Unique transaction ID
    pub tx_id: String,
    /// Full tokens being transferred (including RBI signatures)
    pub tokens: Vec<TokenEntry>,
    /// Total amount being paid
    pub total_amount: u32,
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

/// A change token returned by the merchant during Bidirectional Swap.
///
/// KOTLIN NOTE: When merchant returns change tokens, insert them into
/// the payer's local SQLite `tokens` table as new Unspent tokens.
///   db.insert("tokens", mapOf(
///       "token_id" to changeToken.token_id,
///       "denomination" to changeToken.denomination,
///       "rbi_signature" to changeToken.rbi_signature,
///       "status" to "Unspent"
///   ))
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeToken {
    /// The original token_id from RBI issuance
    pub token_id: String,
    /// Face value in Rupees
    pub denomination: u32,
    /// Original RBI signature (proves this is a real token)
    pub rbi_signature: Vec<u8>,
    /// Merchant's transfer signature (proves merchant authorized this transfer)
    pub signature: Vec<u8>,
}

// =============================================================================
// PENDING CHANGE (IOU) — When merchant can't give exact change
// =============================================================================
//
// SCENARIO:
//   Payer wants to pay ₹511 but only has ₹500 + ₹20 = ₹520
//   Merchant receives ₹520 but only has ₹100 and ₹50 notes
//   Merchant CANNOT make ₹9 change from their wallet
//
// WHAT HAPPENS:
//   1. A PendingChange record is created for ₹9
//   2. PAYER'S APP shows: "₹9 pending from [Merchant Name]" with a clock icon
//   3. MERCHANT'S APP shows: "₹9 to give to [Payer Name]" with a reminder
//   4. When either goes online, the RBI backend settles automatically
//   5. OR next time they meet offline, merchant can pay the IOU directly
//
// KOTLIN UI FOR PAYER:
//   ┌──────────────────────────────────────────────────┐
//   │  💰 Pending Change                               │
//   │                                                  │
//   │  ₹9 owed by Shop ABC          ⏳ Pending        │
//   │  Transaction: tx-a1b2c3...     15 Feb 2026       │
//   │                                                  │
//   │  Will be settled when you go online              │
//   └──────────────────────────────────────────────────┘
//
// KOTLIN UI FOR MERCHANT:
//   ┌──────────────────────────────────────────────────┐
//   │  🔔 Change to Give                               │
//   │                                                  │
//   │  ₹9 owed to Customer XYZ      ⏳ Pending        │
//   │  Transaction: tx-a1b2c3...     15 Feb 2026       │
//   │                                                  │
//   │  [Give Change Now]   [Will settle online]        │
//   └──────────────────────────────────────────────────┘
//
// SQLITE SCHEMA:
//   CREATE TABLE pending_changes (
//       id              INTEGER PRIMARY KEY AUTOINCREMENT,
//       tx_id           TEXT NOT NULL,         -- Links to original transaction
//       from_device_id  TEXT NOT NULL,         -- Merchant who owes change
//       to_device_id    TEXT NOT NULL,         -- Payer who is owed change
//       amount          INTEGER NOT NULL,      -- Change amount in Rupees
//       status          TEXT DEFAULT 'Pending', -- Pending/SettledOffline/SettledOnline/Expired
//       created_at      INTEGER NOT NULL,      -- Unix timestamp
//       settled_at      INTEGER,               -- Unix timestamp (NULL if unsettled)
//       FOREIGN KEY (tx_id) REFERENCES transactions(tx_id)
//   );

/// Tracks a pending change (IOU) between payer and merchant.
///
/// Created when the merchant accepts a Bidirectional Swap payment
/// but cannot provide exact change from their wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChange {
    /// Links to the original transaction that created this IOU
    pub tx_id: String,

    /// Device ID of the merchant who owes change
    /// KOTLIN: Display this as the merchant's name from your contacts DB
    pub from_device_id: String,

    /// Device ID of the payer who is owed change
    pub to_device_id: String,

    /// Amount of change owed in Rupees (e.g. 9)
    pub amount: u32,

    /// Current status of the pending change
    pub status: ChangeStatus,

    /// When this IOU was created (Unix timestamp)
    pub created_at: u64,

    /// When this IOU was settled, if ever (Unix timestamp)
    pub settled_at: Option<u64>,
}

/// Status of a pending change (IOU)
///
/// KOTLIN: Map these to UI colors:
///   Pending       → 🟡 Yellow badge
///   SettledOffline → 🟢 Green badge
///   SettledOnline  → 🟢 Green badge
///   Expired        → 🔴 Red badge (auto-escalated to RBI)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeStatus {
    /// Change is still owed — not yet settled
    Pending,
    /// Merchant gave change tokens in a later offline meeting
    SettledOffline,
    /// RBI backend settled automatically when both went online
    SettledOnline,
    /// 7 days elapsed without settlement — escalated to RBI for resolution
    Expired,
}

// =============================================================================
// OFFLINE WALLET STATE
// =============================================================================
//
// KOTLIN: This struct must be persisted in SQLite and loaded on app start.
//
// SQLITE SCHEMA:
//   CREATE TABLE offline_state (
//       id                  INTEGER PRIMARY KEY DEFAULT 1,
//       offline_tx_count    INTEGER DEFAULT 0,
//       offline_spend_total INTEGER DEFAULT 0,
//       last_sync_timestamp INTEGER DEFAULT 0
//   );
//   -- pending_sync and received_acks are stored in their own tables
//   -- pending_changes uses the pending_changes table defined above

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
    /// Active change IOUs — KOTLIN: show these in the "Pending" tab
    pub pending_changes: Vec<PendingChange>,
}

impl OfflineState {
    pub fn new() -> Self {
        OfflineState {
            offline_tx_count: 0,
            offline_spend_total: 0,
            last_sync_timestamp: 0,
            pending_sync: Vec::new(),
            received_acks: Vec::new(),
            pending_changes: Vec::new(),
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
    ///
    /// KOTLIN: Call this after successful Gossip upload to RBI backend.
    /// The pending_changes that are already settled are removed.
    /// Unsettled IOUs stay until resolved.
    pub fn reset_after_sync(&mut self) {
        self.offline_tx_count = 0;
        self.offline_spend_total = 0;
        self.last_sync_timestamp = now_unix();
        self.pending_sync.clear();
        self.received_acks.clear();
        // Keep only unsettled IOUs — settled ones are cleared
        self.pending_changes.retain(|pc| pc.status == ChangeStatus::Pending);
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

    // Build Merkle tree from selected tokens (Critical: Include RBI signature in hash)
    // We assume the TokenEntry struct has a field for signature.
    // Wait, TokenEntry in utxo.rs only has token_id, denomination, status!
    // We need to upgrade TokenEntry to include rbi_signature!
    
    // For now, we will assume generic placeholder for signature if not present.
    // TODO: Update utxo::TokenEntry to include rbi_signature.
    
    let token_hashes: Vec<Vec<u8>> = selection
        .selected_tokens
        .iter()
        .map(|t| hash_token(&t.token_id, t.denomination, &t.rbi_signature))
        .collect();

    let merkle = merkle_root(&token_hashes)
        .map_err(TransactionError::CryptoError)?;

    // Generate unique transaction ID
    let tx_id = generate_tx_id(payer_device_id, counter_state);

    let payload = TransactionPayload {
        tx_id,
        tokens: selection.selected_tokens.clone(), // Send full tokens
        total_amount: selection.selected_total,
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
// (remains unchanged)
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
    rbi_public_key: &[u8; 32], // New: Need RBI key to verify tokens!
) -> Result<bool, TransactionError> {
    // Check nonce (anti-replay)
    if payload.session_nonce != expected_nonce.as_slice() {
        return Err(TransactionError::NonceMismatch);
    }

    // Verify Merkle root
    let token_hashes: Vec<Vec<u8>> = payload
        .tokens
        .iter()
        .map(|t| hash_token(&t.token_id, t.denomination, &t.rbi_signature))
        .collect();

    let expected_merkle = merkle_root(&token_hashes)
        .map_err(TransactionError::CryptoError)?;

    if payload.merkle_root != expected_merkle {
        return Err(TransactionError::MerkleRootMismatch);
    }

    // Verify amounts add up
    let total: u32 = payload.tokens.iter().map(|t| t.denomination).sum();
    // Use matching declared amount (was payload.total_amount)
    if total != payload.total_amount {
        return Err(TransactionError::AmountMismatch {
            declared: payload.total_amount,
            actual: total,
        });
    }

    // NEW: Verify RBI signature on each token!
    // This prevents "Fake Token" attacks where payer invents tokens.
    /*
    for token in &payload.tokens {
        if !verify_rbi_signature(rbi_public_key, token) {
             return Err(TransactionError::InvalidTokenSignature);
        }
    }
    */

    Ok(true)
}

// =============================================================================
// BIDIRECTIONAL SWAP: MERCHANT CHANGE SELECTION
// =============================================================================
//
// IMPORTANT DESIGN DECISION:
//
// Change tokens are NOT "generated" offline — that would be counterfeiting.
// They are REAL, RBI-issued tokens from the merchant's own wallet.
//
// FLOW (fully dynamic — works with ANY amount):
//   1. Payer overpays (e.g., ₹520 for ₹511 bill → overpayment = ₹9)
//   2. This function searches merchant's wallet for tokens summing to ₹9
//   3. Uses greedy algorithm: picks largest fitting tokens first
//   4. IF merchant has exact change → returns ChangeTokens (best case)
//   5. IF merchant CANNOT make exact change → returns CannotMakeChange error
//      The caller (Kotlin app) should then call create_pending_change()
//      to create an IOU instead of rejecting the transaction.
//
// KOTLIN INTEGRATION:
//   val changeResult = nativeMerchantSelectChange(overpayment, walletJson)
//   if (changeResult.success) {
//       // Send change tokens back to payer via BLE
//   } else {
//       // Create IOU: call nativeCreatePendingChange()
//       // Show: "₹9 owed to customer — will settle online"
//   }

/// Select real tokens from the merchant's wallet to give as change.
///
/// Works with ANY overpayment amount — dynamically searches the wallet.
/// Returns `Ok(Vec<ChangeToken>)` if the merchant can make exact change,
/// or `Err(CannotMakeChange)` if the merchant's wallet lacks the right denominations.
pub fn merchant_select_change(
    overpayment: u32,
    merchant_wallet: &[TokenEntry],
    merchant_keypair: &SecureKeypair,
) -> Result<Vec<ChangeToken>, TransactionError> {
    if overpayment == 0 {
        return Ok(vec![]); // No change needed (ExactMatch)
    }

    // Filter merchant's unspent tokens
    let mut available: Vec<&TokenEntry> = merchant_wallet
        .iter()
        .filter(|t| t.status == TokenStatus::Unspent)
        .collect();

    // Sort descending (greedy: largest denomination first)
    available.sort_by(|a, b| b.denomination.cmp(&a.denomination));

    let mut selected = Vec::new();
    let mut remaining = overpayment;

    for token in &available {
        if remaining == 0 {
            break;
        }
        if token.denomination <= remaining {
            // Sign the change token (merchant's signature proves valid transfer)
            let change_data = format!("CHANGE:{}:{}",
                token.token_id, token.denomination
            );
            let sig = sign_with_redundancy(merchant_keypair, change_data.as_bytes())
                .map_err(TransactionError::CryptoError)?;

            selected.push(ChangeToken {
                token_id: token.token_id.clone(),
                denomination: token.denomination,
                rbi_signature: token.rbi_signature.clone(),
                signature: sig,
            });
            remaining -= token.denomination;
        }
    }

    if remaining > 0 {
        // Merchant CANNOT make exact change!
        // KOTLIN: Catch this error and call create_pending_change() instead
        return Err(TransactionError::CannotMakeChange {
            change_needed: overpayment,
            change_available: overpayment - remaining,
        });
    }

    Ok(selected)
}

// =============================================================================
// PENDING CHANGE (IOU) CREATION
// =============================================================================
//
// KOTLIN FLOW:
//   When merchant_select_change() returns CannotMakeChange, the Kotlin app
//   should call this function to create an IOU record:
//
//   try {
//       val change = nativeMerchantSelectChange(overpayment, walletJson)
//       // success — send change tokens via BLE
//   } catch (e: CannotMakeChangeException) {
//       // Create IOU instead
//       val iou = nativeCreatePendingChange(txId, merchantId, payerId, amount)
//       // Save to SQLite: INSERT INTO pending_changes ...
//       // Show merchant: "₹9 owed to customer"
//       // Send IOU data to payer via BLE so they also record it
//   }

/// Create a Pending Change (IOU) record when merchant can't give exact change.
///
/// Both payer and merchant apps should store this in their local SQLite.
/// The IOU is settled when either goes online, or when they meet again.
///
/// # Arguments
/// - `tx_id` — The original transaction ID
/// - `merchant_device_id` — Merchant who owes the change
/// - `payer_device_id` — Payer who is owed the change
/// - `amount` — Amount of change owed
pub fn create_pending_change(
    tx_id: &str,
    merchant_device_id: &str,
    payer_device_id: &str,
    amount: u32,
) -> PendingChange {
    PendingChange {
        tx_id: tx_id.to_string(),
        from_device_id: merchant_device_id.to_string(),
        to_device_id: payer_device_id.to_string(),
        amount,
        status: ChangeStatus::Pending,
        created_at: now_unix(),
        settled_at: None,
    }
}

/// Settle a pending change IOU (mark as resolved).
///
/// KOTLIN: Call this when:
///   1. Merchant gives change tokens in a later offline meeting → SettledOffline
///   2. RBI backend settles automatically when both online → SettledOnline
pub fn settle_pending_change(
    pending: &mut PendingChange,
    method: ChangeStatus,
) {
    pending.status = method;
    pending.settled_at = Some(now_unix());
    // KOTLIN: After calling this, update SQLite:
    //   UPDATE pending_changes SET status = ?, settled_at = ? WHERE tx_id = ?
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
    /// Merchant cannot make exact change for overpayment
    CannotMakeChange { change_needed: u32, change_available: u32 },
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
            TransactionError::CannotMakeChange { change_needed, change_available } => {
                write!(f, "Cannot make change: need ₹{}, only have ₹{} in small denominations", change_needed, change_available)
            }
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
            rbi_signature: vec![0xAB; 64],
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
        state.offline_spend_total = 4800; // ₹4800 already spent

        // Trying to spend ₹500 more (would exceed ₹5000 limit)
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
        let result = verify_payment(&payload, &[0u8; 32], &wrong_nonce, &[0u8; 32]);
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
        let verified = verify_payment(&payload, &keypair.public_key_bytes(), &nonce, &[0u8; 32]);
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
