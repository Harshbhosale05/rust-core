// =============================================================================
// A-SPARSH SD-SE: Smart UTXO Coin Selection Engine
// =============================================================================
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                     KOTLIN DEVELOPER GUIDE                             │
// │                                                                         │
// │  This module handles the "digital wallet" — selecting which tokens      │
// │  (digital notes) to use for a payment. Think of it like choosing        │
// │  physical notes from your wallet.                                       │
// │                                                                         │
// │  HOW TO CALL FROM KOTLIN (via JNI):                                    │
// │  ──────────────────────────────────────────────────────────────────     │
// │  1. Load tokens from SQLite → pass as JSON array to Rust                │
// │  2. Call `suggest_payment(amount, tokensJson)` → get PaymentSuggestion  │
// │  3. Show the suggestion to user in the UI                               │
// │  4. If user confirms → call `prepare_payment()` in transaction.rs       │
// │                                                                         │
// │  SQLITE SCHEMA FOR TOKENS:                                              │
// │  ──────────────────────────────────────────────────────────────────     │
// │  CREATE TABLE tokens (                                                  │
// │      token_id     TEXT PRIMARY KEY,    -- e.g. "eR-500-0001"           │
// │      denomination INTEGER NOT NULL,    -- 1,2,5,10,20,50,100,200,500  │
// │      rbi_signature BLOB NOT NULL,      -- 64-byte Ed25519 signature   │
// │      status       TEXT DEFAULT 'Unspent' -- Unspent/Pending/Spent     │
// │  );                                                                      │
// │                                                                         │
// │  KOTLIN CODE TO LOAD TOKENS:                                            │
// │  ──────────────────────────────────────────────────────────────────     │
// │  fun loadWalletTokens(): String {                                       │
// │      val cursor = db.query("tokens",                                   │
// │          arrayOf("token_id","denomination","rbi_signature","status"),   │
// │          "status = ?", arrayOf("Unspent"), null, null, null)           │
// │      val tokens = mutableListOf<Map<String,Any>>()                     │
// │      while (cursor.moveToNext()) {                                     │
// │          tokens.add(mapOf(                                              │
// │              "token_id" to cursor.getString(0),                         │
// │              "denomination" to cursor.getInt(1),                        │
// │              "rbi_signature" to cursor.getBlob(2).toList(),            │
// │              "status" to cursor.getString(3)                            │
// │          ))                                                              │
// │      }                                                                   │
// │      return Gson().toJson(tokens) // Pass this JSON to Rust            │
// │  }                                                                       │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘
//
// Implements the three settlement methods:
//   1. Smart Coin Selection & Batching  (exact denomination match)
//   2. Bidirectional Atomic Swap        (overpay + get offline change)
//   3. Cryptographic Slicing / Tearable (split a token, freeze remainder)
//
// The algorithm mirrors physical cash: RBI issues fixed denominations
// (₹1, ₹2, ₹5, ₹10, ₹20, ₹50, ₹100, ₹200, ₹500).

use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

/// The valid RBI e-Rupee denominations (mirroring physical fiat)
pub const VALID_DENOMINATIONS: &[u32] = &[1, 2, 5, 10, 20, 50, 100, 200, 500];

// =============================================================================
// TOKEN ENTRY — A single digital note in the wallet
// =============================================================================
//
// KOTLIN JNI MAPPING:
// ──────────────────
// This struct maps directly to a JSON object passed from Kotlin.
// When calling Rust via JNI, serialize your Kotlin token list to JSON:
//
//   val tokensJson = """[
//       {"token_id":"eR-500-0001","denomination":500,"rbi_signature":[171,171,...],"status":"Unspent"},
//       {"token_id":"eR-100-0001","denomination":100,"rbi_signature":[171,171,...],"status":"Unspent"}
//   ]"""
//   val resultJson = nativeSuggestPayment(amount, tokensJson) // JNI call
//
// DB NOTE:
// ────────
// Each token is issued by RBI during provisioning and stored in SQLite.
// The `rbi_signature` is critical — it proves the token is genuine.
// Never modify this field; doing so will cause verify_payment() to fail.

/// Represents a single digital token in the local wallet
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEntry {
    /// Unique token identifier (format: "eR-{denomination}-{serial}")
    /// Example: "eR-500-0001", "eR-10-0042"
    /// This ID is globally unique and assigned by RBI during issuance.
    pub token_id: String,

    /// Face value of this token in Rupees (₹1, ₹2, ₹5, ... ₹500)
    /// Must be one of the VALID_DENOMINATIONS values.
    pub denomination: u32,

    /// Ed25519 signature from RBI certifying this token:
    ///   rbi_signature = Ed25519_Sign(rbi_private_key, SHA256(token_id || denomination))
    /// This is verified by the merchant during verify_payment() to prevent
    /// "Fake Token" attacks where a payer invents tokens with arbitrary IDs.
    ///
    /// DB STORAGE: Store as BLOB in SQLite (64 bytes)
    pub rbi_signature: Vec<u8>,

    /// Current status of this token in the payer's wallet
    /// - Unspent: Available for new payments
    /// - Pending: Currently in an unconfirmed transaction
    /// - Spent: Successfully transferred to someone else
    /// - Frozen: Partially spent via CryptographicSlice (awaits online sync)
    ///
    /// KOTLIN UI NOTE: Only show "Unspent" tokens in the wallet balance.
    /// "Pending" tokens should show with a ⏳ icon.
    /// "Spent" tokens can be hidden or shown in transaction history.
    pub status: TokenStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenStatus {
    /// Available for payments — shown in wallet balance
    Unspent,
    /// In transit: an offline transaction is in progress but not yet confirmed
    /// KOTLIN UI: Show as "Processing..." with a spinner
    Pending,
    /// Successfully transferred — no longer usable
    Spent,
    /// Frozen: partial spend occurred, remainder awaits online reconciliation
    /// KOTLIN UI: Show as "Frozen (₹X locked)" with an info tooltip
    Frozen,
}

// =============================================================================
// PAYMENT SUGGESTION — What to show the user BEFORE they confirm
// =============================================================================
//
// KOTLIN UI FLOW:
// ───────────────
// 1. User enters amount (e.g. ₹153) in the "Pay" screen
// 2. Kotlin calls: nativeSuggestPayment(153, walletTokensJson)
// 3. Rust returns a PaymentSuggestion as JSON
// 4. Kotlin parses it and shows a dialog:
//
//   ┌──────────────────────────────────────────────────┐
//   │              Confirm Payment                     │
//   │                                                  │
//   │  You want to pay: ₹153                          │
//   │  Best available:  ₹155 (₹100 + ₹50 + ₹5)      │
//   │  Change owed:     ₹2 (will be returned)         │
//   │                                                  │
//   │  Using 3 tokens from your wallet                │
//   │                                                  │
//   │          [Cancel]     [Pay ₹155]                │
//   └──────────────────────────────────────────────────┘
//
// If exact match (overpayment = 0):
//   ┌──────────────────────────────────────────────────┐
//   │              Confirm Payment                     │
//   │                                                  │
//   │  Paying: ₹50 (₹50 note — exact match! ✅)      │
//   │                                                  │
//   │          [Cancel]     [Pay ₹50]                 │
//   └──────────────────────────────────────────────────┘
//
// KOTLIN CODE TO PARSE:
// ─────────────────────
//   data class PaymentSuggestion(
//       val requested_amount: Int,
//       val suggested_amount: Int,
//       val overpayment: Int,
//       val is_exact_match: Boolean,
//       val denomination_breakdown: String,
//       val token_count: Int,
//       val tokens_to_use: List<TokenEntry>,
//       val user_message: String  // Human-readable explanation
//   )

/// What the Kotlin UI should display to the user before they confirm payment.
///
/// This struct is returned by `suggest_payment()` and contains everything
/// the UI needs to render a payment confirmation dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentSuggestion {
    /// The amount the user originally typed (e.g. ₹153)
    pub requested_amount: u32,

    /// The actual amount that will be transferred (e.g. ₹155)
    /// This equals requested_amount if exact match, or higher if overpay needed.
    pub suggested_amount: u32,

    /// How much change the payer is owed back (suggested_amount - requested_amount)
    /// If 0, it's an exact match and no change is needed.
    pub overpayment: u32,

    /// True if the wallet has exact denominations for the requested amount
    pub is_exact_match: bool,

    /// Human-readable breakdown of which notes will be used
    /// Example: "₹100 + ₹50 + ₹5" or "₹500 note"
    pub denomination_breakdown: String,

    /// Number of tokens that will be transferred
    pub token_count: usize,

    /// The actual tokens selected (used internally by prepare_payment)
    /// KOTLIN NOTE: You don't need to display these individually,
    /// just pass this entire PaymentSuggestion JSON to prepare_payment().
    pub tokens_to_use: Vec<TokenEntry>,

    /// Human-readable message to show the user
    /// Examples:
    /// - "Exact match! Paying ₹50 with a ₹50 note."
    /// - "You don't have exact change. Pay ₹520 (₹500 + ₹20) and get ₹9 back."
    /// - "Insufficient balance. You have ₹180 but need ₹500."
    pub user_message: String,

    /// The settlement method that will be used
    pub settlement_method: SettlementMethod,
}

/// Result of the UTXO selection algorithm (used internally)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoSelection {
    /// Tokens selected for payment
    pub selected_tokens: Vec<TokenEntry>,
    /// Total value of selected tokens
    pub selected_total: u32,
    /// The exact amount the user wants to pay
    pub target_amount: u32,
    /// Overpayment amount (selected_total - target_amount)
    /// If > 0, triggers Bidirectional Atomic Swap for change
    pub overpayment: u32,
    /// Settlement method used
    pub method: SettlementMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SettlementMethod {
    /// Perfect denomination match, no change needed
    ExactMatch,
    /// Overpayment — merchant must return offline change
    BidirectionalSwap,
    /// Token tearing — remainder frozen until online reconciliation
    CryptographicSlice,
}

/// Errors during UTXO selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtxoError {
    /// Wallet doesn't have enough funds
    InsufficientBalance { available: u32, requested: u32 },
    /// No unspent tokens available
    NoUnspentTokens,
    /// Invalid amount (zero or negative)
    InvalidAmount,
}

impl std::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtxoError::InsufficientBalance { available, requested } => {
                write!(f, "Insufficient balance: have ₹{}, need ₹{}", available, requested)
            }
            UtxoError::NoUnspentTokens => write!(f, "No unspent tokens in wallet"),
            UtxoError::InvalidAmount => write!(f, "Invalid payment amount"),
        }
    }
}

impl std::error::Error for UtxoError {}

// =============================================================================
// PAYMENT SUGGESTION ENGINE — The first thing Kotlin calls
// =============================================================================
//
// KOTLIN JNI BRIDGE:
// ──────────────────
// On the Kotlin side, you would call this via JNI:
//
//   // In your PaymentActivity.kt:
//   external fun nativeSuggestPayment(amount: Int, walletTokensJson: String): String
//
//   // Usage:
//   val tokensJson = loadWalletTokens() // Load from SQLite
//   val suggestionJson = nativeSuggestPayment(153, tokensJson)
//   val suggestion = Gson().fromJson(suggestionJson, PaymentSuggestion::class.java)
//
//   if (suggestion.is_exact_match) {
//       showConfirmDialog("Pay ₹${suggestion.suggested_amount}?")
//   } else {
//       showConfirmDialog(suggestion.user_message)
//   }
//
// IMPORTANT: This function does NOT execute the payment.
// It only tells the UI what WOULD happen if the user confirms.
// The actual payment starts when the user taps "Confirm" →
// which calls prepare_payment() in transaction.rs.

/// Generate a payment suggestion for the Kotlin UI.
///
/// This is called BEFORE the user confirms the payment.
/// It analyzes the wallet, picks the best tokens, and returns
/// a human-readable suggestion for the UI to display.
///
/// Works with ANY amount — dynamically checks all available denominations.
///
/// # Arguments
/// - `amount` — The amount the user wants to pay (e.g. 153)
/// - `available_tokens` — All tokens in the user's wallet (loaded from SQLite)
///
/// # Returns
/// A `PaymentSuggestion` with everything the Kotlin UI needs.
pub fn suggest_payment(
    amount: u32,
    available_tokens: &[TokenEntry],
) -> PaymentSuggestion {
    // Edge case: zero amount
    if amount == 0 {
        return PaymentSuggestion {
            requested_amount: 0,
            suggested_amount: 0,
            overpayment: 0,
            is_exact_match: false,
            denomination_breakdown: String::new(),
            token_count: 0,
            tokens_to_use: vec![],
            user_message: "Please enter a valid amount.".to_string(),
            settlement_method: SettlementMethod::ExactMatch,
        };
    }

    // Try to select tokens for this amount
    match select_utxos(amount, available_tokens) {
        Ok(selection) => {
            // Build the denomination breakdown string (e.g. "₹500 + ₹20")
            let breakdown = build_denomination_breakdown(&selection.selected_tokens);

            let is_exact = selection.overpayment == 0;

            // Build the human-readable message for the Kotlin UI
            //
            // KOTLIN UI NOTE:
            // Display this message directly in a TextView or Dialog.
            // It's designed to be user-friendly and self-explanatory.
            let message = if is_exact {
                format!(
                    "Exact match! Paying ₹{} with {}.",
                    selection.selected_total, breakdown
                )
            } else {
                format!(
                    "You don't have exact change for ₹{}. \
                     Pay ₹{} ({}) and get ₹{} back from merchant.",
                    amount,
                    selection.selected_total,
                    breakdown,
                    selection.overpayment
                )
            };

            PaymentSuggestion {
                requested_amount: amount,
                suggested_amount: selection.selected_total,
                overpayment: selection.overpayment,
                is_exact_match: is_exact,
                denomination_breakdown: breakdown,
                token_count: selection.selected_tokens.len(),
                tokens_to_use: selection.selected_tokens,
                user_message: message,
                settlement_method: if is_exact {
                    SettlementMethod::ExactMatch
                } else {
                    SettlementMethod::BidirectionalSwap
                },
            }
        }

        Err(UtxoError::InsufficientBalance { available, requested }) => {
            // KOTLIN UI: Show error state — not enough money
            //   Toast.makeText(this, suggestion.user_message, Toast.LENGTH_LONG).show()
            //   payButton.isEnabled = false
            PaymentSuggestion {
                requested_amount: requested,
                suggested_amount: 0,
                overpayment: 0,
                is_exact_match: false,
                denomination_breakdown: String::new(),
                token_count: 0,
                tokens_to_use: vec![],
                user_message: format!(
                    "Insufficient balance! You have ₹{} but need ₹{}.",
                    available, requested
                ),
                settlement_method: SettlementMethod::ExactMatch,
            }
        }

        Err(UtxoError::NoUnspentTokens) => {
            // KOTLIN UI: Show empty wallet state
            //   walletEmptyView.visibility = View.VISIBLE
            //   payButton.isEnabled = false
            PaymentSuggestion {
                requested_amount: amount,
                suggested_amount: 0,
                overpayment: 0,
                is_exact_match: false,
                denomination_breakdown: String::new(),
                token_count: 0,
                tokens_to_use: vec![],
                user_message: "Your wallet is empty! Load tokens by going online.".to_string(),
                settlement_method: SettlementMethod::ExactMatch,
            }
        }

        Err(_) => {
            PaymentSuggestion {
                requested_amount: amount,
                suggested_amount: 0,
                overpayment: 0,
                is_exact_match: false,
                denomination_breakdown: String::new(),
                token_count: 0,
                tokens_to_use: vec![],
                user_message: "An error occurred. Please try again.".to_string(),
                settlement_method: SettlementMethod::ExactMatch,
            }
        }
    }
}

/// Build a human-readable string like "₹500 + ₹20" from selected tokens.
///
/// KOTLIN NOTE: This is already formatted for display in a TextView.
/// You can use it directly:
///   denominationText.text = suggestion.denomination_breakdown
fn build_denomination_breakdown(tokens: &[TokenEntry]) -> String {
    if tokens.is_empty() {
        return String::new();
    }

    if tokens.len() == 1 {
        return format!("₹{} note", tokens[0].denomination);
    }

    tokens
        .iter()
        .map(|t| format!("₹{}", t.denomination))
        .collect::<Vec<_>>()
        .join(" + ")
}

// =============================================================================
// CORE UTXO SELECTION ALGORITHM
// =============================================================================
//
// This is the internal algorithm. Kotlin code should NOT call this directly.
// Instead, call suggest_payment() which wraps this with UI-friendly output.
//
// The algorithm works with ANY amount and ANY wallet composition:
//   - ₹7   with wallet [₹5, ₹2, ₹1]      → ExactMatch:  ₹5 + ₹2
//   - ₹153 with wallet [₹100, ₹50, ₹5]    → ExactMatch:  ₹100 + ₹50 + ₹5 = ₹155? No...
//                                            → Actually:    ₹100 + ₹50 + ₹5 = ₹155,
//                                                           but ₹153 needs ₹100+₹50+₹2+₹1
//   - ₹999 with wallet [₹500, ₹500, ₹2]  → BidirectionalSwap: ₹1002, change ₹3
//
// ALGORITHM STEPS:
//   1. Filter only Unspent tokens
//   2. Check total balance ≥ requested amount
//   3. Sort tokens by denomination (largest first)
//   4. STRATEGY 1: Greedy exact match — take largest tokens that fit
//   5. If exact match fails → STRATEGY 2: Overpay with smallest sufficient extra token
//   6. Return UtxoSelection with method (ExactMatch or BidirectionalSwap)

/// Smart UTXO Coin Selection Algorithm
///
/// Selects the optimal combination of digital tokens to pay an exact amount.
/// Uses a greedy approach: largest denominations first, minimizing token count
/// (and therefore minimizing the number of hardware key burns).
///
/// # Settlement Methods
///
/// 1. **ExactMatch**: The greedy algorithm finds exact denominations.
///    Example: Pay ₹137 with [₹100, ₹20, ₹10, ₹5, ₹2] — perfect.
///
/// 2. **BidirectionalSwap**: Greedy overshoots. The merchant must return
///    offline change in the same BLE handshake.
///    Example: Pay ₹511 with [₹500, ₹20] = ₹520 → merchant returns ₹9.
///
/// 3. **CryptographicSlice**: Not enough total value but a single large token
///    can be "torn". Remainder is frozen until online reconciliation.
///    (Currently simplified — full tearable tokens require RBI backend support.)
pub fn select_utxos(
    target_amount: u32,
    available_tokens: &[TokenEntry],
) -> Result<UtxoSelection, UtxoError> {
    if target_amount == 0 {
        return Err(UtxoError::InvalidAmount);
    }

    // Filter only UNSPENT tokens
    let mut unspent: Vec<&TokenEntry> = available_tokens
        .iter()
        .filter(|t| t.status == TokenStatus::Unspent)
        .collect();

    if unspent.is_empty() {
        return Err(UtxoError::NoUnspentTokens);
    }

    let total_available: u32 = unspent.iter().map(|t| t.denomination).sum();
    if total_available < target_amount {
        return Err(UtxoError::InsufficientBalance {
            available: total_available,
            requested: target_amount,
        });
    }

    // Sort descending by denomination (greedy: largest first)
    unspent.sort_by_key(|t| Reverse(t.denomination));

    // --- Strategy 1: Greedy exact match ---
    let mut selected = Vec::new();
    let mut remaining = target_amount;

    for token in &unspent {
        if remaining == 0 {
            break;
        }
        if token.denomination <= remaining {
            selected.push((*token).clone());
            remaining -= token.denomination;
        }
    }

    if remaining == 0 {
        // Perfect exact match!
        let selected_total = selected.iter().map(|t| t.denomination).sum();
        return Ok(UtxoSelection {
            selected_tokens: selected,
            selected_total,
            target_amount,
            overpayment: 0,
            method: SettlementMethod::ExactMatch,
        });
    }

    // --- Strategy 2: Overpay with the smallest sufficient coin ---
    // Reset and try: greedy as far as possible, then overpay with next coin
    selected.clear();
    remaining = target_amount;
    let mut used_indices = Vec::new();

    for (i, token) in unspent.iter().enumerate() {
        if remaining == 0 {
            break;
        }
        if token.denomination <= remaining {
            selected.push((*token).clone());
            remaining -= token.denomination;
            used_indices.push(i);
        }
    }

    if remaining > 0 {
        // Find the smallest unused token that covers the remainder
        for (i, token) in unspent.iter().enumerate().rev() {
            if !used_indices.contains(&i) && token.denomination >= remaining {
                selected.push((*token).clone());
                remaining = 0;
                break;
            }
        }

        // If still can't cover, grab any available tokens
        if remaining > 0 {
            for (i, token) in unspent.iter().enumerate() {
                if remaining == 0 {
                    break;
                }
                if !used_indices.contains(&i)
                    && !selected.iter().any(|s| s.token_id == token.token_id)
                {
                    selected.push((*token).clone());
                    if token.denomination >= remaining {
                        remaining = 0;
                    } else {
                        remaining -= token.denomination;
                    }
                }
            }
        }
    }

    let selected_total: u32 = selected.iter().map(|t| t.denomination).sum();
    let overpayment = selected_total.saturating_sub(target_amount);

    Ok(UtxoSelection {
        selected_tokens: selected,
        selected_total,
        target_amount,
        overpayment,
        method: if overpayment > 0 {
            SettlementMethod::BidirectionalSwap
        } else {
            SettlementMethod::ExactMatch
        },
    })
}

// =============================================================================
// CHANGE DENOMINATION CALCULATOR
// =============================================================================
//
// KOTLIN NOTE: This function tells the merchant app what denominations
// the change should ideally be broken into.
//
// Example: overpayment = ₹9 → returns [5, 2, 2]
// meaning the merchant should give back one ₹5 token and two ₹2 tokens.
//
// IMPORTANT: This calculates the IDEAL change denominations.
// The merchant may not have these exact tokens in their wallet.
// See transaction.rs → merchant_select_change() for what actually happens.

/// Calculate the optimal change denominations for a Bidirectional Swap.
///
/// Given any overpayment amount, returns the minimal set of denominations
/// that sum to that amount, using the standard RBI denomination set.
///
/// Works with ANY amount — uses greedy algorithm on the denomination table.
///
/// Examples:
///   ₹9   → [₹5, ₹2, ₹2]
///   ₹47  → [₹20, ₹20, ₹5, ₹2]
///   ₹123 → [₹100, ₹20, ₹2, ₹1]
///   ₹0   → []
pub fn calculate_change_denominations(overpayment: u32) -> Vec<u32> {
    if overpayment == 0 {
        return vec![];
    }

    let mut change = Vec::new();
    let mut remaining = overpayment;
    let denoms = [500, 200, 100, 50, 20, 10, 5, 2, 1];

    for &d in &denoms {
        while remaining >= d {
            change.push(d);
            remaining -= d;
        }
    }

    change
}

/// Get the total wallet balance (sum of all Unspent tokens).
///
/// KOTLIN: Call this to display the wallet balance on the home screen:
///   balanceText.text = "₹${nativeGetWalletBalance(tokensJson)}"
pub fn wallet_balance(tokens: &[TokenEntry]) -> u32 {
    tokens
        .iter()
        .filter(|t| t.status == TokenStatus::Unspent)
        .map(|t| t.denomination)
        .sum()
}

/// Get a human-readable breakdown of the wallet contents.
///
/// KOTLIN: Useful for the "Wallet Details" screen:
///   walletDetailsText.text = nativeGetWalletBreakdown(tokensJson)
///
/// Returns something like: "2x ₹500, 1x ₹100, 3x ₹10, 1x ₹5, 2x ₹2"
pub fn wallet_breakdown(tokens: &[TokenEntry]) -> String {
    let mut counts: std::collections::BTreeMap<u32, u32> = std::collections::BTreeMap::new();

    for t in tokens.iter().filter(|t| t.status == TokenStatus::Unspent) {
        *counts.entry(t.denomination).or_insert(0) += 1;
    }

    // Sort by denomination descending
    counts
        .iter()
        .rev()
        .map(|(denom, count)| format!("{}x ₹{}", count, denom))
        .collect::<Vec<_>>()
        .join(", ")
}

// =============================================================================
// TESTS
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(id: &str, denom: u32) -> TokenEntry {
        TokenEntry {
            token_id: id.to_string(),
            denomination: denom,
            rbi_signature: vec![0xAB; 64], // Dummy signature
            status: TokenStatus::Unspent,
        }
    }

    #[test]
    fn test_exact_match_511() {
        // Wallet: 1x500, 1x50, 1x10, 2x1
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 50),
            make_token("t3", 10),
            make_token("t4", 1),
            make_token("t5", 1),
        ];
        let result = select_utxos(511, &tokens).unwrap();
        assert_eq!(result.method, SettlementMethod::ExactMatch);
        assert_eq!(result.selected_total, 511);
        assert_eq!(result.overpayment, 0);
        // Should select: 500 + 10 + 1
        let selected_denoms: Vec<u32> = result.selected_tokens.iter().map(|t| t.denomination).collect();
        assert!(selected_denoms.contains(&500));
        assert!(selected_denoms.contains(&10));
        assert!(selected_denoms.contains(&1));
    }

    #[test]
    fn test_bidirectional_swap_overpayment() {
        // Wallet: 1x500, 1x20 only — must overpay for ₹511
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 20),
        ];
        let result = select_utxos(511, &tokens).unwrap();
        assert_eq!(result.method, SettlementMethod::BidirectionalSwap);
        assert_eq!(result.selected_total, 520);
        assert_eq!(result.overpayment, 9);
    }

    #[test]
    fn test_insufficient_balance() {
        let tokens = vec![make_token("t1", 500)];
        let result = select_utxos(1000, &tokens);
        assert!(matches!(result, Err(UtxoError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_zero_amount() {
        let tokens = vec![make_token("t1", 10)];
        let result = select_utxos(0, &tokens);
        assert!(matches!(result, Err(UtxoError::InvalidAmount)));
    }

    #[test]
    fn test_no_unspent_tokens() {
        let tokens = vec![TokenEntry {
            token_id: "t1".to_string(),
            denomination: 500,
            rbi_signature: vec![],
            status: TokenStatus::Spent,
        }];
        let result = select_utxos(100, &tokens);
        assert!(matches!(result, Err(UtxoError::NoUnspentTokens)));
    }

    #[test]
    fn test_exact_match_small_denominations() {
        // Pay ₹7 with exact coins: 5 + 2
        let tokens = vec![
            make_token("t1", 5),
            make_token("t2", 2),
            make_token("t3", 1),
        ];
        let result = select_utxos(7, &tokens).unwrap();
        assert_eq!(result.method, SettlementMethod::ExactMatch);
        assert_eq!(result.selected_total, 7);
    }

    #[test]
    fn test_change_denominations() {
        let change = calculate_change_denominations(9);
        // ₹9 = ₹5 + ₹2 + ₹2
        assert_eq!(change.iter().sum::<u32>(), 9);
        assert_eq!(change, vec![5, 2, 2]);
    }

    #[test]
    fn test_change_denominations_zero() {
        let change = calculate_change_denominations(0);
        assert!(change.is_empty());
    }

    #[test]
    fn test_large_wallet_selection() {
        // Realistic wallet: mixed denominations
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 100),
            make_token("t3", 50),
            make_token("t4", 20),
            make_token("t5", 10),
            make_token("t6", 10),
            make_token("t7", 5),
            make_token("t8", 2),
            make_token("t9", 2),
            make_token("t10", 1),
        ];
        // Pay ₹137  → 100 + 20 + 10 + 5 + 2 = 137
        let result = select_utxos(137, &tokens).unwrap();
        assert_eq!(result.selected_total, 137);
        assert_eq!(result.overpayment, 0);
        assert_eq!(result.method, SettlementMethod::ExactMatch);
    }

    // =========================================================================
    // NEW: PaymentSuggestion tests
    // =========================================================================

    #[test]
    fn test_suggest_exact_match() {
        let tokens = vec![
            make_token("t1", 50),
            make_token("t2", 10),
            make_token("t3", 5),
        ];
        let suggestion = suggest_payment(50, &tokens);
        assert!(suggestion.is_exact_match);
        assert_eq!(suggestion.requested_amount, 50);
        assert_eq!(suggestion.suggested_amount, 50);
        assert_eq!(suggestion.overpayment, 0);
        assert!(suggestion.user_message.contains("Exact match"));
    }

    #[test]
    fn test_suggest_overpay() {
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 20),
        ];
        let suggestion = suggest_payment(511, &tokens);
        assert!(!suggestion.is_exact_match);
        assert_eq!(suggestion.requested_amount, 511);
        assert_eq!(suggestion.suggested_amount, 520);
        assert_eq!(suggestion.overpayment, 9);
        assert!(suggestion.user_message.contains("₹9 back"));
        assert_eq!(suggestion.settlement_method, SettlementMethod::BidirectionalSwap);
    }

    #[test]
    fn test_suggest_insufficient() {
        let tokens = vec![make_token("t1", 100)];
        let suggestion = suggest_payment(500, &tokens);
        assert_eq!(suggestion.suggested_amount, 0);
        assert!(suggestion.user_message.contains("Insufficient"));
    }

    #[test]
    fn test_suggest_empty_wallet() {
        let tokens: Vec<TokenEntry> = vec![];
        let suggestion = suggest_payment(50, &tokens);
        assert!(suggestion.user_message.contains("empty"));
    }

    #[test]
    fn test_wallet_balance() {
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 100),
            TokenEntry {
                token_id: "t3".into(),
                denomination: 50,
                rbi_signature: vec![],
                status: TokenStatus::Spent, // Should NOT count
            },
        ];
        assert_eq!(wallet_balance(&tokens), 600); // 500 + 100, not 650
    }

    #[test]
    fn test_denomination_breakdown_single() {
        let tokens = vec![make_token("t1", 500)];
        assert_eq!(build_denomination_breakdown(&tokens), "₹500 note");
    }

    #[test]
    fn test_denomination_breakdown_multiple() {
        let tokens = vec![
            make_token("t1", 500),
            make_token("t2", 20),
        ];
        assert_eq!(build_denomination_breakdown(&tokens), "₹500 + ₹20");
    }
}
