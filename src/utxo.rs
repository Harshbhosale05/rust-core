// =============================================================================
// A-SPARSH SD-SE: Smart UTXO Coin Selection Engine
// =============================================================================
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

/// Represents a single digital token in the local wallet
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEntry {
    pub token_id: String,
    pub denomination: u32,
    pub status: TokenStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenStatus {
    Unspent,
    Pending,
    Spent,
    /// Frozen: partial spend occurred, remainder awaits online reconciliation
    Frozen,
}

/// Result of the UTXO selection algorithm
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

/// Smart UTXO Coin Selection Algorithm
///
/// Selects the optimal combination of digital tokens to pay an exact amount.
/// Uses a greedy approach: largest denominations first, minimizing token count
/// (and therefore minimizing the number of hardware key burns).
///
/// # Settlement Methods
///
/// 1. **ExactMatch**: The greedy algorithm finds exact denominations.
///    Example: Pay ₹511 with [₹500, ₹10, ₹1] — perfect.
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

/// Calculate the optimal change denominations for a Bidirectional Swap.
///
/// Given an overpayment of ₹9, returns the token set needed:
/// e.g., [₹5, ₹2, ₹2] or [₹5, ₹2, ₹1, ₹1]
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
}
