// ============================================================================
// Typus Finance TLP - Vulnerable Contract Reconstruction
// Based on the October 15, 2025 exploit ($3.44M stolen)
//
// PURPOSE: Demonstrates security pattern ABSENCE that enabled the exploit.
// This is a SIMPLIFIED reconstruction for analyzer demonstration, NOT the
// full Typus codebase. It captures the structural vulnerabilities.
//
// VULNERABILITY SUMMARY:
//   The Typus Finance TLP (Typus Liquidity Pool) contract used a custom
//   oracle for price feeds. The oracle contract had:
//   1. NO authority/capability checks (anyone could call update_price)
//   2. A MISSING assert statement for price validation
//   This allowed the attacker to set arbitrary prices, manipulate token
//   values, and drain funds through swaps at incorrect prices.
//
// MISSING SECURITY PATTERNS:
//   - NO AccessControlPattern: Oracle update had no capability check
//     (no AdminCap/OracleCap guard on price updates)
//   - NO CircuitBreakerPattern: No pause mechanism to halt when
//     anomalous prices detected (had to manually pause all contracts)
//   - Escapability was needed POST-HACK: Contracts had to be redeployed
//     with audited code
// ============================================================================

module typus::tlp_pool;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};

// === Error Constants ===
const E_INSUFFICIENT_BALANCE: u64 = 1;
const E_INVALID_AMOUNT: u64 = 2;
const E_SLIPPAGE_EXCEEDED: u64 = 3;

// === Structs ===

/// Custom Oracle - VULNERABLE: no capability protection
/// VULNERABILITY: Missing AdminCap/OracleCap for price updates
/// In Typus, this was an unaudited custom oracle module
public struct PriceOracle has key, store {
    id: UID,
    // Token prices in USD (scaled by 1e8)
    sui_price: u64,
    usdc_price: u64,
    btc_price: u64,
    eth_price: u64,
    last_update: u64,
    // NOTE: Missing fields that should exist:
    // - oracle_cap: ID              (AccessControlPattern)
    // - min_price_threshold: u64    (validation)
    // - max_price_threshold: u64    (validation)
}

/// TLP (Typus Liquidity Pool) token - represents pool share
public struct TLP has drop {}

/// Liquidity Pool holding multiple assets
/// VULNERABILITY: No pause capability
public struct LiquidityPool<phantom CoinA, phantom CoinB> has key, store {
    id: UID,
    coin_a: Balance<CoinA>,
    coin_b: Balance<CoinB>,
    total_tlp_supply: u64,
    // NOTE: Missing fields that should exist:
    // - is_paused: bool             (CircuitBreakerPattern)
    // - pause_cap: ID               (CircuitBreakerPattern)
}

// === VULNERABLE FUNCTIONS ===

/// Update oracle price - NO AUTHORITY CHECK
/// VULNERABILITY: This is the ROOT CAUSE of the Typus exploit.
/// Anyone can call this function to set arbitrary prices.
/// The original code had NO assert for caller authorization.

public fun update_price(
    oracle: &mut PriceOracle,
    token_id: u8,
    new_price: u64,
) {
    // BUG: No capability check! No OracleCap required!
    // BUG: No price validation! No assert for reasonable ranges!
    // Attacker can set SUI price to 999999999 or 0
    if (token_id == 0) {
        oracle.sui_price = new_price;
    } else if (token_id == 1) {
        oracle.usdc_price = new_price;
    } else if (token_id == 2) {
        oracle.btc_price = new_price;
    } else if (token_id == 3) {
        oracle.eth_price = new_price;
    };
}

/// Get token price from oracle
/// VULNERABILITY: In the original exploit, this query function could
/// also inadvertently modify state (the "flawed query function")
public fun get_price(oracle: &PriceOracle, token_id: u8): u64 {
    if (token_id == 0) {
        oracle.sui_price
    } else if (token_id == 1) {
        oracle.usdc_price
    } else if (token_id == 2) {
        oracle.btc_price
    } else {
        oracle.eth_price
    }
}

/// Swap tokens using oracle price - NO PAUSE CHECK
/// VULNERABILITY: Uses manipulatable oracle prices for swap calculation
/// Attacker flow: 1) update_price to inflate SUI, 2) swap cheap USDC for SUI
public fun swap<CoinA, CoinB>(
    pool: &mut LiquidityPool<CoinA, CoinB>,
    oracle: &PriceOracle,
    coin_in: Coin<CoinA>,
    token_in_id: u8,
    token_out_id: u8,
    min_amount_out: u64,
    ctx: &mut TxContext,
): Coin<CoinB> {
    // NO PAUSE CHECK: pool has no is_paused field
    // In a secure version:
    //   assert!(!pool.is_paused, E_POOL_PAUSED);

    let amount_in = coin::value(&coin_in);
    assert!(amount_in > 0, E_INVALID_AMOUNT);

    // Get prices from MANIPULATABLE oracle
    let price_in = get_price(oracle, token_in_id);
    let price_out = get_price(oracle, token_out_id);

    // Calculate output based on oracle prices
    // With manipulated prices, attacker gets far more than fair value
    let value_in = (amount_in as u128) * (price_in as u128);
    let amount_out = ((value_in / (price_out as u128)) as u64);

    assert!(amount_out >= min_amount_out, E_SLIPPAGE_EXCEEDED);

    // Accept input
    balance::join(&mut pool.coin_a, coin::into_balance(coin_in));

    // Return output at manipulated rate
    coin::take(&mut pool.coin_b, amount_out, ctx)
}

/// Add liquidity to pool - NO ACCESS CONTROL
public fun add_liquidity<CoinA, CoinB>(
    pool: &mut LiquidityPool<CoinA, CoinB>,
    coin_a: Coin<CoinA>,
    coin_b: Coin<CoinB>,
) {
    // No capability check on who can add liquidity
    balance::join(&mut pool.coin_a, coin::into_balance(coin_a));
    balance::join(&mut pool.coin_b, coin::into_balance(coin_b));
    pool.total_tlp_supply = pool.total_tlp_supply + 1;
}

/// Remove liquidity from pool - NO ACCESS CONTROL
public fun remove_liquidity<CoinA, CoinB>(
    pool: &mut LiquidityPool<CoinA, CoinB>,
    amount_a: u64,
    amount_b: u64,
    ctx: &mut TxContext,
): (Coin<CoinA>, Coin<CoinB>) {
    // No capability check, no pause check
    let coin_a = coin::take(&mut pool.coin_a, amount_a, ctx);
    let coin_b = coin::take(&mut pool.coin_b, amount_b, ctx);
    pool.total_tlp_supply = pool.total_tlp_supply - 1;
    (coin_a, coin_b)
}