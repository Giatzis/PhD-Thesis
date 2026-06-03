// ============================================================================
// VULNERABLE CONTRACT 2: Circuit Breaker Vulnerabilities
// Demonstrates: Missing pause mechanism + SUWC-CONS-01 + SUWC-CONS-02
// Pattern: CircuitBreakerPattern (absence)
// ============================================================================

module vulnerable::dex_pool;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use std::vector;

const E_ZERO_AMOUNT: u64 = 1;
const E_INSUFFICIENT: u64 = 2;

public struct Pool<phantom CoinA, phantom CoinB> has key, store {
    id: UID,
    reserve_a: Balance<CoinA>,
    reserve_b: Balance<CoinB>,
    lp_supply: u64,
    lp_providers: vector<address>,  // Used by distribute_fees (CONS-02)
    // MISSING: is_paused: bool       (CircuitBreakerPattern)
    // MISSING: deny_cap: ID          (CircuitBreakerPattern)
}

// CONS-01: Swap without curve invariant check (k = x * y)
// BUG: No assert! checking the constant product formula
public fun swap_a_to_b<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    coin_in: Coin<CoinA>,
    ctx: &mut TxContext,
): Coin<CoinB> {
    // NO PAUSE CHECK - cannot halt during exploit
    let amount_in = coin::value(&coin_in);
    assert!(amount_in > 0, E_ZERO_AMOUNT);

    balance::join(&mut pool.reserve_a, coin::into_balance(coin_in));

    // BUG: Simple calculation without invariant verification
    // Should check: assert!(new_reserve_a * new_reserve_b >= k, E_INVARIANT);
    let amount_out = amount_in;
    coin::take(&mut pool.reserve_b, amount_out, ctx)
}

// CONS-01: Another swap without invariant check
public fun swap_b_to_a<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    coin_in: Coin<CoinB>,
    ctx: &mut TxContext,
): Coin<CoinA> {
    // NO PAUSE CHECK
    let amount_in = coin::value(&coin_in);
    assert!(amount_in > 0, E_ZERO_AMOUNT);

    balance::join(&mut pool.reserve_b, coin::into_balance(coin_in));
    let amount_out = amount_in;
    coin::take(&mut pool.reserve_a, amount_out, ctx)
}

// AUTH-01 + no pause: Add liquidity without capability or pause check
public fun add_liquidity<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    coin_a: Coin<CoinA>,
    coin_b: Coin<CoinB>,
) {
    // NO PAUSE CHECK - pool cannot be halted
    balance::join(&mut pool.reserve_a, coin::into_balance(coin_a));
    balance::join(&mut pool.reserve_b, coin::into_balance(coin_b));
    pool.lp_supply = pool.lp_supply + 1;
}

// Drain function: no capability, no pause, no invariant
public fun remove_liquidity<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
    amount_a: u64,
    amount_b: u64,
    ctx: &mut TxContext,
): (Coin<CoinA>, Coin<CoinB>) {
    // NO PAUSE CHECK
    let coin_a = coin::take(&mut pool.reserve_a, amount_a, ctx);
    let coin_b = coin::take(&mut pool.reserve_b, amount_b, ctx);
    pool.lp_supply = pool.lp_supply - 1;
    (coin_a, coin_b)
}

// MISSING: Pause / Unpause functions
// A secure implementation would include:
//
// public fun pause_pool<CoinA, CoinB>(
//     pool: &mut Pool<CoinA, CoinB>,
//     _cap: &DenyCapV2,
// ) { pool.is_paused = true; }

// CONS-02: Unbounded vector iteration without pagination or gas limits
// BUG: Iterates over all LP providers without batch_size or limit control
// An attacker can inflate the provider list, causing gas exhaustion
public fun distribute_fees<CoinA, CoinB>(
    pool: &mut Pool<CoinA, CoinB>,
) {
    let i = 0;
    while (i < vector::length(&pool.lp_providers)) {
        let _provider = vector::borrow(&pool.lp_providers, i);
        // In production: would send proportional fees to each provider
        i = i + 1;
    };
}
