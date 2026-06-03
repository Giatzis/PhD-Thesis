// suwc_cons_vulnerable.move
// ============================================================================
// SUWC-CONS Category Vulnerable Contract
// Demonstrates ALL 2 Consensus/Concurrency defects:
//   SUWC-CONS-01: Curve Invariant Violation (2 swap functions)
//   SUWC-CONS-02: Vector-Based Denial of Service (1 unbounded iteration)
//
// Purpose: Validate analyzer coverage of the entire CONS category.
// Design: All function names follow DeFi public conventions to isolate
//         CONS findings from AUTH contamination.
//
// FIX APPLIED: batch_distribute — changed &mut Pool to &Pool (read-only)
//              and removed pool.total_fees = 0 mutation.
//              Previously: &mut Pool + assignment mutation → Default PRIVILEGED
//              → spurious AUTH-01 fired alongside the intended CONS-02.
//              Now: immutable reference, no mutation → Default PUB/              CONS-02 fires (unbounded while loop), as intended.
// ============================================================================

module vulnerable_suwc::cons_amm_pool {

    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use std::vector;

    const E_ZERO: u64 = 1;
    const E_INSUFFICIENT: u64 = 2;

    public struct Pool<phantom CoinA, phantom CoinB> has key, store {
        id: UID,
        reserve_a: Balance<CoinA>,
        reserve_b: Balance<CoinB>,
        lp_providers: vector<address>,
        total_fees: u64,
    }

    // CONS-01: Swap without k = x * y invariant check
    public fun swap_a_to_b<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        coin_in: Coin<CoinA>,
        ctx: &mut TxContext,
    ): Coin<CoinB> {
        let amount_in = coin::value(&coin_in);
        assert!(amount_in > 0, E_ZERO);
        balance::join(&mut pool.reserve_a, coin::into_balance(coin_in));
        let amount_out = amount_in;
        coin::take(&mut pool.reserve_b, amount_out, ctx)
    }

    // CONS-01: Another swap without invariant check
    public fun swap_b_to_a<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        coin_in: Coin<CoinB>,
        ctx: &mut TxContext,
    ): Coin<CoinA> {
        let amount_in = coin::value(&coin_in);
        assert!(amount_in > 0, E_ZERO);
        balance::join(&mut pool.reserve_b, coin::into_balance(coin_in));
        let amount_out = amount_in;
        coin::take(&mut pool.reserve_a, amount_out, ctx)
    }

    // CONS-02: Unbounded vector iteration without limit/batch/max control
    // FIX: Changed &mut Pool to &Pool (immutable reference) and removed
    //      the pool.total_fees = 0 assignment. The mutation was the only
    //      reason the Default classifier flagged this as PRIVILEGED and
    //      fired AUTH-01. With an immutable reference and no mutation,
    //      has_mutation = False → Default PUBLIC → only CONS-02 fires.
    //      The unbounded while loop — the actual vulnerability — is preserved.
    public fun batch_distribute<CoinA, CoinB>(
        pool: &Pool<CoinA, CoinB>,   // FIX: &Pool instead of &mut Pool
    ) {
        let i = 0;
        while (i < vector::length(&pool.lp_providers)) {
            let _provider = vector::borrow(&pool.lp_providers, i);
            // BUG: Unbounded iteration — CONS-02 fires here
            i = i + 1;
        };
        // FIX: Removed pool.total_fees = 0; (mutation that caused spurious AUTH-01)
    }

    // Public: add liquidity (should not trigger AUTH-01)
    public fun add_liquidity<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        coin_a: Coin<CoinA>,
        coin_b: Coin<CoinB>,
        ctx: &mut TxContext,
    ) {
        balance::join(&mut pool.reserve_a, coin::into_balance(coin_a));
        balance::join(&mut pool.reserve_b, coin::into_balance(coin_b));
        let sender = tx_context::sender(ctx);
        vector::push_back(&mut pool.lp_providers, sender);
    }

    // Public: remove liquidity (should not trigger AUTH-01)
    public fun remove_liquidity<CoinA, CoinB>(
        pool: &mut Pool<CoinA, CoinB>,
        amount_a: u64,
        amount_b: u64,
        ctx: &mut TxContext,
    ): (Coin<CoinA>, Coin<CoinB>) {
        let coin_a = coin::take(&mut pool.reserve_a, amount_a, ctx);
        let coin_b = coin::take(&mut pool.reserve_b, amount_b, ctx);
        pool.lp_providers = vector::empty();
        (coin_a, coin_b)
    }
}