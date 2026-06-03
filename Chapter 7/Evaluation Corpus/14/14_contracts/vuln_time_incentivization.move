// ============================================================================
// VULNERABLE CONTRACT 3: Time Incentivization Vulnerabilities
// Demonstrates: SUWC-TIME-01, SUWC-TIME-02, SUWC-TIME-03, SUWC-TIME-04
// Pattern: TimeIncentivizationPattern (misuse)
// ============================================================================

module vulnerable::staking;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::clock::Clock;
use sui::sui::SUI;

const E_INSUFFICIENT: u64 = 1;

// TIME-02 setup: Staking struct with lock but NO unlock mechanism
public struct StakingPool has key, store {
    id: UID,
    total_staked: Balance<SUI>,
    reward_rate: u64,
    // MISSING: unlock_time, timeout, or deadline field
}

// Stake position - has temporal context
public struct StakePosition has key, store {
    id: UID,
    amount: u64,
    start_time: u64,
    duration: u64,
}

// Create stake with Clock (establishes temporal context)
public fun stake(
    pool: &mut StakingPool,
    coin: Coin<SUI>,
    clock: &Clock,
    duration: u64,
    ctx: &mut TxContext,
): StakePosition {
    let amount = coin::value(&coin);
    balance::join(&mut pool.total_staked, coin::into_balance(coin));
    StakePosition {
        id: object::new(ctx),
        amount,
        start_time: clock::timestamp_ms(clock),
        duration,
    }
}

// TIME-01: Claim function WITHOUT time verification
// BUG: Allows premature withdrawal — no check if vesting period elapsed
public fun claim(
    pool: &mut StakingPool,
    position: &mut StakePosition,
    ctx: &mut TxContext,
): Coin<SUI> {
    // BUG: No Clock parameter, no timestamp check!
    // Should verify: current_time >= position.start_time + position.duration
    let reward = position.amount * 10 / 100;
    coin::take(&mut pool.total_staked, reward, ctx)
}

// TIME-01: Withdraw function WITHOUT time verification
// BUG: Allows instant unstaking, defeating the lock purpose
public fun withdraw(
    pool: &mut StakingPool,
    position: StakePosition,
    ctx: &mut TxContext,
): Coin<SUI> {
    // BUG: No time check! Staker can withdraw immediately
    let StakePosition { id, amount, start_time: _, duration: _ } = position;
    id.delete();
    coin::take(&mut pool.total_staked, amount, ctx)
}

// TIME-02: Lock function without unlock mechanism
// BUG: Assets can be locked but there's no unlock_time or deadline
public fun lock_rewards(
    pool: &mut StakingPool,
    coin: Coin<SUI>,
) {
    // Locks rewards but no way to unlock them (no timeout/deadline)
    balance::join(&mut pool.total_staked, coin::into_balance(coin));
}

// TIME-03: Uses timestamp_ms without safety assertions
// BUG: Raw timestamp usage without assert! validation
public fun calculate_rewards(
    position: &StakePosition,
    clock: &Clock,
): u64 {
    let current = clock::timestamp_ms(clock);
    let elapsed = current - position.start_time;
    // BUG: No assert!(current >= position.start_time) safety check
    // If clock is manipulated, elapsed could underflow
    (position.amount * elapsed * 10) / (365 * 24 * 60 * 60 * 1000)
}

// TIME-04: Multiple timestamp reads (race condition risk)
public fun compound_rewards(
    position: &mut StakePosition,
    clock: &Clock,
): u64 {
    let time_a = clock::timestamp_ms(clock);
    let elapsed = time_a - position.start_time;
    let reward = (position.amount * elapsed) / 1000;
    // BUG: Second timestamp read — value could differ
    let time_b = clock::timestamp_ms(clock);
    let bonus = time_b - time_a;
    position.amount = position.amount + reward;
    reward + bonus
}

// TIME-01: Release function without time check
public fun release(
    pool: &mut StakingPool,
    amount: u64,
    ctx: &mut TxContext,
): Coin<SUI> {
    // BUG: No temporal guard on release
    coin::take(&mut pool.total_staked, amount, ctx)
}
