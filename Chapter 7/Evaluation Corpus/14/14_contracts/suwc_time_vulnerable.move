// ============================================================================
// SUWC-TIME Category Vulnerable Contract
// Demonstrates ALL 4 Temporal Correctness defects:
//   SUWC-TIME-01: Premature Release (3 functions without time checks)
//   SUWC-TIME-02: Indefinite Lock (1 lock without unlock mechanism)
//   SUWC-TIME-03: Unsafe Timestamp (4 functions using timestamp_ms w/o assert)
//   SUWC-TIME-04: Race Between Time Conditions (1 function with dual reads)
//
// Purpose: Validate analyzer coverage of the entire TIME category.
// Design: Inline authorization (assert sender == owner) used on privileged
//         functions to prevent AUTH contamination.
// ============================================================================

module vulnerable_suwc::time_vesting {

    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::clock::{Self, Clock};
    use sui::sui::SUI;

    const E_INSUFFICIENT: u64 = 1;
    const E_NOT_OWNER: u64 = 2;

    // Struct with temporal fields (establishes temporal context for TIME-01)
    public struct VestingVault has key, store {
        id: UID,
        funds: Balance<SUI>,
        owner: address,
        vesting_start: u64,
        duration: u64,
    }

    // TIME-02 setup: Pool with NO unlock_time / timeout / deadline field
    public struct RewardPool has key, store {
        id: UID,
        rewards: Balance<SUI>,
    }

    public struct StakePosition has key, store {
        id: UID,
        staker: address,
        amount: u64,
        start_time: u64,
    }

    // Establishes temporal context (Clock param + timestamp usage)
    public fun create_vault(
        coin: Coin<SUI>,
        clock: &Clock,
        duration: u64,
        ctx: &mut TxContext,
    ): VestingVault {
        VestingVault {
            id: object::new(ctx),
            funds: coin::into_balance(coin),
            owner: tx_context::sender(ctx),
            vesting_start: clock::timestamp_ms(clock),
            duration,
        }
    }

    // TIME-01: Claim without time verification (temporal context exists)
    public fun claim_rewards(
        vault: &mut VestingVault,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let reward = 100;
        coin::take(&mut vault.funds, reward, ctx)
    }

    // TIME-01: Withdraw with inline auth but NO time check
    public fun withdraw_vested(
        vault: &mut VestingVault,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let sender = tx_context::sender(ctx);
        assert!(sender == vault.owner, E_NOT_OWNER);
        coin::take(&mut vault.funds, amount, ctx)
    }

    // TIME-01: Release with inline auth but NO time check
    public fun release_tokens(
        vault: &mut VestingVault,
        amount: u64,
        ctx: &mut TxContext,
    ): Coin<SUI> {
        let sender = tx_context::sender(ctx);
        assert!(sender == vault.owner, E_NOT_OWNER);
        coin::take(&mut vault.funds, amount, ctx)
    }

    // TIME-02: Lock function — no unlock_time or deadline in any struct
    public fun lock_rewards(
        pool: &mut RewardPool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.rewards, coin::into_balance(coin));
    }

    // TIME-03: Uses timestamp_ms without safety assertion
    public fun stake(
        pool: &mut RewardPool,
        coin: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext,
    ): StakePosition {
        let amount = coin::value(&coin);
        balance::join(&mut pool.rewards, coin::into_balance(coin));
        StakePosition {
            id: object::new(ctx),
            staker: tx_context::sender(ctx),
            amount,
            start_time: clock::timestamp_ms(clock),
        }
    }

    // TIME-03: Another function using timestamp without assertion
    public fun check_elapsed(
        position: &StakePosition,
        clock: &Clock,
    ): u64 {
        let current = clock::timestamp_ms(clock);
        current - position.start_time
    }

    // TIME-03 + TIME-04: Multiple timestamp reads (race condition)
    public fun compound_and_restake(
        position: &mut StakePosition,
        clock: &Clock,
    ): u64 {
        let time1 = clock::timestamp_ms(clock);
        let elapsed = time1 - position.start_time;
        let reward = (position.amount * elapsed) / 1000;
        let time2 = clock::timestamp_ms(clock);
        let bonus = time2 - time1;
        position.amount = position.amount + reward;
        reward + bonus
    }
}
