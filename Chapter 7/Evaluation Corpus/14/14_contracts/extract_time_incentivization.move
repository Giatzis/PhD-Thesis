// Source: vesting::linear (Official Sui Framework)
// Pattern: TimeIncentivizationPattern - Clock-based linear vesting
// Extract: Complete module (already focused on time pattern)

module vesting::linear;

use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};

#[error]
const EInvalidStartTime: vector<u8> = b"Start time must be in the future.";

/// Wallet - time-locked vesting schedule
public struct Wallet<phantom T> has key, store {
    id: UID,
    balance: Balance<T>,
    start: u64,
    claimed: u64,
    duration: u64,
}

/// Create new wallet with vesting schedule - TIME INCENTIVIZATION: requires Clock
public fun new_wallet<T>(
    coins: Coin<T>,
    clock: &Clock,
    start: u64,
    duration: u64,
    ctx: &mut TxContext,
): Wallet<T> {
    assert!(start > clock.timestamp_ms(), EInvalidStartTime);
    Wallet {
        id: object::new(ctx),
        balance: coins.into_balance(),
        start,
        claimed: 0,
        duration,
    }
}

/// Claim available coins - TIME INCENTIVIZATION: time-gated by Clock
public fun claim<T>(self: &mut Wallet<T>, clock: &Clock, ctx: &mut TxContext): Coin<T> {
    let claimable_amount = self.claimable(clock);
    self.claimed = self.claimed + claimable_amount;
    coin::from_balance(self.balance.split(claimable_amount), ctx)
}

/// Calculate claimable amount - TIME INCENTIVIZATION: linear schedule via Clock
public fun claimable<T>(self: &Wallet<T>, clock: &Clock): u64 {
    let timestamp = clock.timestamp_ms();
    if (timestamp < self.start) return 0;
    if (timestamp >= self.start + self.duration) return self.balance.value();
    let elapsed = timestamp - self.start;
    let claimable: u128 =
        (self.balance.value() + self.claimed as u128) * (elapsed as u128) / (self.duration as u128);
    (claimable as u64) - self.claimed
}
