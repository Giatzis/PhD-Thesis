// Source: sui::transfer_policy (Official Sui Framework)
// Pattern: AccessControlPattern - TransferPolicyCap capability-based access control
// Extract: Only capability struct and protected operations

module sui::transfer_policy;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::dynamic_field as df;
use sui::event;
use sui::package::{Self, Publisher};
use sui::sui::SUI;
use sui::vec_set::{Self, VecSet};

const ENotOwner: u64 = 4;
const ENotEnough: u64 = 5;
const ERuleAlreadySet: u64 = 3;

/// TransferPolicy - customizable primitive for transfer rules
public struct TransferPolicy<phantom T> has key, store {
    id: UID,
    balance: Balance<SUI>,
    rules: VecSet<TypeName>,
}

/// TransferPolicyCap - Capability granting permission to manage TransferPolicy
public struct TransferPolicyCap<phantom T> has key, store {
    id: UID,
    policy_id: ID,
}

public struct RuleKey<phantom T: drop> has copy, drop, store {}

/// Create new TransferPolicy + TransferPolicyCap (requires Publisher capability)
public fun new<T>(pub: &Publisher, ctx: &mut TxContext): (TransferPolicy<T>, TransferPolicyCap<T>) {
    assert!(package::from_package<T>(pub), 0);
    let id = object::new(ctx);
    let policy_id = id.to_inner();
    (
        TransferPolicy { id, rules: vec_set::empty(), balance: balance::zero() },
        TransferPolicyCap { id: object::new(ctx), policy_id },
    )
}

/// Withdraw profits - PROTECTED by TransferPolicyCap
public fun withdraw<T>(
    self: &mut TransferPolicy<T>,
    cap: &TransferPolicyCap<T>,
    amount: Option<u64>,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(object::id(self) == cap.policy_id, ENotOwner);
    let amount = if (amount.is_some()) {
        let amt = amount.destroy_some();
        assert!(amt <= self.balance.value(), ENotEnough);
        amt
    } else {
        self.balance.value()
    };
    coin::take(&mut self.balance, amount, ctx)
}

/// Add rule - PROTECTED by TransferPolicyCap
public fun add_rule<T, Rule: drop, Config: store + drop>(
    _: Rule,
    policy: &mut TransferPolicy<T>,
    cap: &TransferPolicyCap<T>,
    cfg: Config,
) {
    assert!(object::id(policy) == cap.policy_id, ENotOwner);
    df::add(&mut policy.id, RuleKey<Rule> {}, cfg);
}

/// Remove rule - PROTECTED by TransferPolicyCap
public fun remove_rule<T, Rule: drop, Config: store + drop>(
    policy: &mut TransferPolicy<T>,
    cap: &TransferPolicyCap<T>,
) {
    assert!(object::id(policy) == cap.policy_id, ENotOwner);
    let _: Config = df::remove(&mut policy.id, RuleKey<Rule> {});
}
