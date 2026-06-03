// suwc_auth_vulnerable.move
// ============================================================================
// SUWC-AUTH Category Vulnerable Contract
// Demonstrates ALL 4 Authorization defects:
//   SUWC-AUTH-01: Missing Signer Check (4 functions)
//   SUWC-AUTH-02: Capability Leakage (2 structs)
//   SUWC-AUTH-03: Witness Pattern Violation (init function)
//   SUWC-AUTH-04: Shared Object Permission Bypass (4 functions)
//
// Purpose: Validate analyzer coverage of the entire AUTH category.
// FIX APPLIED: emergency_withdraw — changed from returning Coin<SUI> to
//              draining to treasury.admin address. This ensures the function
//              is NOT caught by Layer 2 (return type Coin → PUBLIC) of the
//              behavioral classifier, so AUTH-01 fires correctly.
// ============================================================================

module vulnerable_suwc::auth_governance {

    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;

    const E_NOT_ENOUGH: u64 = 1;

    // AUTH-02: Capability with store + copy (leakable AND duplicable)
    public struct GovernanceCap has key, store, copy {
        id: UID,
        governance_id: ID,
    }

    // AUTH-02: Capability with store (transferable to unauthorized parties)
    public struct TreasuryAuthCap has key, store {
        id: UID,
    }

    public struct Treasury has key, store {
        id: UID,
        funds: Balance<SUI>,
        admin: address,
        fee_rate: u64,
        is_active: bool,
    }

    public struct Proposal has key, store {
        id: UID,
        description: vector<u8>,
        votes: u64,
    }

    // AUTH-03: One-Time-Witness passed by reference (should be consumed by value)
    fun init(witness: &AUTH_GOVERNANCE, ctx: &mut TxContext) {
        let treasury = Treasury {
            id: object::new(ctx),
            funds: balance::zero(),
            admin: tx_context::sender(ctx),
            fee_rate: 100,
            is_active: true,
        };
        transfer::share_object(treasury);
    }

    // AUTH-01 + AUTH-04: Privileged — modifies fee rate without capability
    public fun set_fee_rate(
        treasury: &mut Treasury,
        new_rate: u64,
    ) {
        treasury.fee_rate = new_rate;
    }

    // AUTH-01 + AUTH-04: Privileged — drains treasury without capability
    // FIX: Changed return type from Coin<SUI> to void, draining to treasury.admin.
    //      Previously: returned Coin<SUI> → Layer 2 of behavioral classifier
    //      classified this as PUBLIC → AUTH-01 was never fired (false negative).
    //      Now: pure outflow with no return and no transfer-to-sender
    //      → no behavioral PUBLIC signal → Default PRIVILEGED → AUTH-01 fires.
    public fun emergency_withdraw(
        treasury: &mut Treasury,
        amount: u64,
        ctx: &mut TxContext,
    ) {
        assert!(treasury.funds.value() >= amount, E_NOT_ENOUGH);
        let coin = coin::take(&mut treasury.funds, amount, ctx);
        // Drains to the stored admin address — not tx_context::sender
        // This preserves the vulnerability (no cap check) while making
        // the behavioral pattern unambiguous for the classifier.
        transfer::public_transfer(coin, treasury.admin);
    }

    // AUTH-01 + AUTH-04: Privileged — toggles active state without capability
    public fun pause_treasury(
        treasury: &mut Treasury,
    ) {
        treasury.is_active = !treasury.is_active;
    }

    // AUTH-01 + AUTH-04: Privileged — changes admin without capability
    public fun update_admin(
        treasury: &mut Treasury,
        new_admin: address,
    ) {
        treasury.admin = new_admin;
    }

    // PUBLIC function — should NOT be flagged as AUTH-01
    public fun deposit(
        treasury: &mut Treasury,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut treasury.funds, coin::into_balance(coin));
    }
}