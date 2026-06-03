// ============================================================================
// Secure DeFi Vault — Sui Move Contract with All 4 Security Design Patterns
//
// This contract demonstrates a well-designed DeFi vault that implements
// all 4 security patterns from the ontology:
//   1. AccessControlPattern  — AdminCap capability-based authorization
//   2. CircuitBreakerPattern — DenyCapV2 pause/unpause mechanism
//   3. TimeIncentivizationPattern — Clock-based vesting schedule
//   4. EscapabilityPattern   — UpgradeCap for contract upgradeability
// ============================================================================

module defi::secure_vault;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::clock::Clock;
use sui::sui::SUI;

// === Error Constants ===
const E_NOT_AUTHORIZED: u64 = 1;
const E_VAULT_PAUSED: u64 = 2;
const E_VESTING_NOT_STARTED: u64 = 3;
const E_NOTHING_TO_CLAIM: u64 = 4;
const E_INSUFFICIENT_BALANCE: u64 = 5;

// === PATTERN 1: Access Control — AdminCap ===

/// AdminCap — Capability granting administrative access to the vault
public struct AdminCap has key, store {
    id: UID,
    vault_id: ID,
}

// === PATTERN 2: Circuit Breaker — DenyCapV2 ===

/// DenyCapV2 — Capability for pausing/unpausing vault operations
public struct DenyCapV2 has key, store {
    id: UID,
    vault_id: ID,
}

// === Core Vault Struct ===

/// SecureVault — holds funds with all 4 security mechanisms
public struct SecureVault has key, store {
    id: UID,
    balance: Balance<SUI>,
    is_paused: bool,
    total_deposited: u64,
}

// === PATTERN 3: Time Incentivization — Vesting ===

/// VestingSchedule — time-locked token release using Clock
public struct VestingSchedule has key, store {
    id: UID,
    vault_id: ID,
    beneficiary: address,
    total_amount: u64,
    claimed: u64,
    start_time: u64,
    duration: u64,
}

// === PATTERN 4: Escapability — UpgradeCap ===

/// UpgradeCap — Capability for upgrading the vault contract
public struct UpgradeCap has key, store {
    id: UID,
    vault_id: ID,
    version: u64,
    policy: u8,
}

/// UpgradeTicket — Authorization for a specific upgrade
public struct UpgradeTicket {
    cap_id: ID,
    vault_id: ID,
    policy: u8,
    digest: vector<u8>,
}

/// UpgradeReceipt — Proof that an upgrade was applied
public struct UpgradeReceipt {
    cap_id: ID,
    vault_id: ID,
}

// =====================================================
// PATTERN 1: AccessControlPattern — Protected Functions
// =====================================================

/// Create a new vault with AdminCap (PROTECTED: requires creator context)
public fun create_vault(ctx: &mut TxContext): (SecureVault, AdminCap, DenyCapV2) {
    let vault_id_obj = object::new(ctx);
    let vault_id = vault_id_obj.to_inner();
    let vault = SecureVault {
        id: vault_id_obj,
        balance: balance::zero(),
        is_paused: false,
        total_deposited: 0,
    };
    let admin_cap = AdminCap {
        id: object::new(ctx),
        vault_id,
    };
    let deny_cap = DenyCapV2 {
        id: object::new(ctx),
        vault_id,
    };
    (vault, admin_cap, deny_cap)
}

/// Deposit funds — PROTECTED by AdminCap
public fun deposit(
    vault: &mut SecureVault,
    cap: &AdminCap,
    coin: Coin<SUI>,
) {
    assert!(object::id(vault) == cap.vault_id, E_NOT_AUTHORIZED);
    assert!(!vault.is_paused, E_VAULT_PAUSED);
    let amount = coin::value(&coin);
    balance::join(&mut vault.balance, coin::into_balance(coin));
    vault.total_deposited = vault.total_deposited + amount;
}

/// Withdraw funds — PROTECTED by AdminCap
public fun withdraw(
    vault: &mut SecureVault,
    cap: &AdminCap,
    amount: u64,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(object::id(vault) == cap.vault_id, E_NOT_AUTHORIZED);
    assert!(!vault.is_paused, E_VAULT_PAUSED);
    assert!(vault.balance.value() >= amount, E_INSUFFICIENT_BALANCE);
    coin::take(&mut vault.balance, amount, ctx)
}

// =====================================================
// PATTERN 2: CircuitBreakerPattern — Pause/Unpause
// =====================================================

/// Pause vault — PROTECTED by DenyCapV2 (Circuit Breaker)
public fun pause_vault(
    vault: &mut SecureVault,
    cap: &DenyCapV2,
) {
    assert!(object::id(vault) == cap.vault_id, E_NOT_AUTHORIZED);
    vault.is_paused = true;
}

/// Unpause vault — PROTECTED by DenyCapV2 (Circuit Breaker)
public fun unpause_vault(
    vault: &mut SecureVault,
    cap: &DenyCapV2,
) {
    assert!(object::id(vault) == cap.vault_id, E_NOT_AUTHORIZED);
    vault.is_paused = false;
}

// =====================================================
// PATTERN 3: TimeIncentivizationPattern — Vesting
// =====================================================

/// Create vesting schedule — PROTECTED by AdminCap, uses Clock
public fun create_vesting(
    vault: &SecureVault,
    cap: &AdminCap,
    clock: &Clock,
    beneficiary: address,
    total_amount: u64,
    duration: u64,
    ctx: &mut TxContext,
): VestingSchedule {
    assert!(object::id(vault) == cap.vault_id, E_NOT_AUTHORIZED);
    let start_time = clock.timestamp_ms();
    VestingSchedule {
        id: object::new(ctx),
        vault_id: cap.vault_id,
        beneficiary,
        total_amount,
        claimed: 0,
        start_time,
        duration,
    }
}

/// Claim vested tokens — uses Clock for time verification
public fun claim_vested(
    vault: &mut SecureVault,
    schedule: &mut VestingSchedule,
    clock: &Clock,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(!vault.is_paused, E_VAULT_PAUSED);
    let now = clock.timestamp_ms();
    assert!(now >= schedule.start_time, E_VESTING_NOT_STARTED);

    let elapsed = now - schedule.start_time;
    let vested = if (elapsed >= schedule.duration) {
        schedule.total_amount
    } else {
        (schedule.total_amount * elapsed) / schedule.duration
    };
    let claimable = vested - schedule.claimed;
    assert!(claimable > 0, E_NOTHING_TO_CLAIM);

    schedule.claimed = schedule.claimed + claimable;
    coin::take(&mut vault.balance, claimable, ctx)
}

// =====================================================
// PATTERN 4: EscapabilityPattern — Upgrade Mechanism
// =====================================================

/// Authorize upgrade — PROTECTED by UpgradeCap
public fun authorize_upgrade(
    cap: &mut UpgradeCap,
    policy: u8,
    digest: vector<u8>,
): UpgradeTicket {
    UpgradeTicket {
        cap_id: cap.id.to_inner(),
        vault_id: cap.vault_id,
        policy,
        digest,
    }
}

/// Commit upgrade — finalize with UpgradeCap and receipt
public fun commit_upgrade(
    cap: &mut UpgradeCap,
    receipt: UpgradeReceipt,
) {
    let UpgradeReceipt { cap_id, vault_id: _ } = receipt;
    assert!(cap.id.to_inner() == cap_id, E_NOT_AUTHORIZED);
    cap.version = cap.version + 1;
}

/// Make immutable — permanently prevent upgrades
public entry fun make_immutable(cap: UpgradeCap) {
    let UpgradeCap { id, vault_id: _, version: _, policy: _ } = cap;
    id.delete();
}
