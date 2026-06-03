
// ============================================================================
// VULNERABLE CONTRACT 4: Escapability Vulnerabilities
// Demonstrates: SUWC-AUTH-02 on custom cap + SUWC-RES-01 + SUWC-RES-02 + SUWC-RES-03
// Pattern: EscapabilityPattern (misuse)
// ============================================================================

module vulnerable::upgradeable_vault;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::transfer;

const E_NOT_AUTHORIZED: u64 = 1;
const E_WRONG_VERSION: u64 = 2;

// AUTH-02: Custom upgrade capability with store (leakable)
public struct VaultUpgradeCap has key, store {
    id: UID,
    vault_id: ID,
    version: u64,
}

// AUTH-02: Migration capability with both store and copy (leakable)
public struct MigrationAuthCap has key, store, copy {
    id: UID,
    vault_id: ID,
}

// RES-01: Hot potato Receipt struct with 'drop' ability
// BUG: Receipt should NOT have drop — enforces upgrade completion
public struct UpgradeReceipt has drop {
    vault_id: ID,
    new_version: u64,
}

// RES-02: Wrapper struct without unwrap function
// BUG: Once assets are wrapped for migration, they cannot be recovered
public struct MigrationWrapper has key, store {
    id: UID,
    balance: Balance<SUI>,
    source_version: u64,
}

public struct Vault has key, store {
    id: UID,
    balance: Balance<SUI>,
    version: u64,
}

// Authorize upgrade — issues a receipt (hot potato)
public fun authorize_upgrade(
    cap: &mut VaultUpgradeCap,
): UpgradeReceipt {
    cap.version = cap.version + 1;
    UpgradeReceipt {
        vault_id: cap.vault_id,
        new_version: cap.version,
    }
}

// Commit upgrade using receipt
public fun commit_upgrade(
    vault: &mut Vault,
    receipt: UpgradeReceipt,
) {
    let UpgradeReceipt { vault_id: _, new_version } = receipt;
    vault.version = new_version;
}

// Wrap assets for migration — AUTH-01 VULNERABLE (no cap check)
public fun wrap_for_migration(
    vault: &mut Vault,
    amount: u64,
    _ctx: &mut TxContext,   // ctx no longer needed; kept for API stability
): MigrationWrapper {
    // FIX: Pure outflow — balance::split produces no inflow signal.
    //      No capability check = the vulnerability (AUTH-01) remains intact.
    let inner = balance::split(&mut vault.balance, amount);
    MigrationWrapper {
        id: object::new(_ctx),
        balance: inner,
        source_version: vault.version,
    }
}

// Destroy old vault (residual balance must be zero)
public fun burn_old_vault(vault: Vault) {
    let Vault { id, balance, version: _ } = vault;
    balance::destroy_zero(balance);
    id.delete();
}

// Deposit into vault
public fun deposit(vault: &mut Vault, coin: Coin<SUI>) {
    balance::join(&mut vault.balance, coin::into_balance(coin));
}

// RES-03: Transfer to burn address — permanent asset lock
public fun send_to_burn(wrapper: MigrationWrapper) {
    transfer::public_transfer(wrapper, @0x0);
}