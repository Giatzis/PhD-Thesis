// Source: sui::package (Official Sui Framework)
// Pattern: EscapabilityPattern - UpgradeCap upgrade mechanism
// Extract: Only UpgradeCap struct and upgrade-related operations

module sui::package;

/// UpgradeCap - Capability for authorizing package upgrades (Escapability)
public struct UpgradeCap has key, store {
    id: UID,
    package: ID,
    version: u64,
    policy: u8,
}

/// UpgradeTicket - Authorization ticket for a specific upgrade
public struct UpgradeTicket {
    cap: ID,
    package: ID,
    policy: u8,
    digest: vector<u8>,
}

/// UpgradeReceipt - Proof that upgrade was completed
public struct UpgradeReceipt {
    cap: ID,
    package: ID,
}

/// Authorize upgrade - ESCAPABILITY: issue upgrade ticket with UpgradeCap
public fun authorize_upgrade(
    cap: &mut UpgradeCap,
    policy: u8,
    digest: vector<u8>,
): UpgradeTicket {
    let id_zero = @0x0.to_id();
    assert!(._policy_valid(cap.policy, policy));
    UpgradeTicket {
        cap: cap.id.to_inner(),
        package: cap.package,
        policy,
        digest,
    }
}

/// Commit upgrade - ESCAPABILITY: finalize upgrade with receipt
public fun commit_upgrade(cap: &mut UpgradeCap, receipt: UpgradeReceipt) {
    let UpgradeReceipt { cap: cap_id, package } = receipt;
    assert!(cap.id.to_inner() == cap_id);
    cap.package = package;
    cap.version = cap.version + 1;
}

/// Restrict upgrades - tighten policy (cannot be loosened)
public fun restrict(cap: &mut UpgradeCap, policy: u8) {
    assert!(._policy_valid(cap.policy, policy));
    cap.policy = policy;
}

/// Make immutable - ESCAPABILITY: permanently prevent future upgrades
public entry fun make_immutable(cap: UpgradeCap) {
    let UpgradeCap { id, package: _, version: _, policy: _ } = cap;
    id.delete();
}

/// Get upgrade policy
public fun upgrade_policy(cap: &UpgradeCap): u8 {
    cap.policy
}

/// Get ticket package
public fun ticket_package(ticket: &UpgradeTicket): ID {
    ticket.package
}

/// Get receipt package
public fun receipt_package(receipt: &UpgradeReceipt): ID {
    receipt.package
}
