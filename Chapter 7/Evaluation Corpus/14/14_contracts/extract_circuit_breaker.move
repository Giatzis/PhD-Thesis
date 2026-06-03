// Source: sui::coin (Official Sui Framework)
// Pattern: CircuitBreakerPattern - DenyCapV2 deny-list mechanism
// Extract: Only DenyCapV2 struct and deny-list operations (circuit breaker)

module sui::coin;

use sui::deny_list::DenyList;
use std::type_name;

/// DenyCapV2 - Capability for denying addresses from using coin (Circuit Breaker)
/// If allow_global_pause is true, bearer can enable a global pause (kill switch)
public struct DenyCapV2<phantom T> has key, store {
    id: UID,
    allow_global_pause: bool,
}

const EGlobalPauseNotAllowed: u64 = 3;
const DENY_LIST_COIN_INDEX: u64 = 0;

/// Add address to deny list - CIRCUIT BREAKER: freeze specific address
public fun deny_list_v2_add<T>(
    deny_list: &mut DenyList,
    _deny_cap: &mut DenyCapV2<T>,
    addr: address,
    ctx: &mut TxContext,
) {
    let ty = type_name::with_original_ids<T>().into_string().into_bytes();
    deny_list.v2_add(DENY_LIST_COIN_INDEX, ty, addr, ctx)
}

/// Remove address from deny list - CIRCUIT BREAKER: unfreeze address
public fun deny_list_v2_remove<T>(
    deny_list: &mut DenyList,
    _deny_cap: &mut DenyCapV2<T>,
    addr: address,
    ctx: &mut TxContext,
) {
    let ty = type_name::with_original_ids<T>().into_string().into_bytes();
    deny_list.v2_remove(DENY_LIST_COIN_INDEX, ty, addr, ctx)
}

/// Enable global pause - CIRCUIT BREAKER: freeze ALL addresses
public fun deny_list_v2_enable_global_pause<T>(
    deny_list: &mut DenyList,
    deny_cap: &mut DenyCapV2<T>,
    ctx: &mut TxContext,
) {
    assert!(deny_cap.allow_global_pause, EGlobalPauseNotAllowed);
    let ty = type_name::with_original_ids<T>().into_string().into_bytes();
    deny_list.v2_enable_global_pause(DENY_LIST_COIN_INDEX, ty, ctx)
}

/// Disable global pause - CIRCUIT BREAKER: resume all operations
public fun deny_list_v2_disable_global_pause<T>(
    deny_list: &mut DenyList,
    deny_cap: &mut DenyCapV2<T>,
    ctx: &mut TxContext,
) {
    assert!(deny_cap.allow_global_pause, EGlobalPauseNotAllowed);
    let ty = type_name::with_original_ids<T>().into_string().into_bytes();
    deny_list.v2_disable_global_pause(DENY_LIST_COIN_INDEX, ty, ctx)
}
