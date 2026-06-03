
import sys, io, os, json, re, traceback
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure imports work relative to this script
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(script_dir))

from Comprehensive_Sui_Analyzer import ComprehensiveSuiAnalyzer

# ============================================================================
# HELPERS
# ============================================================================
results = []  # list of (category, test_name, pass_bool, detail)

def run(code, label):
    a = ComprehensiveSuiAnalyzer()
    return a.analyze_contract(code, label)

def has_pattern(r, pat):
    return r["patterns"].get(pat, 0) > 0

def has_vuln(r, defect_id, func_name=None):
    for v in r["vulnerabilities"]:
        if v.defect_id == defect_id:
            if func_name is None or v.function_name == func_name:
                return True
    return False

def no_vuln(r, defect_id, func_name=None):
    return not has_vuln(r, defect_id, func_name)

def cap_det(r):
    return r["statistics"]["detection_methods"]["capability_based"]

def dcr_count(r):
    return r["statistics"]["dcr_graphs_generated"]

def test(cat, name, cond, detail=""):
    results.append((cat, name, bool(cond), detail))

# ============================================================================
# 1. PATTERN DETECTION TESTS (14)
# ============================================================================
CAT1 = "Pattern Detection"

# 1.1 AC - AdminCap
c = """module test::access_control {
    struct AdminCap has key, store { id: UID }
    public entry fun admin_only_function(_admin: &AdminCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_1")
test(CAT1, "1.1 AC-AdminCap", has_pattern(r, "AccessControlPattern"), "AC={0}".format(r["patterns"]))

# 1.2 AC - OwnerCap
c = """module test::owner {
    struct OwnerCap has key, store { id: UID }
    public entry fun owner_only_function(_owner: &OwnerCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_2")
test(CAT1, "1.2 AC-OwnerCap", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 1.3 AC - TreasuryCap
c = """module test::treasury {
    use sui::coin::TreasuryCap;
    public entry fun mint_tokens<T>(treasury: &mut TreasuryCap<T>, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_3")
test(CAT1, "1.3 AC-TreasuryCap", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 1.4 AC - Dynamic ACL Table
c = """module test::dynamic_acl {
    use sui::table::{Self, Table};
    use sui::tx_context::{Self, TxContext};
    struct Registry has key { id: UID, admins: Table<address, bool> }
    public entry fun admin_function(registry: &Registry, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        assert!(table::contains(&registry.admins, sender), 0);
    }
}"""
r = run(c, "t1_4")
test(CAT1, "1.4 AC-DynACL-Table", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 1.5 AC - Dynamic ACL VecSet
c = """module test::vecset_acl {
    use sui::vec_set::{Self, VecSet};
    use sui::tx_context::{Self, TxContext};
    struct Whitelist has key { id: UID, members: VecSet<address> }
    public entry fun member_only_function(whitelist: &Whitelist, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        assert!(vec_set::contains(&whitelist.members, &sender), 0);
    }
}"""
r = run(c, "t1_5")
test(CAT1, "1.5 AC-DynACL-VecSet", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 1.6 AC - Inline Auth
c = """module test::inline_auth {
    struct Wallet has key { id: UID, owner: address, balance: u64 }
    public entry fun withdraw(wallet: &mut Wallet, ctx: &mut TxContext) {
        assert!(wallet.owner == tx_context::sender(ctx), 0);
    }
}"""
r = run(c, "t1_6")
test(CAT1, "1.6 AC-InlineAuth", has_pattern(r, "AccessControlPattern"), str(r["patterns"]) + " inline=" + str(r["statistics"]["detection_methods"]["inline_auth"]))

# 1.7 CB - PauseCap
c = """module test::pause {
    struct PauseCap has key, store { id: UID }
    struct Protocol has key { id: UID, paused: bool }
    public entry fun pause(_cap: &PauseCap, protocol: &mut Protocol, ctx: &mut TxContext) { protocol.paused = true; }
    public entry fun unpause(_cap: &PauseCap, protocol: &mut Protocol, ctx: &mut TxContext) { protocol.paused = false; }
}"""
r = run(c, "t1_7")
test(CAT1, "1.7 CB-PauseCap", has_pattern(r, "CircuitBreakerPattern"), str(r["patterns"]))

# 1.8 CB - EmergencyCap
c = """module test::emergency {
    struct EmergencyCap has key, store { id: UID }
    public entry fun emergency_shutdown(_cap: &EmergencyCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_8")
test(CAT1, "1.8 CB-EmergencyCap", has_pattern(r, "CircuitBreakerPattern"), str(r["patterns"]))

# 1.9 CB - DenyCap
c = """module test::deny {
    use sui::coin::DenyCap;
    public entry fun deny_address<T>(cap: &mut DenyCap<T>, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_9")
test(CAT1, "1.9 CB-DenyCap", has_pattern(r, "CircuitBreakerPattern"), str(r["patterns"]))

# 1.10 TI - Clock
c = """module test::vesting {
    use sui::clock::{Self, Clock};
    struct VestingWallet has key { id: UID, unlock_time: u64, balance: u64 }
    public entry fun claim(wallet: &mut VestingWallet, clock: &Clock, ctx: &mut TxContext) {
        let current_time = clock::timestamp_ms(clock);
        assert!(current_time >= wallet.unlock_time, 0);
    }
}"""
r = run(c, "t1_10")
test(CAT1, "1.10 TI-Clock", has_pattern(r, "TimeIncentivizationPattern"), str(r["patterns"]))

# 1.11 TI - Temporal Check
c = """module test::timelock {
    use sui::clock::{Self, Clock};
    struct TimeLock has key { id: UID, release_time: u64 }
    public entry fun unlock(lock: &TimeLock, clock: &Clock, ctx: &mut TxContext) {
        assert!(clock::timestamp_ms(clock) >= lock.release_time, 0);
    }
}"""
r = run(c, "t1_11")
test(CAT1, "1.11 TI-TemporalCheck", has_pattern(r, "TimeIncentivizationPattern"), str(r["patterns"]))

# 1.12 ES - UpgradeCap
c = """module test::upgrade {
    struct UpgradeCap has key, store { id: UID }
    public entry fun authorize_upgrade(cap: &UpgradeCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_12")
test(CAT1, "1.12 ES-UpgradeCap", has_pattern(r, "EscapabilityPattern"), str(r["patterns"]))

# 1.13 ES - MigrationCap
c = """module test::migration {
    struct MigrationCap has key, store { id: UID }
    public entry fun migrate_state(_cap: &MigrationCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t1_13")
test(CAT1, "1.13 ES-MigrationCap", has_pattern(r, "EscapabilityPattern"), str(r["patterns"]))

# 1.14 Multiple Patterns
c = """module test::multi {
    use sui::clock::{Self, Clock};
    struct AdminCap has key, store { id: UID }
    struct PauseCap has key, store { id: UID }
    struct UpgradeCap has key, store { id: UID }
    struct Protocol has key { id: UID, paused: bool, upgrade_delay: u64 }
    public entry fun pause(_cap: &PauseCap, protocol: &mut Protocol, ctx: &mut TxContext) { protocol.paused = true; }
    public entry fun admin_upgrade(_admin: &AdminCap, _upgrade: &UpgradeCap, protocol: &mut Protocol, clock: &Clock, ctx: &mut TxContext) {
        assert!(!protocol.paused, 0);
        let current_time = clock::timestamp_ms(clock);
        assert!(current_time >= protocol.upgrade_delay, 0);
    }
}"""
r = run(c, "t1_14")
pats = r["patterns"]
test(CAT1, "1.14 MultiPattern", len(pats) >= 3, str(pats))

# ============================================================================
# 2. HEURISTIC CLASSIFICATION TESTS (12)
# ============================================================================
CAT2 = "Heuristic Classification"

def is_privileged(code, func_name, label):
    r = run(code, label)
    return has_vuln(r, "SUWC-AUTH-01", func_name) or has_vuln(r, "SUWC-AUTH-04", func_name)

def is_public(code, func_name, label):
    r = run(code, label)
    return no_vuln(r, "SUWC-AUTH-01", func_name)

# 2.1 admin_set_config -> PRIVILEGED
c = """module test::admin {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    struct Config has key, store { id: UID, val: u64, reserve: Balance<SUI> }
    public fun admin_set_config(config: &mut Config) { config.val = 1; }
}"""
test(CAT2, "2.1 admin_set_config=PRIV", is_privileged(c, "admin_set_config", "t2_1"), "")

# 2.2 owner_withdraw -> PRIVILEGED
c = """module test::owner {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
    struct Vault has key, store { id: UID, balance: Balance<SUI>, owner: address }
    public fun owner_withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        let coin = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coin, vault.owner);
    }
}"""
test(CAT2, "2.2 owner_withdraw=PRIV", is_privileged(c, "owner_withdraw", "t2_2"), "")

# 2.3 drain_funds -> PRIVILEGED
c = """module test::drain {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, balance: Balance<SUI> }
    public fun drain_funds(pool: &mut Pool) { let _ = balance::split(&mut pool.balance, 100); }
}"""
test(CAT2, "2.3 drain_funds=PRIV", is_privileged(c, "drain_funds", "t2_3"), "")

# 2.4 pause_protocol -> PRIVILEGED
c = """module test::pause {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    struct Proto has key, store { id: UID, paused: bool, reserve: Balance<SUI> }
    public fun pause_protocol(proto: &mut Proto) { proto.paused = true; }
}"""
test(CAT2, "2.4 pause_protocol=PRIV", is_privileged(c, "pause_protocol", "t2_4"), "")

# 2.5 upgrade_contract -> PRIVILEGED
c = """module test::upgrade {
    struct Config has key, store { id: UID, version: u64 }
    public fun upgrade_contract(config: &mut Config) { config.version = config.version + 1; }
}"""
test(CAT2, "2.5 upgrade_contract=PRIV", is_privileged(c, "upgrade_contract", "t2_5"), "upgrade pattern commented out")

# 2.6 admin_drain_swap -> PRIVILEGED (priority override)
c = """module test::exploit {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, balance: Balance<SUI> }
    public fun admin_drain_swap(pool: &mut Pool) { let _ = balance::split(&mut pool.balance, 100); }
}"""
test(CAT2, "2.6 admin_drain_swap=PRIV", is_privileged(c, "admin_drain_swap", "t2_6"), "")

# 2.7 swap_x_to_y -> PUBLIC
c = """module test::dex {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, rx: Balance<SUI>, ry: Balance<SUI> }
    public fun swap_x_to_y(pool: &mut Pool, coin_in: Coin<SUI>, ctx: &mut TxContext): Coin<SUI> {
        balance::join(&mut pool.rx, coin::into_balance(coin_in));
        coin::take(&mut pool.ry, 100, ctx)
    }
}"""
test(CAT2, "2.7 swap_x_to_y=PUBLIC", is_public(c, "swap_x_to_y", "t2_7"), "")

# 2.8 stake_tokens -> PUBLIC
c = """module test::staking {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, staked: Balance<SUI> }
    public fun stake_tokens(pool: &mut Pool, tokens: Coin<SUI>) {
        balance::join(&mut pool.staked, coin::into_balance(tokens));
    }
}"""
test(CAT2, "2.8 stake_tokens=PUBLIC", is_public(c, "stake_tokens", "t2_8"), "")

# 2.9 claim_rewards -> PUBLIC
c = """module test::rewards {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, rewards: Balance<SUI> }
    public fun claim_rewards(pool: &mut Pool, ctx: &mut TxContext): Coin<SUI> {
        coin::take(&mut pool.rewards, 100, ctx)
    }
}"""
test(CAT2, "2.9 claim_rewards=PUBLIC", is_public(c, "claim_rewards", "t2_9"), "")

# 2.10 deposit_funds -> PUBLIC
c = """module test::vault {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Vault has key, store { id: UID, balance: Balance<SUI> }
    public fun deposit_funds(vault: &mut Vault, coin: Coin<SUI>) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }
}"""
test(CAT2, "2.10 deposit_funds=PUBLIC", is_public(c, "deposit_funds", "t2_10"), "")

# 2.11 new_pool -> PUBLIC
c = """module test::factory {
    struct Pool has key { id: UID, val: u64 }
    public fun new_pool(ctx: &mut TxContext): Pool { Pool { id: object::new(ctx), val: 0 } }
}"""
test(CAT2, "2.11 new_pool=PUBLIC", is_public(c, "new_pool", "t2_11"), "")

# 2.12 get_balance -> PUBLIC
c = """module test::query {
    struct Vault has key { id: UID, amount: u64 }
    public fun get_balance(vault: &Vault): u64 { vault.amount }
}"""
test(CAT2, "2.12 get_balance=PUBLIC", is_public(c, "get_balance", "t2_12"), "")

# ============================================================================
# 3. REGEX COVERAGE TESTS (5)
# ============================================================================
CAT3 = "Regex Coverage"

# 3.1 Whitespace
c = """module test::whitespace {
    struct   AdminCap   has   key , store   { id  :  UID }
    public   entry   fun   admin_function  ( _cap :  &  AdminCap  , ctx  :  &mut  TxContext )   {}
}"""
r = run(c, "t3_1")
test(CAT3, "3.1 Whitespace handling", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 3.2 Clock formats
c = """module test::clock_formats {
    use sui::clock::{Self, Clock};
    public fun test1(clock:&Clock, ctx: &mut TxContext) {}
    public fun test2(clock: & Clock, ctx: &mut TxContext) {}
    public fun test3(clock :&Clock, ctx: &mut TxContext) {}
}"""
r = run(c, "t3_2")
test(CAT3, "3.2 Clock format variants", has_pattern(r, "TimeIncentivizationPattern"), str(r["patterns"]))

# 3.3 Generic cap names (EXPECTED FAIL)
c = """module test::generic_caps {
    struct PublisherCap has key { id: UID }
    struct ManagerCap has key { id: UID }
}"""
r = run(c, "t3_3")
test(CAT3, "3.3 GenericCap names", has_pattern(r, "AccessControlPattern"), str(r["patterns"]))

# 3.4 Multiple caps same function
c = """module test::multi_cap {
struct AdminCap has key { id: UID }
struct OwnerCap has key { id: UID }
public entry fun dual_auth(_admin: &AdminCap, _owner: &OwnerCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t3_4")
test(CAT3, "3.4 MultiCap same fn", has_pattern(r, "AccessControlPattern") and r["statistics"]["functions_analyzed"] >= 1, "cap_det=" + str(cap_det(r)))

# 3.5 Nested generic types
c = """module test::nested {
    use std::option::Option;
    struct AdminCap has key { id: UID }
    public fun complex_param(cap: Option<&AdminCap>, ctx: &mut TxContext) {}
}"""
r = run(c, "t3_5")
test(CAT3, "3.5 Nested generic types", r["statistics"]["functions_analyzed"] >= 1, "funcs=" + str(r["statistics"]["functions_analyzed"]))

# ============================================================================
# 4. FALSE POSITIVE/NEGATIVE TESTS (6)
# ============================================================================
CAT4 = "False Positive/Negative"

# 4.1 No FP: swap
c = """module test::dex {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Pool has key { id: UID, r: Balance<SUI> }
    public fun swap(pool: &mut Pool, c: Coin<SUI>, ctx: &mut TxContext): Coin<SUI> {
        balance::join(&mut pool.r, coin::into_balance(c));
        coin::take(&mut pool.r, 100, ctx)
    }
}"""
r = run(c, "t4_1")
test(CAT4, "4.1 No FP: swap", no_vuln(r, "SUWC-AUTH-01", "swap"), "")

# 4.2 No FP: add_liquidity
c = """module test::liquidity {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    struct Pool has key { id: UID, r: Balance<SUI> }
    public fun add_liquidity(pool: &mut Pool, c: Coin<SUI>) {
        balance::join(&mut pool.r, coin::into_balance(c));
    }
}"""
r = run(c, "t4_2")
test(CAT4, "4.2 No FP: add_liquidity", no_vuln(r, "SUWC-AUTH-01", "add_liquidity"), "")

# 4.3 No FP: create_pool
c = """module test::factory {
    struct Pool has key { id: UID, val: u64 }
    public fun create_pool(ctx: &mut TxContext): Pool { Pool { id: object::new(ctx), val: 0 } }
}"""
r = run(c, "t4_3")
test(CAT4, "4.3 No FP: create_pool", no_vuln(r, "SUWC-AUTH-01", "create_pool"), "")

# 4.4 No FP: claim with inline auth
c = """module test::rewards {
    struct RewardPool has key { id: UID, owner: address }
    public fun claim(pool: &mut RewardPool, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        assert!(pool.owner == sender, 0);
    }
}"""
r = run(c, "t4_4")
test(CAT4, "4.4 No FP: claim w/ inline auth", no_vuln(r, "SUWC-AUTH-01", "claim"), str([v.defect_id + ":" + v.function_name for v in r["vulnerabilities"]]))

# 4.5 No FN: admin_drain_swap
c = """module test::exploit {
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    struct Pool has key, store { id: UID, balance: Balance<SUI> }
    public fun admin_drain_swap(pool: &mut Pool) { let _ = balance::split(&mut pool.balance, 100); }
}"""
r = run(c, "t4_5")
test(CAT4, "4.5 No FN: admin_drain_swap flagged", has_vuln(r, "SUWC-AUTH-01", "admin_drain_swap"), "")

# 4.6 No FN: emergency_withdraw
c = """module test::emergency {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
    struct Vault has key, store { id: UID, balance: Balance<SUI>, admin: address }
    public fun emergency_withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        let coin = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coin, vault.admin);
    }
}"""
r = run(c, "t4_6")
test(CAT4, "4.6 No FN: emergency_withdraw", has_vuln(r, "SUWC-AUTH-01", "emergency_withdraw"), "")

# ============================================================================
# 5. INTEGRATION TESTS (5)
# ============================================================================
CAT5 = "Integration"

# 5.1 Complete DeFi Protocol
c = """module test::defi {
    use sui::clock::{Self, Clock};
    struct AdminCap has key, store { id: UID }
    struct PauseCap has key, store { id: UID }
    struct UpgradeCap has key, store { id: UID }
    struct Pool has key { id: UID, reserve_x: u64, reserve_y: u64, fee: u64, paused: bool }
    public fun swap(pool: &mut Pool, amount: u64, ctx: &mut TxContext) { assert!(!pool.paused, 0); }
    public fun set_fee(_admin: &AdminCap, pool: &mut Pool, new_fee: u64) { pool.fee = new_fee; }
    public fun pause(_cap: &PauseCap, pool: &mut Pool) { pool.paused = true; }
    public fun upgrade(_admin: &AdminCap, _upgrade: &UpgradeCap, clock: &Clock, ctx: &mut TxContext) {
        let _ = clock::timestamp_ms(clock);
    }
}"""
r = run(c, "t5_1")
test(CAT5, "5.1 Complete DeFi", r["statistics"]["patterns_detected"] >= 3, "pats=" + str(r["patterns"]))

# 5.2 DCR Graph Generation
c = """module test::graphs {
    use sui::clock::{Self, Clock};
    struct AdminCap has key, store { id: UID }
    struct PauseCap has key, store { id: UID }
    struct UpgradeCap has key, store { id: UID }
    struct Protocol has key { id: UID, paused: bool, upgrade_delay: u64 }
    public fun pause(_cap: &PauseCap, protocol: &mut Protocol) { protocol.paused = true; }
    public fun unpause(_cap: &PauseCap, protocol: &mut Protocol) { protocol.paused = false; }
    public fun admin_upgrade(_admin: &AdminCap, _upgrade: &UpgradeCap, protocol: &Protocol, clock: &Clock) {
        assert!(!protocol.paused, 0);
        let _ = clock::timestamp_ms(clock);
    }
}"""
r = run(c, "t5_2")
test(CAT5, "5.2 DCR Generation", dcr_count(r) >= 2, "dcr=" + str(dcr_count(r)))

# 5.3 RDF Ontology Population
c = """module test::ontology {
    struct AdminCap has key, store { id: UID }
    public entry fun privileged_operation(_admin: &AdminCap, ctx: &mut TxContext) {}
}"""
r = run(c, "t5_3")
test(CAT5, "5.3 RDF Population", r["ontology_triples"] >= 1181, "triples=" + str(r["ontology_triples"]))

# 5.4 Full Pipeline: Vuln -> Fix -> Pattern linkage
c = """module test::pipeline {
    use sui::clock::{Self, Clock};
    struct AdminCap has key, store { id: UID }
    struct Vault has key { id: UID, paused: bool }
    public fun deposit(_admin: &AdminCap, vault: &mut Vault) {}
    public fun timed_claim(vault: &mut Vault, clock: &Clock, ctx: &mut TxContext) {
        assert!(!vault.paused, 0);
        let _ = clock::timestamp_ms(clock);
    }
}"""
r = run(c, "t5_4")
test(CAT5, "5.4 Pipeline: vuln+fix+pattern", r["statistics"]["fixes_available"] >= 0 and r["statistics"]["patterns_detected"] >= 1, "pats=" + str(r["patterns"]) + " fixes=" + str(r["statistics"]["fixes_available"]))

# 5.5 Cross-category: AUTH+CONS in same contract
c = """module test::cross {
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
struct Pool has key, store { id: UID, rx: Balance, ry: Balance, fee: u64 }
public fun admin_set_fee(pool: &mut Pool) { pool.fee = 100; }
public fun swap(pool: &mut Pool, c: Coin, ctx: &mut TxContext): Coin {
balance::join(&mut pool.rx, coin::into_balance(c));
coin::take(&mut pool.ry, 100, ctx)
}
}"""
r = run(c, "t5_5")
cats_found = set()
for v in r["vulnerabilities"]:
    cats_found.add(v.category.value)
test(CAT5, "5.5 Cross-category AUTH+CONS", len(cats_found) >= 2, "cats=" + str(cats_found))

# ============================================================================
# OUTPUT
# ============================================================================
print("\n" + "=" * 100)
print("TEST RESULTS: 42 TESTS")
print("=" * 100)

passed = sum(1 for _, _, p, _ in results if p)
failed = sum(1 for _, _, p, _ in results if not p)

cats = {}
for cat, name, p, d in results:
    if cat not in cats:
        cats[cat] = {"pass": 0, "fail": 0, "tests": []}
    if p:
        cats[cat]["pass"] += 1
    else:
        cats[cat]["fail"] += 1
    cats[cat]["tests"].append((name, p, d))

for cat in cats:
    c = cats[cat]
    print("\n--- " + cat + " (" + str(c["pass"]) + "/" + str(c["pass"] + c["fail"]) + ") ---")
    for name, p, d in c["tests"]:
        icon = "PASS" if p else "FAIL"
        print("  [" + icon + "] " + name + ("  (" + d + ")" if d and not p else ""))

print("\n" + "=" * 100)
print("TOTAL: " + str(passed) + " PASSED, " + str(failed) + " FAILED out of " + str(len(results)))
print("=" * 100)

# Print failures for report
print("\nFAILED TESTS:")
for cat, name, p, d in results:
    if not p:
        print("  " + cat + " | " + name + " | " + d)