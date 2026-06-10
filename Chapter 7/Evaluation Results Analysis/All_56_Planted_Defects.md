# All 56 Planted Defects — Contract Location Reference

Total: **56 planted defect instances** across Contexts A, A2, and D.
- Context A (`vuln_*.move`): **25 planted instances** across 4 contracts
- Context A2 (`suwc_*.move`): **28 planted instances** across 4 contracts
- Context D (`typus_vulnerable.move`): **3 planted instances**
- Context B (SecureVault) and Context C (Official Extracts): **0 planted defects**

Detection outcome: **51 raw findings** (collapsed to 50 architectural-unit TP) + **5 missed** (FN, outside architectural unit).

---

## Architectural Breakdown of the 50 Detected TPs
To adhere to the Sokolova single-unit principle, the 50 True Positives are structurally separated based on where the defect was planted. This mathematically proves the evaluation unit totals in Table 18, where the confusion matrix includes both the 80 evaluated functions and the 14 evaluated struct definitions.

### 1. Struct-Level TPs (8 Total)
These are object-ability defects planted directly in the struct definitions (e.g., giving capabilities the `store` ability, or hot-potato receipts the `drop` ability).
*   **Context A (4 TPs):** 
    *   `vuln_access_control.move`: `SaleCap`
    *   `vuln_escapability.move`: `VaultUpgradeCap`, `MigrationAuthCap`, `UpgradeReceipt`
*   **Context A2 (4 TPs):** 
    *   `suwc_auth_vulnerable.move`: `GovernanceCap`, `TreasuryAuthCap`
    *   `suwc_res_vulnerable.move`: `FlashLoanReceipt`, `SwapProof`

### 2. Function-Level TPs (42 Total)
These are behavioral defects planted inside executable logic (e.g., missing capability checks or unvalidated timestamps). 
*   **Context A (19 TPs):**
    *   `vuln_access_control.move`: 7 TPs
    *   `vuln_circuit_breaker.move`: 3 TPs
    *   `vuln_escapability.move`: 2 TPs
    *   `vuln_time_incentivization.move`: 7 TPs
*   **Context A2 (20 TPs):**
    *   `suwc_auth_vulnerable.move`: 9 TPs
    *   `suwc_cons_vulnerable.move`: 3 TPs
    *   `suwc_res_vulnerable.move`: 1 TP (`burn_to_null`)
    *   `suwc_time_vulnerable.move`: 7 TPs
*   **Context D (3 TPs):**
    *   `typus_vulnerable.move`: 3 TPs

*(Total: 8 Struct TPs + 42 Function TPs = 50 Detected TPs)*

---

## Context A — `vuln_*.move` (25 planted instances)

### Contract 1: `vuln_access_control.move` — 8 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 1 | `set_price` | AUTH-01 — privileged state mutation without capability check | CRITICAL | ✅ TP |
| 2 | `set_price` | AUTH-04 — `&mut TokenSale` shared object without authorization | HIGH | ✅ TP |
| 3 | `withdraw_funds` | AUTH-01 — privileged balance drain without capability check | CRITICAL | ✅ TP |
| 4 | `withdraw_funds` | AUTH-04 — mutable shared object without authorization | HIGH | ✅ TP |
| 5 | `toggle_sale` | AUTH-01 — privileged state toggle without capability check | CRITICAL | ✅ TP |
| 6 | `toggle_sale` | AUTH-04 — mutable shared object without authorization | HIGH | ✅ TP |
| 7 | `SaleCap` struct | AUTH-02 — `key, store, copy` abilities enable unauthorized duplication | HIGH | ✅ TP |
| 8 | `init` | AUTH-03 — `TOKENSALE` OTW passed by reference instead of consumed | HIGH | ✅ TP |

---

### Contract 2: `vuln_circuit_breaker.move` — 3 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 9 | `swap_a_to_b` | CONS-01 — bilateral token exchange without AMM curve invariant assert | CRITICAL | ✅ TP |
| 10 | `swap_b_to_a` | CONS-01 — bilateral token exchange without AMM curve invariant assert | CRITICAL | ✅ TP |
| 11 | `distribute_fees` | CONS-02 — unbounded `while vector::length` loop without pagination | HIGH | ✅ TP |

---

### Contract 3: `vuln_escapability.move` — 6 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 12 | `VaultUpgradeCap` struct | AUTH-02 — `key, store` with non-UID financial fields | HIGH | ✅ TP |
| 13 | `MigrationAuthCap` struct | AUTH-02 — `key, store, copy` with non-UID field `vault_id` | HIGH | ✅ TP |
| 14 | `UpgradeReceipt` struct | RES-01 — `drop` ability on hot-potato receipt with value fields | HIGH | ✅ TP |
| 15 | `send_to_burn` | RES-03 — `transfer::public_transfer(asset, @0x0)` permanent asset destruction | HIGH | ✅ TP |
| 16 | `wrap_for_migration` | AUTH-01 — `balance::split` on shared vault without capability check | HIGH | ✅ TP |
| 17 | `MigrationWrapper` struct | RES-02 — Roach Motel: struct can receive assets but has no extraction function | HIGH | ❌ FN-1 |

> **FN-1 root cause:** Module-level extraction check — `wrap_for_migration` body has `balance::split(&mut vault.balance, amount)` which sets `has_extraction = True` globally, suppressing RES-02 for all structs in the module, including `MigrationWrapper` which has no extraction path of its own.

---

### Contract 4: `vuln_time_incentivization.move` — 8 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 18 | `claim` | TIME-01 — asset outflow (`coin::take`) without temporal guard | HIGH | ✅ TP |
| 19 | `withdraw` | TIME-01 — asset outflow without temporal guard | HIGH | ✅ TP |
| 20 | `release` | TIME-01 — asset outflow without temporal guard | HIGH | ✅ TP |
| 21 | `lock_rewards` | TIME-02 — deposits into time-constrained structure with no release mechanism | HIGH | ❌ FN-2 |
| 22 | `calculate_rewards` | TIME-03 — `clock::timestamp_ms()` used in computation without validation | HIGH | ✅ TP |
| 23 | `compound_rewards` | TIME-03 — `clock::timestamp_ms()` used without validation | HIGH | ✅ TP |
| 24 | `compound_rewards` | TIME-04 — two `clock::timestamp_ms()` reads in same function body (race condition) | HIGH | ✅ TP |
| 25 | `stake` | TIME-03 — `clock::timestamp_ms()` stored without validation *(also counts as planted)* | HIGH | ✅ TP |

> **FN-2 root cause:** TIME-02 detection gate requires both a deposit operation AND an `object::new` call in the same function. `lock_rewards` deposits into an *existing* shared pool (`balance::join(&mut pool.rewards, ...)`) without creating a new object — the gate is never triggered.

**Context A subtotal: 23 TP + 2 FN = 25 planted instances**

---

## Context A2 — `suwc_*.move` (28 planted instances)

### Contract 5: `suwc_auth_vulnerable.move` — 11 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 26 | `set_fee_rate` | AUTH-01 — privileged treasury mutation without capability | CRITICAL | ✅ TP |
| 27 | `set_fee_rate` | AUTH-04 — `&mut Treasury` shared object without authorization | HIGH | ✅ TP |
| 28 | `emergency_withdraw` | AUTH-01 — privileged withdrawal without capability | CRITICAL | ✅ TP |
| 29 | `emergency_withdraw` | AUTH-04 — mutable shared object without authorization | HIGH | ✅ TP |
| 30 | `pause_treasury` | AUTH-01 — privileged governance state change without capability | CRITICAL | ✅ TP |
| 31 | `pause_treasury` | AUTH-04 — `&mut GovernancePool` without authorization | HIGH | ✅ TP |
| 32 | `update_admin` | AUTH-01 — privileged admin update without capability | CRITICAL | ✅ TP |
| 33 | `update_admin` | AUTH-04 — mutable shared object without authorization | HIGH | ✅ TP |
| 34 | `GovernanceCap` struct | AUTH-02 — `key, store, copy` abilities | HIGH | ✅ TP |
| 35 | `TreasuryAuthCap` struct | AUTH-02 — `key, store` abilities | HIGH | ✅ TP |
| 36 | `init` | AUTH-03 — `AUTH_GOVERNANCE` OTW passed by reference instead of consumed | HIGH | ✅ TP |

---

### Contract 6: `suwc_cons_vulnerable.move` — 3 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 37 | `swap_a_to_b` | CONS-01 — bilateral token exchange without AMM invariant assert | CRITICAL | ✅ TP |
| 38 | `swap_b_to_a` | CONS-01 — bilateral token exchange without AMM invariant assert | CRITICAL | ✅ TP |
| 39 | `batch_distribute` | CONS-02 — unbounded `while vector::length` loop | HIGH | ✅ TP |

---

### Contract 7: `suwc_res_vulnerable.move` — 5 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 40 | `FlashLoanReceipt` struct | RES-01 — `drop` ability on hot-potato with value fields (`pool_id`, `amount`) | HIGH | ✅ TP |
| 41 | `SwapProof` struct | RES-01 — `drop` ability on hot-potato with value fields (`amount_in`, `amount_out`) | HIGH | ✅ TP |
| 42 | `AssetWrapper` struct | RES-02 — Roach Motel: struct can receive assets but has no extraction function | HIGH | ❌ FN-1 |
| 43 | `TokenContainer` struct | RES-02 — Roach Motel: struct can receive assets but has no extraction function | HIGH | ❌ FN-1 |
| 44 | `burn_to_null` | RES-03 — `transfer::public_transfer(object, @0x0)` permanent asset destruction | HIGH | ✅ TP |

> **FN-1 root cause (same as Contract 3):** `get_flash_loan` in the same module performs `coin::take(&mut pool.reserves, amount, ctx)` — this sets `has_extraction = True` globally for the entire module, suppressing RES-02 on `AssetWrapper` and `TokenContainer` which have no extraction paths of their own.

---

### Contract 8: `suwc_time_vulnerable.move` — 9 planted instances

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 45 | `claim_rewards` | TIME-01 — asset outflow without temporal guard | HIGH | ✅ TP |
| 46 | `withdraw_vested` | TIME-01 — asset outflow without temporal guard | HIGH | ✅ TP |
| 47 | `release_tokens` | TIME-01 — asset outflow without temporal guard | HIGH | ✅ TP |
| 48 | `lock_rewards` | TIME-02 — deposits into time-constrained structure with no release mechanism | HIGH | ❌ FN-2 |
| 49 | `check_elapsed` | TIME-03 — `clock::timestamp_ms()` used without validation | HIGH | ✅ TP |
| 50 | `compound_and_restake` | TIME-03 — `clock::timestamp_ms()` used without validation | HIGH | ✅ TP |
| 51 | `compound_and_restake` | TIME-04 — two `clock::timestamp_ms()` reads in same function body (race condition) | HIGH | ✅ TP |
| 52 | `stake` | TIME-03 — `clock::timestamp_ms()` stored without validation | HIGH | ✅ TP |
| 53 | `create_vault` | TIME-03 — `clock::timestamp_ms()` stored in struct field without validation | HIGH | ✅ TP |

> **FN-2 root cause (same as Contract 4):** `lock_rewards` deposits into an existing shared `RewardPool` object — no `object::new` call — so the TIME-02 co-detection gate (requires deposit + object creation) never fires.

**Context A2 subtotal: 24 TP + 3 FN-instances = 28 planted instances**

> *Note: The 3 FN-instances in A2 are 2 struct FNs (FN-1: AssetWrapper, TokenContainer) + 1 function FN (FN-2: lock_rewards). Combined with Context A's 2 FN-instances (FN-1: MigrationWrapper + FN-2: lock_rewards), total = 5 planted FN-instances across the corpus.*

---

## Context D — `typus_vulnerable.move` (3 planted instances)

| # | Target | Defect | Severity | Outcome |
|---|--------|--------|----------|---------|
| 54 | `update_price` | AUTH-01 — root cause of $3.44M exploit; no `OracleCap` guard on oracle update | CRITICAL | ✅ TP |
| 55 | `update_price` | AUTH-04 — `&mut PriceOracle` shared object modifiable by anyone | HIGH | ✅ TP |
| 56 | `swap` | CONS-01 — AMM swap uses manipulated oracle prices without invariant guard | CRITICAL | ✅ TP |

**Context D subtotal: 3 TP + 0 FN = 3 planted instances**

---

## Master Summary

| Context | Contract | Planted | TP | FN |
|---------|----------|---------|----|----|
| A | `vuln_access_control.move` | 8 | 8 | 0 |
| A | `vuln_circuit_breaker.move` | 3 | 3 | 0 |
| A | `vuln_escapability.move` | 6 | 5 | 1 (RES-02 MigrationWrapper) |
| A | `vuln_time_incentivization.move` | 8 | 7 | 1 (TIME-02 lock_rewards) |
| A2 | `suwc_auth_vulnerable.move` | 11 | 11 | 0 |
| A2 | `suwc_cons_vulnerable.move` | 3 | 3 | 0 |
| A2 | `suwc_res_vulnerable.move` | 5 | 3 | 2 (RES-02 AssetWrapper, TokenContainer) |
| A2 | `suwc_time_vulnerable.move` | 9 | 8 | 1 (TIME-02 lock_rewards) |
| D | `typus_vulnerable.move` | 3 | 3 | 0 |
| **Total** | | **56** | **51*** | **5** |

> *\*51 detected instances collapse to 50 TPs under the single-unit principle (compound_and_restake carries two co-firing defects merged into one TP unit).*

### The 5 FN Detection Instances (2 FN detected 5 times in total)

| FN# | Contract | Target | Expected Defect | Root Cause |
|-----|----------|--------|-----------------|------------|
| FN-1a | `vuln_escapability.move` | `MigrationWrapper` struct | RES-02 Roach Motel | Module-level extraction check: `wrap_for_migration` sets `has_extraction=True` globally |
| FN-1b | `suwc_res_vulnerable.move` | `AssetWrapper` struct | RES-02 Roach Motel | Module-level extraction check: `get_flash_loan` sets `has_extraction=True` globally |
| FN-1c | `suwc_res_vulnerable.move` | `TokenContainer` struct | RES-02 Roach Motel | Same as FN-1b — same module, same suppression |
| FN-2a | `vuln_time_incentivization.move` | `lock_rewards` function | TIME-02 Indefinite Lock | Co-detection gate requires `object::new` + deposit; `lock_rewards` deposits into existing shared pool |
| FN-2b | `suwc_time_vulnerable.move` | `lock_rewards` function | TIME-02 Indefinite Lock | Same as FN-2a — identical structural blind spot confirmed across both suites |

> Both FN root causes are **deterministic and reproducible** — they will miss the same vulnerability type every time it appears under these structural conditions, confirming they are systematic gate limitations, not isolated misses (§7.7.2, §7.7.4).
