# 47 Noise Findings

---

## Methodology

All 111 raw findings were classified into four mutually exclusive categories:

| Category | Count | Source |
|----------|-------|--------|
| **TP** (True Positives) | 51 | 51 raw findings (50 units under single-unit principle) |
| **BLW** (Business Logic Warnings) | 9 findings → 7 BLWs | `BLW_Contract_Analysis.md` |
| **FP** (False Positives) | 4 | Deterministic misclassifications |
| **Noise** | **47** | This document |

---

## The 47 Noise Findings — Full List

| # | Contract | Target | Type | Pipeline | Description |
|---|----------|--------|------|----------|-------------|
| 1 | `suwc_auth_vulnerable.move` | `Treasury` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern — no pause mechanism |
| 2 | `suwc_auth_vulnerable.move` | `deposit` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 3 | `suwc_auth_vulnerable.move` | `emergency_withdraw` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 4 | `suwc_auth_vulnerable.move` | `init` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 5 | `suwc_cons_vulnerable.move` | `batch_distribute` | SUWC-AUTH-01 | Regex | Privileged function without capability check |
| 6 | `suwc_cons_vulnerable.move` | `add_liquidity` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 7 | `suwc_cons_vulnerable.move` | `remove_liquidity` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 8 | `suwc_res_vulnerable.move` | `burn_to_null` | SUWC-AUTH-01 | Regex | Privileged function without capability check |
| 9 | `suwc_res_vulnerable.move` | `wrap_assets` | SUWC-TIME-02 | Regex | Locked position without unlock mechanism |
| 10 | `suwc_res_vulnerable.move` | `wrap_tokens` | SUWC-TIME-02 | Regex | Locked position without unlock mechanism |
| 11 | `suwc_res_vulnerable.move` | `AssetWrapper` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 12 | `suwc_res_vulnerable.move` | `TokenContainer` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 13 | `suwc_res_vulnerable.move` | `Pool` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 14 | `suwc_res_vulnerable.move` | `burn_to_null` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 15 | `suwc_res_vulnerable.move` | `deposit` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 16 | `suwc_res_vulnerable.move` | `deposit_repayment` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 17 | `suwc_res_vulnerable.move` | `get_flash_loan` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 18 | `suwc_res_vulnerable.move` | `wrap_assets` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 19 | `suwc_res_vulnerable.move` | `wrap_tokens` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 20 | `suwc_time_vulnerable.move` | `create_vault` | SUWC-TIME-02 | Regex | Locked position without unlock mechanism |
| 21 | `suwc_time_vulnerable.move` | `stake` | SUWC-TIME-02 | Regex | Locked position without unlock mechanism |
| 22 | `suwc_time_vulnerable.move` | `VestingVault` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 23 | `suwc_time_vulnerable.move` | `RewardPool` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 24 | `suwc_time_vulnerable.move` | `claim_rewards` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 25 | `suwc_time_vulnerable.move` | `create_vault` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 26 | `suwc_time_vulnerable.move` | `lock_rewards` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 27 | `suwc_time_vulnerable.move` | `stake` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 28 | `suwc_time_vulnerable.move` | `stake` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 29 | `vuln_access_control.move` | `TokenSale` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 30 | `vuln_access_control.move` | `init` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 31 | `vuln_access_control.move` | `withdraw_funds` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 32 | `vuln_circuit_breaker.move` | `add_liquidity` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 33 | `vuln_circuit_breaker.move` | `remove_liquidity` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 34 | `vuln_escapability.move` | `wrap_for_migration` | SUWC-AUTH-04 | Regex | Shared object without authorization |
| 35 | `vuln_escapability.move` | `send_to_burn` | SUWC-AUTH-01 | Regex | Privileged function without capability check |
| 36 | `vuln_escapability.move` | `deposit` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 37 | `vuln_escapability.move` | `send_to_burn` | SUWC-AUTH-02 | SPARQL | OwnershipTransfer without mitigation guard |
| 38 | `vuln_escapability.move` | `wrap_for_migration` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 39 | `vuln_escapability.move` | `wrap_for_migration` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 40 | `vuln_time_incentivization.move` | `stake` | SUWC-TIME-02 | Regex | Locked position without unlock mechanism |
| 41 | `vuln_time_incentivization.move` | `StakingPool` | SUWC-CONS-01 | Regex | Struct missing CircuitBreakerPattern |
| 42 | `vuln_time_incentivization.move` | `claim` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 43 | `vuln_time_incentivization.move` | `lock_rewards` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 44 | `vuln_time_incentivization.move` | `release` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 45 | `vuln_time_incentivization.move` | `stake` | SUWC-AUTH-03 | SPARQL | ObjectCreation without OTW mitigation guard |
| 46 | `vuln_time_incentivization.move` | `stake` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |
| 47 | `vuln_time_incentivization.move` | `withdraw` | SUWC-CONS-01 | SPARQL | SharedStateMutation without mitigation guard |

---

## Noise by Contract

| Contract | Noise Count |
|----------|-------------|
| `suwc_auth_vulnerable.move` | 4 |
| `suwc_cons_vulnerable.move` | 3 |
| `suwc_res_vulnerable.move` | 12 |
| `suwc_time_vulnerable.move` | 9 |
| `vuln_access_control.move` | 3 |
| `vuln_circuit_breaker.move` | 2 |
| `vuln_escapability.move` | 6 |
| `vuln_time_incentivization.move` | 8 |
| **Total** | **47** |

> [!NOTE]
> No noise comes from Context B (`secure_vault_all_patterns.move`), Context C (`extract_*.move`), or Context D (`typus_vulnerable.move`). All 47 noise findings originate from Context A (`vuln_*.move`) and Context A2 (`suwc_*.move`) contracts.

---

## Noise by Pipeline

| Pipeline | Count | % of Noise |
|----------|-------|-----------|
| **Regex** | 20 | 42.6% |
| **SPARQL** | 27 | 57.4% |
| **Total** | **47** | 100% |

---

## Noise by Defect Type

| Type | Count | Noise Mechanism |
|------|-------|-----------------|
| SUWC-CONS-01 (SharedStateMutation / Missing CircuitBreaker) | **29** | Over-generalization: conflates any `&mut` mutation or struct definition with invariant violation |
| SUWC-AUTH-03 (ObjectCreation without OTW) | **6** | Over-generalization: flags standard user artifact creation as privileged capability creation |
| SUWC-AUTH-02 (OwnershipTransfer) | **5** | Over-generalization: conflates standard asset transfer with capability leakage |
| SUWC-TIME-02 (Locked position without unlock) | **4** | Cross-function blindness: extraction/unlock exists in another function within the module |
| SUWC-AUTH-01 (Missing capability check) | **2** | Heuristic misclassification: flags non-privileged functions as privileged |
| SUWC-AUTH-04 (Shared object without auth) | **1** | Misclassifies generic shared pool as restricted administrative object |
| **Total** | **47** | |

