# Detailed Classification of Findings per Contract
This document classifies all findings from the analyzer output **per contract** into exactly one of four categories: **TP**, **BLW**, **FP**, or **Noise**.

## `extract_time_incentivization.move` — 1 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-03 | `new_wallet` | SPARQL | **FP** | Deterministic misclassification (FP root cause) |

### Summary

| Category | Count |
|---|---|
| FP (not planted, wrongly flagged) | **1** |
| **Total Findings** | **1** |

---

## `secure_vault_all_patterns.move` — 3 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-02 | `AdminCap` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 2 | TIME-01 | `withdraw` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 3 | AUTH-03 | `create_vault` | SPARQL | **BLW** | Emergent design-level finding (§7.7.3) |

### Summary

| Category | Count |
|---|---|
| BLW (emergent, correctly detected) | **3** |
| **Total Findings** | **3** |

---

## `suwc_auth_vulnerable.move` — 15 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `set_fee_rate` | Regex | **TP** | Planted defect correctly detected |
| 2 | AUTH-04 | `set_fee_rate` | Regex | **TP** | Planted defect correctly detected |
| 3 | AUTH-01 | `emergency_withdraw` | Regex | **TP** | Planted defect correctly detected |
| 4 | AUTH-04 | `emergency_withdraw` | Regex | **TP** | Planted defect correctly detected |
| 5 | AUTH-01 | `pause_treasury` | Regex | **TP** | Planted defect correctly detected |
| 6 | AUTH-04 | `pause_treasury` | Regex | **TP** | Planted defect correctly detected |
| 7 | AUTH-01 | `update_admin` | Regex | **TP** | Planted defect correctly detected |
| 8 | AUTH-04 | `update_admin` | Regex | **TP** | Planted defect correctly detected |
| 9 | AUTH-02 | `GovernanceCap` | Regex | **TP** | Planted defect correctly detected |
| 10 | AUTH-02 | `TreasuryAuthCap` | Regex | **TP** | Planted defect correctly detected |
| 11 | AUTH-03 | `init` | Regex | **TP** | Planted defect correctly detected |
| 12 | CONS-01 | `Treasury` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 13 | CONS-01 | `deposit` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 14 | AUTH-02 | `emergency_withdraw` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 15 | AUTH-02 | `init` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **11** |
| Noise (over-generalization) | **4** |
| **Total Findings** | **15** |

---

## `suwc_cons_vulnerable.move` — 6 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `batch_distribute` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 2 | CONS-01 | `swap_a_to_b` | Regex | **TP** | Planted defect correctly detected |
| 3 | CONS-01 | `swap_b_to_a` | Regex | **TP** | Planted defect correctly detected |
| 4 | CONS-02 | `batch_distribute` | Regex | **TP** | Planted defect correctly detected |
| 5 | CONS-01 | `add_liquidity` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 6 | CONS-01 | `remove_liquidity` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **3** |
| Noise (over-generalization) | **3** |
| **Total Findings** | **6** |

---

## `suwc_res_vulnerable.move` — 15 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `burn_to_null` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 2 | TIME-02 | `wrap_assets` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 3 | TIME-02 | `wrap_tokens` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 4 | RES-01 | `FlashLoanReceipt` | Regex | **TP** | Planted defect correctly detected |
| 5 | RES-01 | `SwapProof` | Regex | **TP** | Planted defect correctly detected |
| 6 | RES-03 | `burn_to_null` | Regex | **TP** | Planted defect correctly detected |
| 7 | CONS-01 | `AssetWrapper` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 8 | CONS-01 | `TokenContainer` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 9 | CONS-01 | `Pool` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 10 | AUTH-02 | `burn_to_null` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 11 | CONS-01 | `deposit` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 12 | CONS-01 | `deposit_repayment` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 13 | CONS-01 | `get_flash_loan` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 14 | AUTH-03 | `wrap_assets` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 15 | AUTH-03 | `wrap_tokens` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **3** |
| Noise (over-generalization) | **12** |
| FN (planted, missed) | **2** (targets: `AssetWrapper` RES-02, `TokenContainer` RES-02) |
| **Total Findings** | **15** |

---

## `suwc_time_vulnerable.move` — 17 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | TIME-02 | `create_vault` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 2 | TIME-03 | `create_vault` | Regex | **TP** | Planted defect correctly detected |
| 3 | TIME-01 | `claim_rewards` | Regex | **TP** | Planted defect correctly detected |
| 4 | TIME-01 | `withdraw_vested` | Regex | **TP** | Planted defect correctly detected |
| 5 | TIME-01 | `release_tokens` | Regex | **TP** | Planted defect correctly detected |
| 6 | TIME-02 | `stake` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 7 | TIME-03 | `stake` | Regex | **TP** | Planted defect correctly detected |
| 8 | TIME-03 | `check_elapsed` | Regex | **TP** | Planted defect correctly detected |
| 9 | TIME-03 | `compound_and_restake` | Regex | **TP** | Planted defect correctly detected |
| 10 | TIME-04 | `compound_and_restake` | Regex | **TP** | Planted defect correctly detected |
| 11 | CONS-01 | `VestingVault` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 12 | CONS-01 | `RewardPool` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 13 | CONS-01 | `claim_rewards` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 14 | AUTH-03 | `create_vault` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 15 | CONS-01 | `lock_rewards` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 16 | AUTH-03 | `stake` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 17 | CONS-01 | `stake` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **8** |
| Noise (over-generalization) | **9** |
| FN (planted, missed) | **1** (targets: `lock_rewards` TIME-02) |
| **Total Findings** | **17** |

---

## `typus_vulnerable.move` — 7 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `update_price` | Regex | **TP** | Planted defect correctly detected |
| 2 | AUTH-04 | `update_price` | Regex | **TP** | Planted defect correctly detected |
| 3 | AUTH-01 | `get_price` | Regex | **FP** | Deterministic misclassification (FP root cause) |
| 4 | CONS-01 | `swap` | Regex | **TP** | Planted defect correctly detected |
| 5 | CONS-01 | `PriceOracle` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 6 | CONS-01 | `add_liquidity` | SPARQL | **BLW** | Emergent design-level finding (§7.7.3) |
| 7 | CONS-01 | `remove_liquidity` | SPARQL | **BLW** | Emergent design-level finding (§7.7.3) |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **3** |
| BLW (emergent, correctly detected) | **3** |
| FP (not planted, wrongly flagged) | **1** |
| **Total Findings** | **7** |

---

## `vuln_access_control.move` — 11 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `set_price` | Regex | **TP** | Planted defect correctly detected |
| 2 | AUTH-04 | `set_price` | Regex | **TP** | Planted defect correctly detected |
| 3 | AUTH-01 | `withdraw_funds` | Regex | **TP** | Planted defect correctly detected |
| 4 | AUTH-04 | `withdraw_funds` | Regex | **TP** | Planted defect correctly detected |
| 5 | AUTH-01 | `toggle_sale` | Regex | **TP** | Planted defect correctly detected |
| 6 | AUTH-04 | `toggle_sale` | Regex | **TP** | Planted defect correctly detected |
| 7 | AUTH-02 | `SaleCap` | Regex | **TP** | Planted defect correctly detected |
| 8 | AUTH-03 | `init` | Regex | **TP** | Planted defect correctly detected |
| 9 | CONS-01 | `TokenSale` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 10 | AUTH-02 | `init` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 11 | AUTH-02 | `withdraw_funds` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **8** |
| Noise (over-generalization) | **3** |
| **Total Findings** | **11** |

---

## `vuln_circuit_breaker.move` — 7 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `distribute_fees` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 2 | AUTH-04 | `distribute_fees` | Regex | **FP** | Deterministic misclassification (FP root cause) |
| 3 | CONS-01 | `swap_a_to_b` | Regex | **TP** | Planted defect correctly detected |
| 4 | CONS-01 | `swap_b_to_a` | Regex | **TP** | Planted defect correctly detected |
| 5 | CONS-02 | `distribute_fees` | Regex | **TP** | Planted defect correctly detected |
| 6 | CONS-01 | `add_liquidity` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 7 | CONS-01 | `remove_liquidity` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **3** |
| BLW (emergent, correctly detected) | **1** |
| FP (not planted, wrongly flagged) | **1** |
| Noise (over-generalization) | **2** |
| **Total Findings** | **7** |

---

## `vuln_escapability.move` — 14 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | AUTH-01 | `wrap_for_migration` | Regex | **TP** | Planted defect correctly detected |
| 2 | AUTH-04 | `wrap_for_migration` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 3 | AUTH-01 | `burn_old_vault` | Regex | **FP** | Deterministic misclassification (FP root cause) |
| 4 | AUTH-01 | `send_to_burn` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 5 | AUTH-02 | `VaultUpgradeCap` | Regex | **TP** | Planted defect correctly detected |
| 6 | AUTH-02 | `MigrationAuthCap` | Regex | **TP** | Planted defect correctly detected |
| 7 | RES-01 | `UpgradeReceipt` | Regex | **TP** | Planted defect correctly detected |
| 8 | RES-03 | `send_to_burn` | Regex | **TP** | Planted defect correctly detected |
| 9 | CONS-01 | `MigrationWrapper` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 10 | CONS-01 | `Vault` | Regex | **BLW** | Emergent design-level finding (§7.7.3) |
| 11 | CONS-01 | `deposit` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 12 | AUTH-02 | `send_to_burn` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 13 | AUTH-03 | `wrap_for_migration` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 14 | CONS-01 | `wrap_for_migration` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **5** |
| BLW (emergent, correctly detected) | **2** |
| FP (not planted, wrongly flagged) | **1** |
| Noise (over-generalization) | **6** |
| FN (planted, missed) | **1** (targets: `MigrationWrapper` RES-02) |
| **Total Findings** | **14** |

---

## `vuln_time_incentivization.move` — 15 Findings Classification

| # | Finding | Target | Layer | Classification | Reason |
|---|---------|--------|-------|----------------|--------|
| 1 | TIME-02 | `stake` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 2 | TIME-03 | `stake` | Regex | **TP** | Planted defect correctly detected |
| 3 | TIME-01 | `claim` | Regex | **TP** | Planted defect correctly detected |
| 4 | TIME-01 | `withdraw` | Regex | **TP** | Planted defect correctly detected |
| 5 | TIME-03 | `calculate_rewards` | Regex | **TP** | Planted defect correctly detected |
| 6 | TIME-03 | `compound_rewards` | Regex | **TP** | Planted defect correctly detected |
| 7 | TIME-04 | `compound_rewards` | Regex | **TP** | Planted defect correctly detected |
| 8 | TIME-01 | `release` | Regex | **TP** | Planted defect correctly detected |
| 9 | CONS-01 | `StakingPool` | Regex | **Noise** | SPARQL/Regex over-generalization |
| 10 | CONS-01 | `claim` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 11 | CONS-01 | `lock_rewards` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 12 | CONS-01 | `release` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 13 | AUTH-03 | `stake` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 14 | CONS-01 | `stake` | SPARQL | **Noise** | SPARQL/Regex over-generalization |
| 15 | CONS-01 | `withdraw` | SPARQL | **Noise** | SPARQL/Regex over-generalization |

### Summary

| Category | Count |
|---|---|
| TP (planted, correctly detected) | **7** |
| Noise (over-generalization) | **8** |
| FN (planted, missed) | **1** (targets: `lock_rewards` TIME-02) |
| **Total Findings** | **15** |

---

