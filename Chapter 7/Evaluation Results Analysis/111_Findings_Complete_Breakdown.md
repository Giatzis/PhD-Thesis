# 111 Total Findings — Complete Breakdown Reference

---

## Master Arithmetic (Raw Findings)

| Category | Raw Findings | Description |
|----------|--------------|-------------|
| Planted-defect TPs | **51** | Correctly detected planted defects. These 51 raw findings collapse to **50 TP units** (Table 18) under the Sokolova principle (TIME-03 & TIME-04 co-fire merge). |
| Business Logic Warnings (BLWs) | **9** | Emergent design-level findings, counted as TP under Sokolova principle (§7.7.3). These 9 findings correspond to **7 BLWs**. |
| Layer-specific FPs | **4** | Confirmed false positives with identified deterministic root causes (§7.7.1). |
| Pipeline noise | **47** | Residual SPARQL/Regex over-generalizations not classified as FP or BLW. |
| **Total findings (Table 24)** | **111** | |

**(51 + 9 + 4 + 47 = 111)**

> **False Negatives (5 instances)** are **not** in the 111 — they are absences of output documented separately in §7.7.2.

---

## Context Totals (Table 24)

| Context | Total Findings | Planted TPs | BLW Findings | FPs | Pipeline Noise |
|---------|---------------|-------------|--------------|-----|--------------|
| A. Vulnerable Contracts | **47** | 23 | 3 | 2 | 19 |
| A2. SUWC Contracts | **53** | 25 | 0 | 0 | 28 |
| B. Secure Vault | **3** | 0 | 3 | 0 | 0 |
| C. Official Extracts | **1** | 0 | 0 | 1 | 0 |
| D. Typus Exploit | **7** | 3 | 3 | 1 | 0 |
| **Total** | **111** | **51** | **9** | **4** | **47** |

---

## The 51 Planted-Defect TP Findings

These are the ground-truth planted vulnerabilities correctly detected. 

| Context | Contract | Planted | Findings |
|---------|----------|---------|-------------|
| A | `vuln_access_control.move` | 8 | 8 |
| A | `vuln_circuit_breaker.move` | 3 | 3 |
| A | `vuln_escapability.move` | 6 | 5 |
| A | `vuln_time_incentivization.move` | 8 | 7 |
| A2 | `suwc_auth_vulnerable.move` | 11 | 11 |
| A2 | `suwc_cons_vulnerable.move` | 3 | 3 |
| A2 | `suwc_res_vulnerable.move` | 5 | 3 |
| A2 | `suwc_time_vulnerable.move` | 9 | 8* |
| D | `typus_vulnerable.move` | 3 | 3 |
| **Total** | | **56 planted** | **51 raw Findings (merged into 50 TPs)** |

> *\* `suwc_time_vulnerable.move` has 8 raw TP findings on 7 architectural units because `compound_and_restake` triggers both TIME-03 and TIME-04. These double-findings safely collapse to ensure Table 18 remains perfectly rigorous.*
> 

---

## The 7 Business Logic Warnings (§7.7.3)

BLWs are correctly detected findings — counted as TP under the Sokolova single-unit principle.  
They are **not** FPs. They surface genuine design-level questions that require developer judgment.

| BLW# | Context | Contract | Target | Finding | Business Logic Question |
|------|---------|----------|--------|---------|------------------------|
| 1.1 | B | `secure_vault_all_patterns` | `AdminCap` | AUTH-02 | Should admin capability be freely transferable? |
| 1.2 | B | `secure_vault_all_patterns` | `withdraw` | TIME-01 | Can admin drain vault before vesting completes? |
| 1.3 | B | `secure_vault_all_patterns` | `create_vault` | AUTH-03 | Should vault creation be singleton-constrained? |
| 2.1 | D | `typus_vulnerable` | `PriceOracle` struct | CONS-01 | Should oracle operations be haltable during anomalous activity? |
| 2.2 | D | `typus_vulnerable` | `add_liquidity`, `remove_liquidity` | CONS-01 (×2) | Should liquidity operations be pausable during an exploit? |
| 3.1 | A | `vuln_circuit_breaker` | `distribute_fees` | AUTH-01 | Should fee distribution be permissionless on a mutable shared pool? |
| 3.2 | A | `vuln_escapability` | `Vault`/`MigrationWrapper` structs | CONS-01 (×2) | Should escapability wrappers be haltable during migrations? |


---

## The 4 Layer-Specific FPs (§7.7.1)

False positives (findings the analyzer produced that are definitively wrong)  
with identified root causes.

| FP# | Context | Contract | Target | Finding | Root Cause | Layer |
|-----|---------|----------|--------|---------|------------|-------|
| FP-1 | C | `extract_time_incentivization` | `new_wallet` | AUTH-03 | SPARQL fires on any `object::new` regardless of privilege context — `new_wallet` creates a non-privileged user artifact. | SPARQL |
| FP-2 | D | `typus_vulnerable` | `get_price` | AUTH-01 | Regex mutation detection matches `=` inside a comparison expression — `get_price` is read-only. | Regex |
| FP-3 | A | `vuln_circuit_breaker` | `distribute_fees` | AUTH-04 | Misclassifies generic shared pool as restricted administrative object | Regex |
| FP-4 | A | `vuln_escapability` | `burn_old_vault` | AUTH-01 | Destructive cleanup function misclassified as a privileged operation requiring a capability check. | Regex |

---

## The 47 Pipeline Cross-Category Noise

Residual SPARQL and Regex findings that are neither documented FPs nor BLWs (over-generalization output from property-chain limitations and broad regex matches).

### Exact Distribution by Contract

| Contract | Noise Count | Primary SPARQL/Regex Patterns |
|----------|-------------|------------------------|
| `suwc_res_vulnerable.move` | 12 | AUTH-03 on wrappers, AUTH-02 on burns/transfers, CONS-01 struct-level absence, TIME-02 cross-function blindness |
| `suwc_time_vulnerable.move` | 9 | AUTH-03 on vaults/staking, CONS-01 struct-level + mut functions, TIME-02 cross-function |
| `vuln_escapability.move` | 6 | AUTH-02/03 on migrations, CONS-01 on shared state mutations |
| `vuln_time_incentivization.move` | 8 | AUTH-03 on staking ops, CONS-01 on shared pools, TIME-02 cross-function |
| `suwc_auth_vulnerable.move` | 4 | AUTH-02 on init/withdraw, CONS-01 on shared pool/struct |
| `vuln_access_control.move` | 3 | AUTH-02 on init/withdraw, CONS-01 on struct |
| `suwc_cons_vulnerable.move` | 3 | AUTH-01 heuristic mismatch, CONS-01 SPARQL over-generalization |
| `vuln_circuit_breaker.move` | 2 | CONS-01 SPARQL on shared state mutations |
| **Total** | **47** | |

### Dominant Root Causes of Noise

| Type | Count | Noise Mechanism |
|------|-------|-----------------|
| **SUWC-CONS-01** | **29** | Over-generalization: conflates any `&mut` mutation or struct definition with invariant violation. |
| **SUWC-AUTH-03** | **6** | Over-generalization: flags standard user artifact creation as privileged capability creation. |
| **SUWC-AUTH-02** | **5** | Over-generalization: conflates standard asset transfer with capability leakage. |
| **SUWC-TIME-02** | **4** | Cross-function blindness: extraction/unlock exists in another function within the module. |
| **SUWC-AUTH-01/04** | **3** | Heuristic misclassification on non-privileged or shared objects. |

---

## Summary Verification

```
Planted-defect TP Findings:  51
Business Logic Warnings:      9  (corresponding to 7 BLWs)
Layer-specific FPs (§7.7.1):  4
Pipeline cross-category noise: 47
─────────────────────────────────
Total findings (Table 24):  111  ✓

False Negatives (§7.7.2):     5  (not in the 111 — absences of output)
```

---

## The 94 Architectural Evaluation Units (Matrix Denominator)

While the analyzer produced 111 total findings (outputs), the confusion matrix (Table 18) evaluates these findings against exactly **94 Architectural Units** (inputs).

To satisfy the Sokolova & Lapalme principle while supporting the SUWC taxonomy, the architectural unit is defined as both functions and capability structs. 

The 94 units break down as follows:
- **80 Evaluated Functions:** (42 TPs + 38 TNs)
- **14 Evaluated Structs:** (8 TPs + 6 TNs)

*(Note: The missed RES-02 and TIME-02 defects are excluded from this 94-unit denominator because their root causes—module-level extraction checks and object-lifecycle gates—operate outside the scope of a single architectural unit).*
