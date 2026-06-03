# False Positives (FPs) and False Negatives (FNs) — Contract Location Reference

This document identifies the exact contract file for each of the 4 confirmed False Positives (FPs) and 2 confirmed False Negatives (FNs).

---

## Part 1 — Confirmed False Positives (4)

All four FPs originate from the SPARQL detection layer, with the exception of FP-2 which originates from a single regex edge case. None of them affect the regex pipeline's architectural-scope results or the 0% FPR reported in Table 19.

---

### FP-1 — SUWC-AUTH-03 on `new_wallet`

| Field | Detail |
|-------|--------|
| **Contract** | `extract_time_incentivization.move` |
| **Context** | C — Official Extracts (MystenLabs/Sui Framework) |
| **Target** | `new_wallet` function |
| **Finding** | SPARQL flags `new_wallet` for performing ObjectCreation without a One-Time Witness (OTW) mitigation guard |
| **Detection Layer** | SPARQL — `ObjectCreation → indicatesDefectRisk(AUTH-03)` chain |
| **Why it is a FP** | `new_wallet` creates a personal vesting wallet for a user — a non-privileged user artifact. Unrestricted creation is the correct and intended design: any user should be able to create their own wallet. The SPARQL filter cannot distinguish between privileged capability creation (AdminCap, DenyCapV2) and non-privileged user artifact creation (a vesting wallet). |
| **Structurally identical to** | BLW 1.3 (`create_vault` in `secure_vault_all_patterns.move`), which triggers the same SPARQL chain — but `create_vault` creates **privileged** objects, making the business logic question genuinely open (BLW), whereas `new_wallet` creates a non-privileged user artifact, making the answer obvious (FP). |
| **Root cause** | The SPARQL Phase 2b filter lacks an object privilege discriminator — it fires identically on capability creation and user-artifact creation. |
| **Future Fix** | Adding an object privilege discriminator to the SPARQL chain that checks whether the created object is a capability type before firing AUTH-03. |

---

### FP-2 — SUWC-AUTH-01 on `get_price`

| Field | Detail |
|-------|--------|
| **Contract** | `typus_vulnerable.move` |
| **Context** | D — Real Exploit (Typus Finance) |
| **Target** | `get_price` function |
| **Finding** | Regex flags `get_price` as a privileged function that modifies state without a capability check (CRITICAL AUTH-01) |
| **Detection Layer** | Regex — heuristic privileged-function classification + mutation detection |
| **Why it is a FP** | `get_price` is a read-only function that takes an immutable reference and returns a computed value. It cannot modify anything. The AUTH-01 detection on this function is a false positive. |
| **Root cause** | The mutation detection regex matches the `=` character inside comparison expressions (`==`) within if-else branches, incorrectly interpreting equality comparisons as assignment operations. The legitimate CRITICAL AUTH-01 on `update_price` — the actual root cause of the Typus exploit — is unaffected by this edge case and is correctly detected as a TP. |
| **Future Fix** | Refining the mutation detection regex to match only assignment operators (`=` not preceded or followed by `=`, `!`, `<`, `>`), excluding equality comparisons (`==`) and inequality operators. |

---

### FP-3 — SUWC-AUTH-04 on `distribute_fees`

| Field | Detail |
|-------|--------|
| **Contract** | `vuln_circuit_breaker.move` |
| **Context** | A — Vulnerable Contracts |
| **Target** | `distribute_fees` function |
| **Finding** | Regex flags function for modifying a shared object without authorization (AUTH-04) |
| **Detection Layer** | Regex — heuristic shared-object mutation |
| **Why it is a FP** | The regex layer produced a False Positive because its heuristic misclassified a generic shared liquidity pool (`&mut Pool`) as a restricted administrative protocol object. While the function genuinely lacks a capability guard (correctly flagged as AUTH-01), the AUTH-04 rule specifically detects unauthorized mutations of restricted protocol objects, falsely triggering an object-level authorization warning where none was architecturally required. |
| **Root cause** | The regex layer over-generates by misclassifying generic shared business objects as restricted administrative objects requiring strict object-level authorization. |
| **Future Fix** | Refining the AUTH-04 heuristic to distinguish between generic shared state (like AMM pools) and restricted administrative objects. |

---

### FP-4 — SUWC-AUTH-01 on `burn_old_vault`

| Field | Detail |
|-------|--------|
| **Contract** | `vuln_escapability.move` |
| **Context** | A — Vulnerable Contracts |
| **Target** | `burn_old_vault` function |
| **Finding** | Regex flags function as a privileged operation missing a capability check (AUTH-01) |
| **Detection Layer** | Regex — heuristic privileged-function classification |
| **Why it is a FP** | `burn_old_vault` is a destructive cleanup function intended to delete an obsolete vault object passed by value. It is not a privileged administrative operation requiring a capability guard in this context. |
| **Root cause** | The regex heuristic flags any public function containing `object::delete` without checking the architectural intent of the destruction routine. |
| **Future Fix** | Refining privilege heuristics to differentiate explicit cleanup/destruction routines from administrative control functions. |

---

## Part 2 — Confirmed False Negatives (2)

Both FNs originate from the regex detection layer. Both recur identically across independently designed contracts, confirming they are structural gate limitations rather than isolated, corpus-specific misses.

---

### FN-1 — RES-02 (Roach Motel) not detected on `AssetWrapper`, `TokenContainer`, `MigrationWrapper`

| Field | Detail |
|-------|--------|
| **Contracts** | `suwc_res_vulnerable.move` (Context A2, ×2 instances); `vuln_escapability.move` (Context A, ×1 instance) |
| **Context** | A — Vulnerable Contracts (×1); A2 — SUWC Contracts (×2) |
| **Target** | `AssetWrapper` struct, `TokenContainer` struct (`suwc_res_vulnerable.move`); `MigrationWrapper` struct (`vuln_escapability.move`) |
| **Expected Finding** | SUWC-RES-02 (Roach Motel) — struct can receive assets but has no extraction function, meaning stored assets are permanently locked |
| **Detection Layer** | Regex — module-level extraction function check |
| **Why it is a FN** | The RES-02 detection check operates at module level: if **any** function in the module performs an extraction operation (e.g., `get_flash_loan` in `suwc_res_vulnerable`), RES-02 is suppressed for **all** structs in that module. In `suwc_res_vulnerable`, the function `get_flash_loan` extracts from the pool's reserves, setting the extraction flag to true for the entire module — incorrectly suppressing RES-02 on `AssetWrapper` and `TokenContainer`, which have no extraction function of their own. The same suppression logic affects `MigrationWrapper` in `vuln_escapability`. |
| **Consequence** | This is the most consequential FN in the evaluation: a developer could receive a false assurance that their assets are recoverable when they are permanently locked. |
| **Root cause** | The extraction check is coarse-grained (module-level) rather than fine-grained (struct-specific). A module-level extraction operation suppresses RES-02 for all structs regardless of whether each individual struct has its own extraction path. |
| **Future Fix** | Making the extraction check struct-specific: RES-02 should fire on struct S if no function in the module extracts assets specifically from struct S — regardless of whether other structs in the module have extraction functions. |

---

### FN-2 — TIME-02 (Indefinite Lock) not detected on `lock_rewards`

| Field | Detail |
|-------|--------|
| **Contracts** | `suwc_time_vulnerable.move` (Context A2, ×1 instance); `vuln_time_incentivization.move` (Context A, ×1 instance) |
| **Context** | A — Vulnerable Contracts (×1); A2 — SUWC Contracts (×1) |
| **Target** | `lock_rewards` function |
| **Expected Finding** | SUWC-TIME-02 (Indefinite Lock) — function deposits assets into a time-constrained structure with no release mechanism, leading to permanently locked assets |
| **Detection Layer** | Regex — deposit + object creation co-detection gate |
| **Why it is a FN** | The TIME-02 detection requires two conditions to be satisfied simultaneously in the same function: (1) a deposit operation, and (2) an object creation. `lock_rewards` satisfies condition (1) — it deposits assets into a time-constrained pool — but it deposits into an **existing** shared pool object rather than creating a new one. The object creation condition (2) is never met, so the detection never fires. |
| **Cross-suite recurrence** | The identical FN occurs in both `suwc_time_vulnerable` and `vuln_time_incentivization`, two independently structured contracts organized around different primary test objectives. This confirms the miss is a structural gate limitation, not a corpus-specific artifact. |
| **Root cause** | The TIME-02 detection gate is too strict: it requires object creation as a proxy for "new time-constrained structure", but misses the case where an existing shared pool object serves as the time-constrained structure without a new object being created. |
| **Future Fix** | Adding a second TIME-02 detection variant: fire when a function deposits assets into an existing shared pool object **and** no module-level unlock function exists for the target field — regardless of whether a new object is created. |

---

## Summary Table

### False Positives

| # | Contract File | Context | Target | Finding | Detection Layer | Root Cause |
|---|--------------|---------|--------|---------|----------------|-----------|
| **FP-1** | `extract_time_incentivization.move` | C | `new_wallet` | AUTH-03 (SPARQL) | SPARQL | No object privilege discriminator in ObjectCreation chain |
| **FP-2** | `typus_vulnerable.move` | D | `get_price` | AUTH-01 (Regex) | Regex | Mutation regex matches `==` as assignment |
| **FP-3** | `vuln_circuit_breaker.move` | A | `distribute_fees` | AUTH-04 (Regex) | Regex | Misclassifies generic shared pool as restricted administrative object |
| **FP-4** | `vuln_escapability.move` | A | `burn_old_vault` | AUTH-01 (Regex) | Regex | Flags destructive cleanup function as privileged |

### False Negatives

| # | Contract Files | Contexts | Target | Expected Finding | Detection Layer | Root Cause |
|---|---------------|---------|--------|-----------------|----------------|-----------|
| **FN-1** | `suwc_res_vulnerable.move` (×2), `vuln_escapability.move` (×1) | A2 (×2), A (×1) | `AssetWrapper`, `TokenContainer`, `MigrationWrapper` structs | RES-02 (Roach Motel) | Regex | Module-level extraction check suppresses struct-specific FNs |
| **FN-2** | `suwc_time_vulnerable.move` (×1), `vuln_time_incentivization.move` (×1) | A2 (×1), A (×1) | `lock_rewards` | TIME-02 (Indefinite Lock) | Regex | Deposit + object creation co-detection gate misses deposit into existing shared objects |

