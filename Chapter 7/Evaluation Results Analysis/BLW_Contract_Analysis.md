# Business Logic Warnings (BLWs) — Contract Location Reference

This document identifies the exact contract file for each of the 7 BLWs (that originate from 9 true detections).

---

## Group 1 — SecureVault (3 BLWs)

**Contract file:** `secure_vault_all_patterns.move`  
**Context:** B — Secure Vault  
**Design intent:** Intentionally well-designed contract implementing all 4 security patterns correctly. BLWs surface design-level governance tensions, not code-level bugs.

### BLW 1.1 — SUWC-AUTH-02 on `AdminCap`

| Field | Detail |
|-------|--------|
| **Contract** | `secure_vault_all_patterns.move` |
| **Target** | `AdminCap` struct (`key`, `store` abilities) |
| **Finding** | Capability with `store` ability allows unrestricted transfer to any address |
| **Detection Layer** | Regex — struct capability check |
| **Business Logic Question** | *Should the admin capability be freely transferable to arbitrary third parties?* |

The `store` ability enables anyone holding the AdminCap to transfer it — including to a compromised wallet or phishing contract. The analyzer surfaces a governance question: should admin rotation be unrestricted (current design) or governed (e.g., timelock, multisig)? Real incidents such as Ronin Bridge and Harmony Horizon confirm that admin key compromise via transferability is a primary attack vector.

---

### BLW 1.2 — SUWC-TIME-01 on `withdraw`

| Field | Detail |
|-------|--------|
| **Contract** | `secure_vault_all_patterns.move` |
| **Target** | `withdraw` function |
| **Finding** | Function releases assets without temporal constraint, despite the contract implementing TimeIncentivizationPattern for users |
| **Detection Layer** | Regex — temporal outflow without clock guard |
| **Business Logic Question** | *Can the admin drain the vault before beneficiaries' vesting schedules complete?* |

This is the strongest BLW in the entire SecureVault group. It surfaces a direct tension between two co-existing security patterns: the AccessControlPattern grants the admin unrestricted withdrawal authority, while the TimeIncentivizationPattern promises beneficiaries time-locked vesting. These guarantees are semantically contradictory — the admin can drain the vault at any moment, undermining every `create_vesting` and `claim_vested` commitment made to users. No syntax-level tool surfaces this cross-pattern conflict, because both patterns are correctly implemented in isolation.

---

### BLW 1.3 — SUWC-AUTH-03 on `create_vault`

| Field | Detail |
|-------|--------|
| **Contract** | `secure_vault_all_patterns.move` |
| **Target** | `create_vault` function |
| **Finding** | Creates privileged capability objects (AdminCap, DenyCapV2) without a One-Time Witness (OTW) singleton constraint |
| **Detection Layer** | SPARQL — ObjectCreation without OTW mitigation guard |
| **Business Logic Question** | *Should vault creation be unrestricted, or singleton-constrained?* |

The SPARQL engine flags that `create_vault` creates privileged objects (AdminCap, DenyCapV2) without an OTW guard, meaning any user can create unlimited vaults with unlimited admin capabilities. This surfaces a governance architecture question: unconstrained creation of privileged protocol objects can lead to liquidity fragmentation, phishing vectors, or governance confusion. The key distinction from FP-1 (`new_wallet`) is object type: here the created objects are capabilities, not user artifacts.

---

## Group 2 — Typus Finance Reconstruction (2 BLWs)

**Contract file:** `typus_vulnerable.move`  
**Context:** D — Real Exploit (Typus Finance)  
**Design intent:** Reconstruction of a real-world $3.44M exploit. BLWs surface why the exploit caused maximum damage beyond the primary root cause already detected as TPs (AUTH-01 on `update_price`, CONS-01 on `swap`).

### BLW 2.1 — SUWC-CONS-01 on `PriceOracle` struct

| Field | Detail |
|-------|--------|
| **Contract** | `typus_vulnerable.move` |
| **Target** | `PriceOracle` struct |
| **Finding** | Struct missing CircuitBreakerPattern — no `is_paused`, `pause_cap`, or `DenyCapV2` field detected |
| **Detection Layer** | Regex — struct-level CircuitBreakerPattern absence check |
| **Business Logic Question** | *Should price oracle operations be haltable during anomalous market activity?* |

This struct-level detection goes beyond curve invariants to ask a design completeness question. The real Typus team required 34 minutes of manual network intervention precisely because no built-in pause existed at the oracle level. A circuit breaker on the oracle struct itself could have contained the damage window from 34 minutes to seconds.

---

### BLW 2.2 — SUWC-CONS-01 on `add_liquidity` and `remove_liquidity`

| Field | Detail |
|-------|--------|
| **Contract** | `typus_vulnerable.move` |
| **Target** | `add_liquidity` and `remove_liquidity` functions |
| **Finding** | Both functions perform SharedStateMutation without any mitigation guard in the knowledge graph |
| **Detection Layer** | SPARQL — SharedStateMutation without `mitigatesDefect` |
| **Business Logic Question** | *Should liquidity operations be pausable during an active exploit?* |

While these are standard public DeFi operations, the business logic question is genuine: during the real Typus incident, the attacker continued interacting with pool operations throughout the 34-minute halt window because nothing was pausable. The tool surfaces that even standard deposit/withdrawal operations should be haltable in an emergency — the exact lesson confirmed by the post-mortem. Both functions trigger the identical SPARQL reasoning chain and raise the identical business logic question, making them two distinct detection findings that share the same architectural root cause.

---

## Group 3 — Vuln Contracts (2 BLWs)

**Context:** A — Vulnerable Contracts (4 contracts: `vuln_access_control.move`, `vuln_circuit_breaker.move`, `vuln_escapability.move`, `vuln_time_incentivization.move`)  
**Design intent:** Each contract is organized around one primary vulnerability pattern. BLWs demonstrate the analyzer's cross-category insight — surfacing design tensions the contract designer did not intend to plant.

### BLW 3.1 — SUWC-AUTH-01 on `distribute_fees`

| Field | Detail |
|-------|--------|
| **Contract** | `vuln_circuit_breaker.move` |
| **Target** | `distribute_fees` function |
| **Finding** | Privileged function mutates `&mut Pool` (shared object) without any capability check |
| **Detection Layer** | Regex — privileged function without capability guard |
| **Business Logic Question** | *Should fee distribution be permissionless on a mutable shared pool?* |

This is the strongest cross-category BLW in the entire evaluation corpus. The contract was designed to test CONS-02 (unbounded loops on `distribute_fees`), not AUTH gaps. Yet the analyzer's behavioral classification correctly surfaces a separate, unintended AUTH design question: in real DeFi, permissionless fee distribution on a mutable shared pool can be exploited via sandwich attacks or gas griefing. A CONS-focused contract contains an AUTH design tension visible only through semantic behavioral classification — precisely the kind of finding that separates a design advisor from a syntax checker.

### BLW 3.2 — SUWC-CONS-01 on `Vault` and `MigrationWrapper` structs

| Field | Detail |
|-------|--------|
| **Contract** | `vuln_escapability.move` |
| **Target** | `Vault` struct and `MigrationWrapper` struct |
| **Finding** | Financial structs involved in upgrade/migration operations missing CircuitBreakerPattern |
| **Detection Layer** | Regex — struct-level CircuitBreakerPattern absence check |
| **Business Logic Question** | *Should escapability wrappers holding financial state be haltable during a compromised migration?* |

The business logic question is particularly relevant in the migration context: escapability wrappers hold financial state during a protocol upgrade, and an irreversible migration with no emergency stop creates a window of maximum exposure between the old and new contract states. The contract was built to test RES-01 and RES-03 vulnerabilities, yet the analyzer surfaces this independent design completeness question through struct-level SPARQL analysis.

---

## Master Summary Table

| # | Contract File | Context | Target | Finding | Detection Layer |
|---|--------------|---------|--------|---------|----------------|
| **1.1** | `secure_vault_all_patterns.move` | B | `AdminCap` struct | AUTH-02 | SPARQL |
| **1.2** | `secure_vault_all_patterns.move` | B | `withdraw` | TIME-01 | Regex |
| **1.3** | `secure_vault_all_patterns.move` | B | `create_vault` | AUTH-03 | SPARQL |
| **2.1** | `typus_vulnerable.move` | D | `PriceOracle` struct | CONS-01 | Regex (struct) |
| **2.2** | `typus_vulnerable.move` | D | `add_liquidity`, `remove_liquidity` | CONS-01 | SPARQL |
| **3.1** | `vuln_circuit_breaker.move` | A | `distribute_fees` | AUTH-01 | Regex |
| **3.2** | `vuln_escapability.move` | A | `Vault`, `MigrationWrapper` structs | CONS-01 | Regex (struct) |

**Total: 7 BLWs across 5 contract files and 3 evaluation contexts.**
