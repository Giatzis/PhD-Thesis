# True Negatives (TNs) Detailed Source-Code Explanation

This document provides a highly granular, file-by-file breakdown of the exact True Negatives (TNs) across Contexts A, A2, B, and D in the evaluation corpus. The data presented here maps exactly to the `.move` source code and confirms the numerical totals established in Table 18.

## What is a True Negative in this Evaluation?
In the context of the Sokolova & Lapalme single-unit evaluation principle, a True Negative (TN) is an evaluation unit (a function or struct) that perfectly meets two conditions:
1. **Ground Truth:** It is genuinely secure (it does *not* contain a planted vulnerability).
2. **Analyzer Output:** The analyzer correctly recognized it as secure and did *not* flag it as a False Positive in the primary regex pipeline.

The presence of TNs is critical because they prove the analyzer's ability to distinguish, between a vulnerable function, and a safe function, in the exact same contract.

---

## Context A: Vulnerable Contracts (8 TNs)
**Total TNs:** 8

Across the 4 contracts in Context A, the developer intentionally planted 25 defect instances. However, smart contracts cannot function solely on vulnerable methods; they require secure helper functions, safe structs, and baseline operational logic to compile and run.

The 8 TNs in Context A represent these **secure operational units**. By cross-referencing the `.move` source code with the regex analyzer output, the exact 8 TN units are:

*   **`vuln_access_control.move` (2 TNs):**
    1.  `buy_token` (function): A standard token purchase logic that correctly bypasses privileged capability checks.
    2.  `TokenSale` (struct): A secure state struct. *(Note: While flagged by SPARQL for missing a circuit breaker, it had 0 regex findings, making it a TN in the Table 18 regex matrix).*

*   **`vuln_circuit_breaker.move` (3 TNs):**
    3.  `add_liquidity` (function): A secure AMM liquidity provision method.
    4.  `remove_liquidity` (function): A secure AMM liquidity removal method.
    5.  `Pool` (struct): The core liquidity pool struct. 

*   **`vuln_escapability.move` (3 TNs):**
    6.  `authorize_upgrade` (function): Secure operational function.
    7.  `commit_upgrade` (function): Secure operational function.
    8.  `deposit` (function): A secure, permissionless asset deposit function.

While the analyzer aggressively flagged the 23 planted TPs in Context A, it successfully read these 8 secure units, recognized that their state mutations or capability checks were architecturally sound, and correctly ignored them, resulting in 0 False Positives (FPs) for Context A in Table 18.

---

## Context A2: SUWC-Category Contracts (6 TNs)
**Total TNs:** 6

Context A2 mirrors Context A but is structured around the 13 SUWC taxonomy categories. Across the 4 SUWC contracts, there are 6 secure evaluation units that act as True Negatives:

*   **`suwc_auth_vulnerable.move` (2 TNs):**
    1.  `deposit` (function): Permissionless deposit logic that correctly does not require `GovernanceCap`.
    2.  `Proposal` (struct): A standard governance state struct.

*   **`suwc_cons_vulnerable.move` (2 TNs):**
    3.  `add_liquidity` (function): Secure AMM liquidity addition.
    4.  `remove_liquidity` (function): Secure AMM liquidity removal.

*   **`suwc_res_vulnerable.move` (2 TNs):**
    5.  `deposit` (function): Secure asset routing logic.
    6.  `create_swap_proof` (function): A secure helper function correctly isolated from the hot-potato vulnerabilities.

Because a permissionless `deposit` does not violate the SUWC-AUTH or SUWC-RES taxonomies, it is ground-truth secure. The analyzer parses the logic, determines it does not pose an unauthorized mutation risk, and correctly leaves it unflagged.

---

## Context D: Typus Finance Exploit (2 TNs)
**Total TNs:** 2
**Contract:** `typus_vulnerable.move`

Context D is a reconstruction of a real-world $3.44M exploit. The evaluation unit count for Context D is 5 total units:
*   **3 TPs:** `update_price` (missing auth guard), `swap` (missing invariant guard), and `PriceOracle` (missing circuit breaker).
*   **2 TNs:** The safe units not involved in the exploit path.

The exact 2 TNs are:
1.  **`add_liquidity`** (function)
2.  **`remove_liquidity`** (function)

**Why they are TNs:**
In the real-world Typus exploit, the attack vector was entirely isolated to the `update_price` and `swap` functions. The `add_liquidity` and `remove_liquidity` functions were architecturally sound and did not contribute to the exploit. 
*   The analyzer correctly flagged the exploit paths (3 TPs).
*   Simultaneously, it scanned `add_liquidity` and `remove_liquidity`, recognized they were secure within the context of the exploit, and correctly ignored them in the regex pipeline. *(While the SPARQL pipeline flagged them as Shared State Mutations, these are correctly abstracted as BLWs findings, leaving their matrix classification unaffected in Table 18).*

---

## Context B: Secure Vault (10 TNs)
**Total TNs:** 10
**Contract:** `secure_vault_all_patterns.move`

Context B is unique because it contains **0 planted defects**. It was explicitly engineered to implement all 4 recognized safe design patterns (e.g., proper capability usage, correct OTW implementation). 

Because the entire contract is ground-truth secure, **all 10 evaluated functions and structs inside this contract are True Negatives**.

The 10 TNs consist of 7 secure functions and **3 secure structs** (`AdminCap`, `SecureVault`, `VestingSchedule`).
*   Even though the analyzer surfaced 3 Business Logic Warnings (BLWs) on units like `AdminCap`, `withdraw`, and `create_vault`, these are qualitative design-level questions, not regex errors. 
*   Mathematically, in the strict confines of the Table 18 confusion matrix, the analyzer generated 0 False Positives, meaning all 10 evaluation units successfully resolved as True Negatives. This proves the tool can scan a heavily complex, pattern-rich secure contract without hallucinating regex errors.

---
