# **DCR Graph Patterns — Sui Move Analyzer**

This document describes the four **hardcoded behavioral patterns** detected and modeled by the Sui Move Analyzer. Each pattern is automatically extracted from a smart contract's structure and rendered as a DCR graph, capturing the lifecycle of a key Sui capability object.

DCR graphs represent reactive, event-driven workflows. Each node is an **activity** (a contract function), and each directed edge encodes a **behavioral constraint** between two activities.

## **DCR Relations Legend**

| Relation | Color | Semantics |
| :---- | :---- | :---- |
| **Condition** | 🟠 Orange | A must happen before B can execute |
| **Response** | 🔵 Blue | A forces B to eventually happen |
| **Exclusion** | 🔴 Red | A prevents B from happening |
| **Inclusion** | 🟢 Green | A allows B to happen again |

## **Pattern 1 — AccessControlPattern**

**Lifecycle of:** AdminCap

### **Description**

The AccessControlPattern captures the role management lifecycle enforced by an AdminCap capability object. In Sui Move, AdminCap is a **singleton object** that grants its holder exclusive rights to perform privileged operations. This pattern models the three fundamental operations that together define a complete access control structure: granting a role, executing a protected call, and revoking a role.

### **DCR Graph — Activities & Relations**

| Activity | Function | Role |
| :---- | :---- | :---- |
| Grant Role | fn: new() | Mints and transfers AdminCap to a new role holder |
| Protected Call | fn: protected\_call() | Executes privileged logic gated by AdminCap possession |
| Revoke Role | fn: destroy() | Burns AdminCap, permanently removing the role |

**Behavioral constraints encoded:**

* Grant Role →🟠**Condition**→ Protected Call: A role must be granted before a protected call can execute.  
* Grant Role →🟠**Condition**→ Revoke Role: A role must exist before it can be revoked.  
* Revoke Role →🔴**Exclusion**→ Protected Call: Once the role is revoked, the protected call is permanently disabled.  
* Protected Call →🟢**Inclusion**→ Grant Role: After a protected call executes, a new role can be re-granted (representing role rotation / re-granting).

### **Vulnerability Relevance**

Missing or bypassable AdminCap checks in protected\_call() constitute an **Access Control Flaw**. If Grant Role lacks a proper one-time initialization guard, an attacker may mint multiple AdminCap instances, breaking the singleton assumption. If Revoke Role is absent or unreachable, the pattern is incomplete and may signal a **privilege lock-in** vulnerability.

## **Pattern 2 — CircuitBreakerPattern**

**Lifecycle of:** DenyCap

### **Description**

The CircuitBreakerPattern models the emergency stop mechanism implemented via a DenyCap object. A circuit breaker allows an authorized party to **pause all operations** in response to an incident and **resume them** once the threat is resolved. This is a critical safety pattern in production DeFi contracts, and its absence or incorrect implementation is a high-severity business logic vulnerability.

### **DCR Graph — Activities & Relations**

| Activity | Function | Role |
| :---- | :---- | :---- |
| Operational Call | fn: execute() | The primary business operation, guarded by the circuit breaker |
| Pause Operations | fn: pause() | Activates the deny state, halting execute() |
| Unpause Operations | fn: unpause() | Deactivates the deny state, re-enabling execute() |

**Behavioral constraints encoded:**

* Pause Operations →🔴**Exclusion**→ Operational Call: Once paused, the main operation cannot execute.  
* Pause Operations →🟢**Inclusion**→ Unpause Operations: Pausing makes an unpause action possible.  
* Unpause Operations →🟢**Inclusion**→ Operational Call: Unpausing re-enables the operational call.  
* Unpause Operations →🟢**Inclusion**→ Pause Operations: Unpausing explicitly re-enables the ability to pause operations again when needed.

### **Vulnerability Relevance**

A contract missing this pattern entirely has **no emergency stop capability** — a critical omission for any contract holding user funds. Incomplete implementations (e.g., pause() exists but Operational Call does not check the deny state) produce a **Circuit Breaker Failure**, where the safety mechanism is present in name but ineffective in execution.

## **Pattern 3 — TimeIncentivizationPattern**

**Lifecycle of:** Wallet

### **Description**

The TimeIncentivizationPattern captures time-locked financial logic, specifically the lifecycle of a **vesting wallet**. Token vesting is a common mechanism in which a beneficiary's tokens unlock gradually over time. The pattern encodes the ordering and temporal dependency between initializing a vesting schedule, claiming vested tokens, and completing or timing out the vesting period.

### **DCR Graph — Activities & Relations**

| Activity | Function | Role |
| :---- | :---- | :---- |
| Start Vesting | fn: new() | Initializes the vesting schedule and locks tokens |
| Claim Vested | fn: claim() | Transfers unlocked tokens to the beneficiary |
| Timeout/Complete | fn: complete() | Terminates the vesting lifecycle (on schedule completion or timeout) |

**Behavioral constraints encoded:**

* Start Vesting →🟠**Condition**→ Claim Vested: Vesting must be initialized before any claim is valid.  
* Start Vesting →🟠**Condition**→ Timeout/Complete: The vesting schedule must exist before it can be finalized.  
* Claim Vested →🔵**Response**→ Timeout/Complete: After a claim is initiated, the lifecycle must eventually be driven to completion/termination.  
* Timeout/Complete →🔴**Exclusion**→ Claim Vested: Once the schedule is complete or timed out, no further claims are allowed.

### **Vulnerability Relevance**

Flaws in this pattern produce **Time & Epoch Manipulation** vulnerabilities. Common issues include: claim() not verifying the current epoch against the unlock schedule (allowing premature withdrawal), complete() being callable by anyone (unauthorized termination), or the absence of Timeout/Complete (leaving vesting wallets in perpetual limbo). The DCR model makes these temporal invariants explicit and machine-checkable.

## **Pattern 4 — EscapabilityPattern**

**Lifecycle of:** UpgradeCap

### **Description**

The EscapabilityPattern models the upgrade lifecycle of a Sui package, governed by an UpgradeCap object. In Sui, UpgradeCap controls the ability to publish new versions of a package. The pattern captures three critical operations: authorizing an upgrade, committing it, and permanently freezing the package by making it immutable. This pattern is architecturally significant because it governs whether a contract's logic can be changed after deployment — a key trust assumption for users.

### **DCR Graph — Activities & Relations**

| Activity | Function | Role |
| :---- | :---- | :---- |
| Authorize Upgrade | fn: authorize\_upgrade() | Grants a one-time ticket to publish an upgrade |
| Execute Upgrade | fn: commit\_upgrade() | Consumes the ticket and applies the new package version |
| Make Immutable | fn: make\_immutable() | Destroys UpgradeCap, permanently preventing future upgrades |

**Behavioral constraints encoded:**

* Authorize Upgrade →🟠**Condition**→ Execute Upgrade: An upgrade must be authorized before it can be committed.  
* Execute Upgrade →🟢**Inclusion**→ Authorize Upgrade: After committing an upgrade, a new authorization cycle becomes possible.  
* Make Immutable →🔴**Exclusion**→ Authorize Upgrade: Once the package is made immutable, no further upgrades can be authorized.  
* Make Immutable →🔴**Exclusion**→ Execute Upgrade: Once the package is made immutable, no pending upgrades can be committed.

### **Vulnerability Relevance**

This pattern surfaces **Capability Leakage** and **Governance Logic Flaws**. Key risks include: an UpgradeCap that is transfer-able to an arbitrary address (allowing a deployer to silently upgrade a contract users trust as immutable), an authorize\_upgrade() function with no access control (any caller can trigger an upgrade), or a missing make\_immutable() path (no way to permanently commit to a fixed codebase). The DCR graph makes the intended finality constraint (Make Immutable excludes all further upgrade actions) formally explicit.

## **How the Analyzer Generates These Patterns**

The Analyzer detects these patterns through a **three-stage pipeline**:

1. **Static Detection** — The AST of the input .move file is scanned for capability object types (AdminCap, DenyCap, UpgradeCap, wallet structs) and their associated function signatures using regex and structural heuristics.  
2. **Pattern Matching** — Detected functions are matched against the hardcoded pattern templates, resolving each activity node to a concrete function in the analyzed contract.  
3. **DCR Graph Construction** — The matched activities are instantiated into an graph with the predefined relational edges (Condition, Response, Exclusion, Inclusion), and rendered in the Streamlit dashboard.
