# 🛡️ Sui Move Security Analysis Report: `suwc_time_vulnerable`
**File:** `./14_contracts/suwc_time_vulnerable.move`  
**Date:** 2026-05-02 12:45:36

---

## 📊 Results Summary
- **Patterns Detected:** 2
- **Vulnerabilities Found:** 17
- **DCR Graphs Generated:** 2
- **Fixes Available:** 17
- **Functions Analyzed:** 8

### 🔍 Vulnerability Breakdown
- **AUTH** (Authorization): 2
- **TIME** (Temporal): 10
- **RES** (Resource): 0
- **CONS** (Constraint): 5

---
## 🧩 Tab 1: Patterns
### ✓ TimeIncentivizationPattern
- **Type:** TimeIncentivizationPattern
- **Count:** 4 function(s)

### ✓ AccessControlPattern
- **Type:** AccessControlPattern
- **Count:** 2 function(s)

---
## 🚨 Tab 2: Vulnerabilities
### 🟡 SUWC-TIME-02: `create_vault`
- **Severity:** MEDIUM
- **Category:** SUWC-TIME
- **Function:** `create_vault`
- **Description:** Function 'create_vault' creates a locked position without unlock mechanism
  
**Evidence:**
```text
Body deposits assets (balance::join) and creates a new object (object::new) but no function in this module performs timed extraction (asset outflow + temporal assert). Recommended pattern: TimeIncentivizationPattern with Epoch-based Unlock
```

### 🟠 SUWC-TIME-03: `create_vault`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `create_vault`
- **Description:** Function uses timestamp_ms() without safety assertions
  
**Evidence:**
```text
Found clock::timestamp_ms without assert! validation. Recommended pattern: TimeIncentivizationPattern with Epoch-based Time
```

### 🟠 SUWC-TIME-01: `claim_rewards`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `claim_rewards`
- **Description:** Function 'claim_rewards' releases assets without time verification
  
**Evidence:**
```text
Body performs net asset outflow (coin::take / balance::split) without corresponding inflow in a temporal contract but lacks clock/epoch guard. Recommended pattern: TimeIncentivizationPattern with Epoch Checks
```

### 🟠 SUWC-TIME-01: `withdraw_vested`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `withdraw_vested`
- **Description:** Function 'withdraw_vested' releases assets without time verification
  
**Evidence:**
```text
Body performs net asset outflow (coin::take / balance::split) without corresponding inflow in a temporal contract but lacks clock/epoch guard. Recommended pattern: TimeIncentivizationPattern with Epoch Checks
```

### 🟠 SUWC-TIME-01: `release_tokens`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `release_tokens`
- **Description:** Function 'release_tokens' releases assets without time verification
  
**Evidence:**
```text
Body performs net asset outflow (coin::take / balance::split) without corresponding inflow in a temporal contract but lacks clock/epoch guard. Recommended pattern: TimeIncentivizationPattern with Epoch Checks
```

### 🟡 SUWC-TIME-02: `stake`
- **Severity:** MEDIUM
- **Category:** SUWC-TIME
- **Function:** `stake`
- **Description:** Function 'stake' creates a locked position without unlock mechanism
  
**Evidence:**
```text
Body deposits assets (balance::join) and creates a new object (object::new) but no function in this module performs timed extraction (asset outflow + temporal assert). Recommended pattern: TimeIncentivizationPattern with Epoch-based Unlock
```

### 🟠 SUWC-TIME-03: `stake`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `stake`
- **Description:** Function uses timestamp_ms() without safety assertions
  
**Evidence:**
```text
Found clock::timestamp_ms without assert! validation. Recommended pattern: TimeIncentivizationPattern with Epoch-based Time
```

### 🟠 SUWC-TIME-03: `check_elapsed`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `check_elapsed`
- **Description:** Function uses timestamp_ms() without safety assertions
  
**Evidence:**
```text
Found clock::timestamp_ms without assert! validation. Recommended pattern: TimeIncentivizationPattern with Epoch-based Time
```

### 🟠 SUWC-TIME-03: `compound_and_restake`
- **Severity:** HIGH
- **Category:** SUWC-TIME
- **Function:** `compound_and_restake`
- **Description:** Function uses timestamp_ms() without safety assertions
  
**Evidence:**
```text
Found clock::timestamp_ms without assert! validation. Recommended pattern: TimeIncentivizationPattern with Epoch-based Time
```

### 🟡 SUWC-TIME-04: `compound_and_restake`
- **Severity:** MEDIUM
- **Category:** SUWC-TIME
- **Function:** `compound_and_restake`
- **Description:** Function 'compound_and_restake' has potential time-based race condition
  
**Evidence:**
```text
Found 2 time reads. Recommended pattern: TimeIncentivizationPattern with Priority Ordering
```

### 🟠 SUWC-CONS-01: `VestingVault`
- **Severity:** HIGH
- **Category:** SUWC-CONS
- **Function:** `VestingVault`
- **Description:** Struct VestingVault is missing CircuitBreakerPattern — no pause mechanism or DenyCapV2 field detected
  
**Evidence:**
```text
No is_paused, pause_cap, or DenyCapV2 field found in struct definition. Recommended pattern: CircuitBreakerPattern with EmergencyPause
```

### 🟠 SUWC-CONS-01: `RewardPool`
- **Severity:** HIGH
- **Category:** SUWC-CONS
- **Function:** `RewardPool`
- **Description:** Struct RewardPool is missing CircuitBreakerPattern — no pause mechanism or DenyCapV2 field detected
  
**Evidence:**
```text
No is_paused, pause_cap, or DenyCapV2 field found in struct definition. Recommended pattern: CircuitBreakerPattern with EmergencyPause
```

### 🟠 SUWC-CONS-01: `claim_rewards`
- **Severity:** HIGH
- **Category:** SUWC-CONS
- **Function:** `claim_rewards`
- **Description:** [SPARQL] claim_rewards performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern
```

### 🟠 SUWC-AUTH-03: `create_vault`
- **Severity:** HIGH
- **Category:** SUWC-AUTH
- **Function:** `create_vault`
- **Description:** [SPARQL] create_vault performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern
```

### 🟠 SUWC-CONS-01: `lock_rewards`
- **Severity:** HIGH
- **Category:** SUWC-CONS
- **Function:** `lock_rewards`
- **Description:** [SPARQL] lock_rewards performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern
```

### 🟠 SUWC-AUTH-03: `stake`
- **Severity:** HIGH
- **Category:** SUWC-AUTH
- **Function:** `stake`
- **Description:** [SPARQL] stake performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern
```

### 🟠 SUWC-CONS-01: `stake`
- **Severity:** HIGH
- **Category:** SUWC-CONS
- **Function:** `stake`
- **Description:** [SPARQL] stake performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern
```

---
## 📈 Tab 3: DCR Graphs
### Graph: AccessControlPattern
```json
{
  "processId": "AC_suwc_time_vulnerable",
  "patternType": "AccessControlPattern",
  "definesLifecycleOf": "AdminCap",
  "events": [
    {
      "id": "ACGrantRole",
      "label": "Grant Role",
      "mapsToFunction": "new",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "ACProtectedCall",
      "label": "Protected Call",
      "mapsToFunction": "protected_call",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "ACRevokeRole",
      "label": "Revoke Role",
      "mapsToFunction": "destroy",
      "executable": true,
      "pending": false,
      "included": true
    }
  ],
  "relations": [
    {
      "source": "ACGrantRole",
      "type": "dcr:condition",
      "target": "ACProtectedCall"
    },
    {
      "source": "ACRevokeRole",
      "type": "dcr:exclusion",
      "target": "ACProtectedCall"
    },
    {
      "source": "ACGrantRole",
      "type": "dcr:inclusion",
      "target": "ACProtectedCall"
    }
  ]
}
```

### Graph: TimeIncentivizationPattern
```json
{
  "processId": "TI_suwc_time_vulnerable",
  "patternType": "TimeIncentivizationPattern",
  "definesLifecycleOf": "Wallet",
  "events": [
    {
      "id": "TIStart",
      "label": "Start Vesting",
      "mapsToFunction": "new",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "TIProceed",
      "label": "Claim Vested",
      "mapsToFunction": "claim",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "TITimeout",
      "label": "Timeout/Complete",
      "mapsToFunction": "complete",
      "executable": true,
      "pending": false,
      "included": true
    }
  ],
  "relations": [
    {
      "source": "TIStart",
      "type": "dcr:condition",
      "target": "TIProceed"
    },
    {
      "source": "TIStart",
      "type": "dcr:response",
      "target": "TIProceed"
    },
    {
      "source": "TIStart",
      "type": "dcr:condition",
      "target": "TITimeout"
    }
  ]
}
```

---
## 🛠️ Tab 4: Fixes
### 💡 Fix: SUWC-TIME-02
- **Affected functions:** `create_vault`, `stake`
- **Recommended Pattern:** EscapabilityPattern
  
**Explanation:**
Assets locked with impossible or missing extraction conditions. Implement the Escapability Pattern with authorized upgrade or emergency withdrawal mechanism to prevent permanent asset loss.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun lock_forever(coin: Coin<SUI>, ctx: &mut TxContext) {
    let locked = LockedCoin { 
        id: object::new(ctx),
        coin: coin,
        // No unlock mechanism - assets locked forever!
    };
    transfer::freeze_object(locked);  // Immutable - cannot be changed
}

// ✅ FIXED CODE with Escapability
public struct LockedCoin has key {
    id: UID,
    coin: Coin<SUI>,
    unlock_epoch: u64,
    owner: address
}

public fun unlock(
    locked: LockedCoin,
    ctx: &TxContext
): Coin<SUI> {
    assert!(tx_context::epoch(ctx) >= locked.unlock_epoch, ETooEarly);
    assert!(tx_context::sender(ctx) == locked.owner, ENotOwner);

    let LockedCoin { id, coin, unlock_epoch: _, owner: _ } = locked;
    object::delete(id);
    coin  // Asset successfully extracted
}

// Emergency escape via upgrade capability
public fun emergency_unlock(
    _upgrade_cap: &UpgradeCap,
    locked: LockedCoin
): Coin<SUI> {
    // Admin can always rescue assets
    let LockedCoin { id, coin, unlock_epoch: _, owner: _ } = locked;
    object::delete(id);
    coin
}

```

### 💡 Fix: SUWC-TIME-03
- **Affected functions:** `create_vault`, `stake`, `check_elapsed`, `compound_and_restake`
- **Recommended Pattern:** TimeIncentivizationPattern with Epoch-based Time
  
**Explanation:**
Using tx_context::timestamp_ms() for time-critical logic is vulnerable to validator manipulation. Use tx_context::epoch() for security-critical temporal checks, as epochs are consensus-guaranteed.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun check_deadline(clock: &Clock, ctx: &TxContext) {
    let now = clock::timestamp_ms(clock);  // DANGER: manipulable by validators
    assert!(now < DEADLINE_MS, EDeadlinePassed);
}

// ✅ FIXED CODE
public fun check_deadline(ctx: &TxContext) {
    let current_epoch = tx_context::epoch(ctx);  // Consensus-guaranteed
    assert!(current_epoch < DEADLINE_EPOCH, EDeadlinePassed);
}

// For display/UI purposes only (not security checks)
public fun get_display_time(ctx: &TxContext): u64 {
    tx_context::timestamp_ms(ctx)  // OK for non-critical use
}

```

### 💡 Fix: SUWC-TIME-01
- **Affected functions:** `claim_rewards`, `withdraw_vested`, `release_tokens`
- **Recommended Pattern:** TimeIncentivizationPattern with Epoch Checks
  
**Explanation:**
Time-locked assets released before vesting period elapses. Use tx_context::epoch() for temporal checks and enforce linear/cliff vesting schedules with proper time validation.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun claim(wallet: &mut Wallet, ctx: &TxContext): Coin<SUI> {
    let balance = wallet.balance;
    // No time check - can claim immediately!
    coin::take(&mut wallet.balance, balance, ctx)
}

// ✅ FIXED CODE with Time Incentivization
public fun claim(wallet: &mut Wallet, ctx: &TxContext): Coin<SUI> {
    let current_epoch = tx_context::epoch(ctx);
    let elapsed = current_epoch - wallet.start_epoch;

    // Enforce minimum vesting period
    assert!(elapsed >= wallet.vesting_duration, EVestingNotComplete);

    // Calculate claimable amount (linear vesting)
    let claimable = if (elapsed >= wallet.vesting_duration) {
        balance::value(&wallet.balance)  // Fully vested
    } else {
        (balance::value(&wallet.balance) * elapsed) / wallet.vesting_duration
    };

    coin::take(&mut wallet.balance, claimable, ctx)
}

```

### 💡 Fix: SUWC-TIME-04
- **Affected functions:** `compound_and_restake`
- **Recommended Pattern:** TimeIncentivizationPattern with Priority Ordering
  
**Explanation:**
Multiple transactions racing on shared vesting/staking pools at epoch boundaries. Implement fair queuing or priority mechanisms to prevent front-running at temporal boundaries.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun claim_reward(
    pool: &mut SharedRewardPool,
    ctx: &TxContext
) {
    let current_epoch = tx_context::epoch(ctx);
    if (current_epoch >= pool.reward_epoch) {
        // Race condition: first caller gets all rewards!
        let reward = pool.total_rewards;
        transfer::public_transfer(
            coin::take(&mut pool.balance, reward, ctx),
            tx_context::sender(ctx)
        );
    }
}

// ✅ FIXED CODE with Fair Distribution
public struct UserStake has store {
    amount: u64,
    stake_epoch: u64,
    claimed: bool  // Track claim status to prevent double-claiming
}

public fun claim_reward(
    user_stake: &mut UserStake,
    pool: &mut SharedRewardPool,
    ctx: &TxContext
) {
    let current_epoch = tx_context::epoch(ctx);
    assert!(current_epoch >= pool.reward_epoch, ETooEarly);

    // Calculate fair share based on user's stake
    let epochs_staked = current_epoch - user_stake.stake_epoch;
    let user_share = (pool.total_rewards * user_stake.amount) / pool.total_staked;

    // Mark as claimed to prevent double-claiming
    assert!(!user_stake.claimed, EAlreadyClaimed);
    user_stake.claimed = true;

    transfer::public_transfer(
        coin::take(&mut pool.balance, user_share, ctx),
        tx_context::sender(ctx)
    );
}

```

### 💡 Fix: SUWC-CONS-01
- **Affected functions:** `VestingVault`, `RewardPool`, `claim_rewards`, `lock_rewards`, `stake`
- **Recommended Pattern:** CircuitBreakerPattern with InvariantCheck
  
**Explanation:**
Mathematical invariant (e.g., x*y=k in AMM) can break after state changes. Add explicit invariant checks before and after critical operations, with circuit breaker to pause on violations.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun swap(pool: &mut Pool, amount_in: u64): u64 {
    let amount_out = calculate_output(pool, amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;
    // No invariant check - curve can be violated!
    amount_out
}

// ✅ FIXED CODE with Circuit Breaker
public fun swap(
    pool: &mut Pool, 
    amount_in: u64,
    ctx: &TxContext
): u64 {
    assert!(!pool.paused, EPaused);  // Circuit breaker check

    let k_before = pool.reserve_x * pool.reserve_y;

    let amount_out = calculate_output(pool, amount_in);
    pool.reserve_x = pool.reserve_x + amount_in;
    pool.reserve_y = pool.reserve_y - amount_out;

    let k_after = pool.reserve_x * pool.reserve_y;
    assert!(k_after >= k_before, EInvariantViolation);  // Invariant check

    amount_out
}

public fun emergency_pause(admin: &AdminCap, pool: &mut Pool) {
    pool.paused = true;  // Circuit breaker activation
}

```

### 💡 Fix: SUWC-AUTH-03
- **Affected functions:** `create_vault`, `stake`
- **Recommended Pattern:** One-Time Witness (OTW) Pattern
  
**Explanation:**
The One-Time Witness struct is borrowed (&OTW) instead of consumed by value, allowing it to be reused multiple times. OTW must be moved (consumed) to guarantee single execution.

**Example Code:**
```rust

// ❌ VULNERABLE CODE
public fun init_pool(
    witness: &PROTOCOL_OTW,  // DANGER: borrowed, can be reused!
    ctx: &mut TxContext
) {
    // Malicious caller can call this multiple times
}

// ✅ FIXED CODE
public fun init_pool(
    witness: PROTOCOL_OTW,  // Consumed by value - single use only
    ctx: &mut TxContext
) {
    // witness is moved, cannot be called again
}

```

---
## 🧠 Tab 5: Ontology Reasoning
### Semantic Property Model (Three-Property Model)
- **indicatesDefectRisk** (Risk): 9 rules
- **mitigatesDefect** (Mitigate): 6 rules
- **addressesDefect** (Prescribe): 15 rules

**SPARQL Detections:** 5 | **Regex Detections:** 12 | **Total:** 17

### SPARQL Findings
#### 🟠 SUWC-CONS-01 — `claim_rewards`
[SPARQL] claim_rewards performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern

#### 🟠 SUWC-AUTH-03 — `create_vault`
[SPARQL] create_vault performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern

#### 🟠 SUWC-CONS-01 — `lock_rewards`
[SPARQL] lock_rewards performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern

#### 🟠 SUWC-AUTH-03 — `stake`
[SPARQL] stake performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern

#### 🟠 SUWC-CONS-01 — `stake`
[SPARQL] stake performs Shared State Mutation that indicates SUWC-CONS-01 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-CONS-01) confirmed by absence of mitigatesDefect. Recommended pattern: CircuitBreakerPattern
