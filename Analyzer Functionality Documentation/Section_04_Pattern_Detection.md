# Section 4: Pattern Detection

## Overview

Pattern detection answers the question: **"Does this function implement a known security design pattern?"** Recognizing a design pattern in a function is important for two reasons:

1. It eliminates the function from certain vulnerability flags (a function that already has proper access control should not be flagged for missing access control).
2. It triggers the generation of a DCR behavioral graph for that pattern.

The entry point for this stage is `_detect_patterns_enhanced()`, which is called once per function during the parsing phase.

---

## `_detect_patterns_enhanced()` — The Orchestrator

```python
def _detect_patterns_enhanced(
    self, params, body, func_uri, func_name, structs_info
) -> List[str]:
    """Enhanced pattern detection with all 3 methods"""
    detected = []

    # METHOD 1: CAPABILITY-BASED DETECTION
    cap_pattern = self._detect_capability_patterns(params, func_uri, structs_info)
    if cap_pattern:
        detected.append(cap_pattern)

    # METHOD 2: DYNAMIC ACL DETECTION
    if self._detect_dynamic_acl_patterns(params, body, func_uri):
        if PatternTypes.ACCESS_CONTROL not in detected:
            detected.append(PatternTypes.ACCESS_CONTROL)

    # METHOD 3: INLINE AUTHORIZATION DETECTION
    if self._detect_inline_authorization(params, body, func_uri, func_name):
        if PatternTypes.ACCESS_CONTROL not in detected:
            detected.append(PatternTypes.ACCESS_CONTROL)

    # PATTERN 2: Time Incentivization
    if re.search(r'\b&?\s*Clock\b', params):
        self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.TimeIncentivizationPattern))
        detected.append(PatternTypes.TIME_INCENTIVIZATION)

    # PATTERN 4: Escapability
    if re.search(r'\b(UpgradeCap|UpgradeTicket|UpgradeReceipt|MigrationCap)\b', params):
        self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.EscapabilityPattern))
        detected.append(PatternTypes.ESCAPABILITY)

    return detected
```

Access Control can be detected by any of three independent methods. Time Incentivization and Escapability each have a single direct signal (Clock parameter and UpgradeCap parameter respectively), so they are detected inline here with a simple regex. The Circuit Breaker pattern is detected inside Method 1 when a pause-specific capability type is found.

---

## Method 1: Capability-Based Detection

```python
def _detect_capability_patterns(self, params, func_uri, structs_info):
    """METHOD 1: Capability-based detection"""
    capability_patterns = [
        (r'\b(PauseCap|EmergencyCap|DenyCapV2|DenyCap)\b',                     40, True),
        (r'\b(AdminCap|OwnerCap|TreasuryCap|TransferPolicyCap|Publisher|ManagerCap)\b', 40, False),
        (r'\b(Authorization|Permissions?)\b',                                  35, False),
        (r'\b(Auth|AuthToken|AuthContext)\b',                                  30, False),
        (r'\b\w*Cap\b',                                                        25, False),
        (r'\b(AC|OC|MC)\b',                                                    20, False),
    ]
```

This method implements a **scoring system**. Each regex pattern is associated with a point value and a boolean flag indicating whether it is a circuit-breaker type capability. Points accumulate if a match is found. The threshold for detection is 40 points.

The scoring is intentional: high-confidence types like `AdminCap` (an exact, well-known Sui type) score 40 immediately, reaching the threshold alone. Lower-confidence signals like `\w*Cap` (any word ending in `Cap`) only score 25 — they need structural corroboration.

**Structural corroboration** is the bonus scoring from looking up the struct definition:

```python
if matched_type and matched_type in structs_info:
    struct_info = structs_info[matched_type]
    field_count = len([f for f in struct_info['fields'].split() if f.strip()])

    if 'UID' in struct_info['fields'] and field_count < 10:
        cap_score += 20  # Bonus for small key struct

    if 'key' in struct_info['abilities'] and 'store' not in struct_info['abilities']:
        cap_score += 15  # Bonus for key-only (non-transferable)

if matched_type and ('&' in params or 'mut' in params):
    cap_score += 10  # Bonus for being passed by reference
```

A struct named `MyAuth` with a `UID` field and `key`-only abilities, passed by reference, would score `25 + 20 + 15 + 10 = 70` — well above the threshold, correctly identified as a capability-based access control.

When the threshold is met, the appropriate triple is added to the graph and either `AccessControlPattern` or `CircuitBreakerPattern` is returned:

```python
if cap_score >= 40:
    if is_circuit_breaker:
        self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.CircuitBreakerPattern))
        self.pattern_detection_methods['capability_based'] += 1
        return PatternTypes.CIRCUIT_BREAKER
    else:
        self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.AccessControlPattern))
        self.pattern_detection_methods['capability_based'] += 1
        return PatternTypes.ACCESS_CONTROL
```

---

## Method 2: Dynamic ACL Detection

A second style of access control in Sui Move uses a **table or set of allowed addresses** rather than a capability object. This method detects that pattern.

```python
def _detect_dynamic_acl_patterns(self, params, body, func_uri):
    """METHOD 2: Dynamic ACL detection"""
    acl_indicators = []

    if re.search(r'Table\s*<\s*address',        params, re.IGNORECASE):
        acl_indicators.append('table_address_param')
    if re.search(r'VecSet\s*<\s*address',        params, re.IGNORECASE) or ...:
        acl_indicators.append('vecset_address_param')
    if re.search(r'table::contains',             body, re.IGNORECASE):
        acl_indicators.append('table_contains')
    if re.search(r'vec_set::contains',           body, re.IGNORECASE):
        acl_indicators.append('vecset_contains')
    if re.search(r'tx_context::sender|sender\s*\(', body, re.IGNORECASE):
        acl_indicators.append('sender_check')
    if re.search(r'assert!\s*\([^)]*contains[^)]*sender', body, re.IGNORECASE):
        acl_indicators.append('assert_membership')

    if len(acl_indicators) >= 3:
        self.g.add((func_uri, self.SUI.implementsPattern, self.PATTERN.AccessControlPattern))
        self.pattern_detection_methods['dynamic_acl'] += 1
        return True

    return False
```

This is a **multi-indicator vote** — the function must exhibit at least 3 of the 6 possible indicators to be classified as implementing dynamic ACL. This prevents false positives from a single coincidental match. A function that takes a `Table<address, ...>`, uses `table::contains`, and checks `tx_context::sender` is almost certainly performing ACL-based access control.

---

## Method 3: Inline Authorization Detection (Fix #2)

The third method catches a very common Sui Move pattern where access control is embedded directly in the function body as an `assert!` statement comparing the transaction sender against a stored owner field:

```python
def _detect_inline_authorization(self, params, body, func_uri, func_name):
    # Skip if has capability parameter (Method 1 already handled it)
    has_cap = bool(re.search(r'(Cap|Authorization|Permission|Auth)', params, re.IGNORECASE))
    if has_cap:
        return False

    # Check for sensitive operations
    sensitive_ops = [
        r'balance\.(split|join|take)',
        r'coin::take',
        r'transfer::(?:public_)?transfer',
        r'object::delete',
        r'vec_set::insert',
        r'\s*=\s*',
    ]
    has_sensitive_op = any(re.search(op, body, re.IGNORECASE) for op in sensitive_ops)
    if not has_sensitive_op:
        return False

    # Check for sender extraction
    sender_check = bool(re.search(r'tx_context::sender', body))

    # Multiple patterns for owner/authorization assertions
    owner_patterns = [
        r'assert!.*==.*\.owner',    # wallet.owner, pool.owner
        r'assert!.*owner\s*==',     # owner == sender
        r'assert!.*\.admin',        # .admin field
        r'assert!.*\.creator',      # .creator field
        r'assert!.*sender\s*==.*owner',
        r'assert!.*sender\s*==.*admin',
    ]

    if sender_check:
        for pattern in owner_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                self.g.add((func_uri, self.SUI.implementsPattern,
                            self.PATTERN.AccessControlPattern))
                self.pattern_detection_methods['inline_auth'] += 1
                return True

    return False
```

The detection logic has three gates, all of which must pass:
1. **No capability in params** — ensures Method 1 hasn't already handled this function
2. **Sensitive operation present** — the function must be doing something that requires protection (financial operation, deletion, state mutation)
3. **Sender extracted AND owner assertion present** — the function must be comparing the caller to a stored owner/admin field

This was introduced to handle the common Sui Move pattern:
```move
public fun withdraw(wallet: &mut Wallet, ctx: &mut TxContext) {
    let sender = tx_context::sender(ctx);
    assert!(sender == wallet.owner, 0);  // ← this is inline auth
    ...
}
```

Without this method, such a function would have been missed by Methods 1 and 2 and incorrectly flagged as AUTH-01 (missing access control).

---

## Semantic Operation Analysis

In parallel with pattern detection, 14 semantic operation types are tagged per function:

```python
def _analyze_semantic_operations(self, func_name, params, body, func_uri):
    """Detect 14 semantic operations"""
    detected_ops = []

    if re.search(r'(?:coin|balance):\w*(?:split|join|put|take|value)', body, re.I):
        self.g.add((func_uri, self.SUI.performsOperation, self.SUI.BalanceOperation))
        detected_ops.append("BalanceOperation")

    if re.search(r'(?:transfer|sui)::(?:public_)?transfer|share_object', body, re.I):
        self.g.add((func_uri, self.SUI.performsOperation, self.SUI.OwnershipTransfer))
        detected_ops.append("OwnershipTransfer")

    # ... and 12 more operation types
```

The full list of 14 semantic operations is:

| Operation Type | Signal |
|----------------|--------|
| `BalanceOperation` | `coin::split`, `balance::join`, `coin::take`, etc. |
| `OwnershipTransfer` | `transfer::transfer`, `share_object` |
| `ObjectCreation` | `coin::mint`, `object::new` |
| `ObjectDeletion` | `coin::burn`, `object::delete` |
| `BalanceMutation` | `&mut Coin` or `&mut Balance` in body |
| `SharedStateMutation` | `&mut <any type>` in body |
| `InvariantCheck` | `assert!(...)` |
| `AMMInvariantCheck` | `assert!` with `reserve_x * reserve_y` pattern |
| `UnboundedIteration` | `while(...)` or `loop {...}` |
| `TemporalCheck` | `clock::timestamp`, `clock::epoch`, `tx_context::epoch` |
| `TemporalConstraint` | `assert!(... timestamp/epoch/clock ...)` |
| `TimestampComparison` | `timestamp` or `epoch` compared with `<`, `>`, `==`, `!=` |
| `DynamicFieldOperation` | `dynamic_field::add/remove/borrow` |
| `OptionalExtraction` | `option::extract/swap/fill/borrow` |

These triples feed directly into the SPARQL reasoning engine. When `_sparql_detect_vulnerabilities()` queries `?func sui:performsOperation ?riskOp`, it is querying these triples.

