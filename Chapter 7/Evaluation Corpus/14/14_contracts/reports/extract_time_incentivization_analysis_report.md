# 🛡️ Sui Move Security Analysis Report: `extract_time_incentivization`
**File:** `./14_contracts/extract_time_incentivization.move`  
**Date:** 2026-05-02 12:45:36

---

## 📊 Results Summary
- **Patterns Detected:** 1
- **Vulnerabilities Found:** 1
- **DCR Graphs Generated:** 1
- **Fixes Available:** 1
- **Functions Analyzed:** 3

### 🔍 Vulnerability Breakdown
- **AUTH** (Authorization): 1
- **TIME** (Temporal): 0
- **RES** (Resource): 0
- **CONS** (Constraint): 0

---
## 🧩 Tab 1: Patterns
### ✓ TimeIncentivizationPattern
- **Type:** TimeIncentivizationPattern
- **Count:** 3 function(s)

---
## 🚨 Tab 2: Vulnerabilities
### 🟠 SUWC-AUTH-03: `new_wallet`
- **Severity:** HIGH
- **Category:** SUWC-AUTH
- **Function:** `new_wallet`
- **Description:** [SPARQL] new_wallet performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard
  
**Evidence:**
```text
Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern
```

---
## 📈 Tab 3: DCR Graphs
### Graph: TimeIncentivizationPattern
```json
{
  "processId": "TI_extract_time_incentivization",
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
### 💡 Fix: SUWC-AUTH-03
- **Affected functions:** `new_wallet`
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

**SPARQL Detections:** 1 | **Regex Detections:** 0 | **Total:** 1

### SPARQL Findings
#### 🟠 SUWC-AUTH-03 — `new_wallet`
[SPARQL] new_wallet performs Object Creation that indicates SUWC-AUTH-03 risk without mitigation guard

> Ontology reasoning: indicatesDefectRisk(SUWC-AUTH-03) confirmed by absence of mitigatesDefect. Recommended pattern: AccessControlPattern
