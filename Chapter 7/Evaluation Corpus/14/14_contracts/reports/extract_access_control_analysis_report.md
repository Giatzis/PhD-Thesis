# 🛡️ Sui Move Security Analysis Report: `extract_access_control`
**File:** `./14_contracts/extract_access_control.move`  
**Date:** 2026-05-02 12:45:35

---

## 📊 Results Summary
- **Patterns Detected:** 1
- **Vulnerabilities Found:** 0
- **DCR Graphs Generated:** 1
- **Fixes Available:** 0
- **Functions Analyzed:** 4

---
## 🧩 Tab 1: Patterns
### ✓ AccessControlPattern
- **Type:** AccessControlPattern
- **Count:** 4 function(s)

---
## 🚨 Tab 2: Vulnerabilities
✅ *No vulnerabilities detected.*

---
## 📈 Tab 3: DCR Graphs
### Graph: AccessControlPattern
```json
{
  "processId": "AC_extract_access_control",
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

---
## 🛠️ Tab 4: Fixes
✅ *No fixes needed.*

---
## 🧠 Tab 5: Ontology Reasoning
### Semantic Property Model (Three-Property Model)
- **indicatesDefectRisk** (Risk): 9 rules
- **mitigatesDefect** (Mitigate): 6 rules
- **addressesDefect** (Prescribe): 15 rules

**SPARQL Detections:** 0 | **Regex Detections:** 0 | **Total:** 0

> All risk-indicating operations have corresponding mitigation guards — no unmitigated risks found by SPARQL reasoning.
