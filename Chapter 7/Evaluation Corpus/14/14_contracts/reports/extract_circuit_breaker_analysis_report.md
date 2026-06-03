# 🛡️ Sui Move Security Analysis Report: `extract_circuit_breaker`
**File:** `./14_contracts/extract_circuit_breaker.move`  
**Date:** 2026-05-02 12:45:36

---

## 📊 Results Summary
- **Patterns Detected:** 1
- **Vulnerabilities Found:** 0
- **DCR Graphs Generated:** 1
- **Fixes Available:** 0
- **Functions Analyzed:** 4

---
## 🧩 Tab 1: Patterns
### ✓ CircuitBreakerPattern
- **Type:** CircuitBreakerPattern
- **Count:** 4 function(s)

---
## 🚨 Tab 2: Vulnerabilities
✅ *No vulnerabilities detected.*

---
## 📈 Tab 3: DCR Graphs
### Graph: CircuitBreakerPattern
```json
{
  "processId": "CB_extract_circuit_breaker",
  "patternType": "CircuitBreakerPattern",
  "definesLifecycleOf": "DenyCap",
  "events": [
    {
      "id": "CBPause",
      "label": "Pause Operations",
      "mapsToFunction": "pause",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "CBUnpause",
      "label": "Unpause Operations",
      "mapsToFunction": "unpause",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "CBOperationalCall",
      "label": "Operational Call",
      "mapsToFunction": "execute",
      "executable": true,
      "pending": false,
      "included": true
    }
  ],
  "relations": [
    {
      "source": "CBPause",
      "type": "dcr:exclusion",
      "target": "CBOperationalCall"
    },
    {
      "source": "CBPause",
      "type": "dcr:inclusion",
      "target": "CBUnpause"
    },
    {
      "source": "CBUnpause",
      "type": "dcr:inclusion",
      "target": "CBOperationalCall"
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
