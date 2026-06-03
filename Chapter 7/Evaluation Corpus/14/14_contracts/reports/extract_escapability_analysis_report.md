# 🛡️ Sui Move Security Analysis Report: `extract_escapability`
**File:** `./14_contracts/extract_escapability.move`  
**Date:** 2026-05-02 12:45:36

---

## 📊 Results Summary
- **Patterns Detected:** 1
- **Vulnerabilities Found:** 0
- **DCR Graphs Generated:** 1
- **Fixes Available:** 0
- **Functions Analyzed:** 7

---
## 🧩 Tab 1: Patterns
### ✓ EscapabilityPattern
- **Type:** EscapabilityPattern
- **Count:** 7 function(s)

---
## 🚨 Tab 2: Vulnerabilities
✅ *No vulnerabilities detected.*

---
## 📈 Tab 3: DCR Graphs
### Graph: EscapabilityPattern
```json
{
  "processId": "ES_extract_escapability",
  "patternType": "EscapabilityPattern",
  "definesLifecycleOf": "UpgradeCap",
  "events": [
    {
      "id": "ESAuthorize",
      "label": "Authorize Upgrade",
      "mapsToFunction": "authorize_upgrade",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "ESEscape",
      "label": "Execute Upgrade",
      "mapsToFunction": "commit_upgrade",
      "executable": true,
      "pending": false,
      "included": true
    },
    {
      "id": "ESMakeImmutable",
      "label": "Make Immutable",
      "mapsToFunction": "make_immutable",
      "executable": true,
      "pending": false,
      "included": true
    }
  ],
  "relations": [
    {
      "source": "ESAuthorize",
      "type": "dcr:condition",
      "target": "ESEscape"
    },
    {
      "source": "ESAuthorize",
      "type": "dcr:inclusion",
      "target": "ESEscape"
    },
    {
      "source": "ESMakeImmutable",
      "type": "dcr:exclusion",
      "target": "ESAuthorize"
    },
    {
      "source": "ESMakeImmutable",
      "type": "dcr:exclusion",
      "target": "ESEscape"
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
