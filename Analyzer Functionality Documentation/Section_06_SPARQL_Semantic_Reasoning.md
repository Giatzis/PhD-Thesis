# Section 6: SPARQL Semantic Reasoning Engine

## Purpose and Motivation

The SPARQL-based detection engine is the **semantic layer** of the analysis. While the regex-based detectors work directly on source code text, the SPARQL engine works on the **RDF knowledge graph** — the structured, machine-readable representation of the contract that was built during parsing.

This distinction is fundamental: the analyzer does not merely scan for textual patterns. It reasons over a formal ontological model of the contract, and the SPARQL engine embodies the "ontology-driven" aspect.

---

## The Three-Phase Reasoning Query

```python
def _sparql_detect_vulnerabilities(self) -> List[VulnerabilityDetection]:
    """Three-phase ontology-driven vulnerability detection via SPARQL."""
```

The core of this method is a single SPARQL SELECT query that implements three logical phases in one pass:

```sparql
PREFIX sui:     <http://www.sui-move-ontology.com/ontology#>
PREFIX suwc:    <http://www.sui-move-ontology.com/defects/v1#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?funcLabel ?defect ?defectLabel ?riskOpLabel ?patternLabel WHERE {

    # PHASE 1: Function performs a risk-indicating operation
    ?func sui:performsOperation ?riskOp .
    ?riskOp sui:indicatesDefectRisk ?defect .
    ?func rdfs:label ?funcLabel .
    ?defect rdfs:label ?defectLabel .
    FILTER(STRSTARTS(?defectLabel, "SUWC-"))
    ?riskOp rdfs:label ?riskOpLabel .

    # PHASE 2: Confirm absence of mitigating operation for same defect
    FILTER NOT EXISTS {
        ?func sui:performsOperation ?mitigOp .
        ?mitigOp sui:mitigatesDefect ?defect .
    }

    # PHASE 2b: Exclude functions already protected by a pattern
    FILTER NOT EXISTS {
        ?func sui:implementsPattern ?guardPattern .
        ?guardPattern sui:addressesDefect ?defect .
    }

    # PHASE 3: Prescribe remediation pattern
    OPTIONAL {
        ?pattern sui:addressesDefect ?defect .
        ?pattern rdfs:label ?patternLabel .
    }
}
ORDER BY ?funcLabel ?defect
```

---

## Phase 1: Risk Signal Detection

```sparql
?func sui:performsOperation ?riskOp .
?riskOp sui:indicatesDefectRisk ?defect .
```

This finds every function in the graph that performs an operation which has been semantically linked (via `indicatesDefectRisk`) to a SUWC defect category. This relationship was established in `_bootstrap_reasoning_properties()`.

For example: if function `withdraw` was tagged with `performsOperation → BalanceOperation` during parsing, and `BalanceOperation indicatesDefectRisk SUWC-AUTH-01` was bootstrapped into the graph, then Phase 1 will match `withdraw` as at risk of `SUWC-AUTH-01`.

The `FILTER(STRSTARTS(?defectLabel, "SUWC-"))` clause ensures only proper SUWC vulnerability categories are returned, not any generic ontology nodes that might also be reachable.

---

## Phase 2: Absence of Mitigation (The Critical Logic)

```sparql
FILTER NOT EXISTS {
    ?func sui:performsOperation ?mitigOp .
    ?mitigOp sui:mitigatesDefect ?defect .
}
```

This is a **negation-as-failure** construct — it asks "does there NOT exist a mitigating operation for the same defect?" A function that both performs a risky operation AND performs a mitigating operation for the same defect is considered protected.

For example: a function that performs `SharedStateMutation` (risky → CONS-01) but also performs `AMMInvariantCheck` (mitigates → CONS-01) would be excluded from results by this filter. The invariant check cancels out the risk signal.

The second filter (`FILTER NOT EXISTS { ... implementsPattern ... }`) additionally excludes functions that are protected by a formal design pattern. If pattern detection has already tagged a function as implementing `AccessControlPattern`, and that pattern addresses `SUWC-AUTH-01`, the function is excluded.

---

## Phase 3: Prescriptive Remediation

```sparql
OPTIONAL {
    ?pattern sui:addressesDefect ?defect .
    ?pattern rdfs:label ?patternLabel .
}
```

The `OPTIONAL` clause is a SPARQL construct that means "retrieve this information if it exists, but do not exclude rows if it doesn't." For each confirmed vulnerability, it looks up which design pattern is prescriptively linked to that defect via `addressesDefect`. This populates the `patternLabel` that appears in the evidence field of the generated `VulnerabilityDetection` object.

---

## Result Processing

```python
severity_map = {
    "SUWC-AUTH-01": SeverityLevel.CRITICAL,
    "SUWC-AUTH-02": SeverityLevel.CRITICAL,
    ...
    "SUWC-CONS-02": SeverityLevel.CRITICAL,
    "SUWC-RES-03":  SeverityLevel.CRITICAL,
}

category_map = {
    "AUTH": VulnerabilityCategory.AUTH,
    "TIME": VulnerabilityCategory.TIME,
    "RES":  VulnerabilityCategory.RES,
    "CONS": VulnerabilityCategory.CONS,
}

results = self.g.query(query)
seen = set()  # Deduplicate (func, defect) pairs

for row in results:
    func_name    = str(row.funcLabel)
    defect_label = str(row.defectLabel).strip()

    key = (func_name, defect_label)
    if key in seen:
        continue
    seen.add(key)

    parts        = defect_label.split("-")
    category_key = parts[1] if len(parts) > 1 else "AUTH"
    category     = category_map.get(category_key, VulnerabilityCategory.AUTH)
    severity     = severity_map.get(defect_label, SeverityLevel.MEDIUM)

    vulnerabilities.append(VulnerabilityDetection(
        defect_id    = defect_label,
        category     = category,
        severity     = severity,
        function_name= func_name,
        line_number  = None,
        description  = (
            f"[SPARQL] {func_name} performs {risk_op_label} that indicates "
            f"{defect_label} risk without mitigation guard"
        ),
        evidence     = (
            f"Ontology reasoning: indicatesDefectRisk({defect_label}) "
            f"confirmed by absence of mitigatesDefect. "
            f"Recommended pattern: {pattern_label}"
        )
    ))
```

Each SPARQL result row is transformed into a `VulnerabilityDetection` object. The `[SPARQL]` prefix in the description field marks the detection origin, making it possible to distinguish SPARQL-sourced detections from regex-sourced ones in the final report. The severity is looked up from a static mapping based on the SUWC defect ID.

---

## Integration with the Dual Pipeline

Back in `_detect_all_vulnerabilities()`:

```python
existing_keys = {(v.function_name, v.defect_id) for v in vulnerabilities}
for sv in sparql_vulns:
    if (sv.function_name, sv.defect_id) not in existing_keys:
        vulnerabilities.append(sv)
```

The merging logic is simple but important: SPARQL results are only added if the same `(function_name, defect_id)` pair was not already found by a regex detector. This means:
- Regex detectors get **priority** (they often produce richer context evidence)
- SPARQL detectors act as a **safety net** for cases the regex detectors miss
- No vulnerability is reported more than once

This dual-pipeline design allows the system to demonstrate both methodological approaches (syntactic regex analysis and semantic ontological reasoning) while ensuring correctness.

