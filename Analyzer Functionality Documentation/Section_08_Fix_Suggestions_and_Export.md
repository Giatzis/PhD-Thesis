# Section 8: Fix Suggestions & Export Functions

## Fix Suggestion Generation

After all vulnerabilities have been detected, the analyzer generates a human-readable remediation suggestion for each one. This is delegated entirely to the `AutomatedFixSuggester` companion module.

```python
def _generate_fixes(self, vulnerabilities: List[VulnerabilityDetection]) -> List[Dict]:
    """Generate fix suggestions"""
    fixes = []

    for vuln in vulnerabilities:
        try:
            fix = self.fix_suggester.suggest_fix(vuln)
            fixes.append({
                "vulnerability": {
                    "defect_id":   vuln.defect_id,
                    "severity":    vuln.severity.value,
                    "function":    vuln.function_name,
                    "description": vuln.description
                },
                "fix": {
                    "title":       fix.title,
                    "pattern":     fix.recommended_pattern,
                    "explanation": fix.explanation,
                    "example":     fix.example_code,
                    "references":  fix.references
                }
            })
        except Exception as e:
            print(f" ⚠️ Could not generate fix for {vuln.defect_id}")

    return fixes
```

Each fix is structured as a paired dictionary: a `vulnerability` block (summarizing what was found) and a `fix` block (the remediation advice). The `fix` block contains:
- **title**: A short headline for the recommended fix
- **pattern**: The design pattern that should be applied
- **explanation**: A prose description of why this vulnerability is dangerous and how the fix addresses it
- **example**: A code snippet showing corrected Sui Move code
- **references**: Academic or framework references supporting the advice

The `try/except` wrapper ensures a failure in `suggest_fix()` for one vulnerability does not prevent the remaining vulnerabilities from receiving suggestions.

---

## Vulnerability Breakdown Statistics

Before the fix generation, the analysis pipeline collects a category breakdown of all found vulnerabilities:

```python
def _get_vulnerability_breakdown(self, vulns: List[VulnerabilityDetection]) -> Dict:
    """Get breakdown of vulnerabilities by category"""
    breakdown = {"AUTH": 0, "TIME": 0, "RES": 0, "CONS": 0}

    for vuln in vulns:
        category = vuln.category.value.replace("SUWC-", "")
        if category in breakdown:
            breakdown[category] += 1

    return breakdown
```

This produces a dictionary like `{"AUTH": 3, "TIME": 1, "RES": 0, "CONS": 2}` that gives a high-level summary of what categories of vulnerabilities were found.

---

## Export: RDF Knowledge Graph

```python
def export_rdf_graph(self, format="turtle", output_file=None):
    """Export RDF knowledge graph in specified format"""
    if output_file:
        self.g.serialize(destination=output_file, format=format)
        print(f"✅ RDF graph exported to {output_file}")
    else:
        return self.g.serialize(format=format)

def export_json_ld(self, output_file=None):
    """Export as JSON-LD"""
    return self.export_rdf_graph(format="json-ld", output_file=output_file)
```

The RDF graph can be exported in two formats:
- **Turtle (`.ttl`)** — the standard RDF serialization format, human-readable, compatible with Protégé and SPARQL endpoints
- **JSON-LD** — JSON-based RDF serialization, useful for web APIs and JavaScript-based tools

---

## Export: Comprehensive Report

```python
def export_comprehensive_report(self, analysis_result: Dict, output_dir: str = "."):
    """Export complete analysis report"""
    module    = analysis_result["module"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Export RDF
    rdf_file = f"{output_dir}/{module}_ontology_{timestamp}.ttl"
    self.export_rdf_graph(format="turtle", output_file=rdf_file)

    # Export JSON report
    json_file = f"{output_dir}/{module}_report_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(analysis_result, f, indent=2, default=str)

    print(f"✅ Reports exported to {output_dir}")
    return {"rdf_file": rdf_file, "json_file": json_file}
```

This convenience method produces two files:
1. A `.ttl` file containing the populated RDF knowledge graph for the analyzed contract
2. A `.json` file containing the complete analysis result (patterns, DCR graphs, vulnerabilities, fixes, statistics)

Both files are timestamped to prevent overwriting previous analyses. The `default=str` argument in `json.dump` ensures that any non-serializable objects (like enum values) are safely converted to strings.

