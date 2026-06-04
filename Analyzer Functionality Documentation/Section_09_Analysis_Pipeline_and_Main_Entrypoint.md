# Section 9: The Analysis Pipeline & Main Entrypoint

## `analyze_contract()` — The Master Orchestrator

This is the only public-facing analysis method. Everything else in the analyzer is private (prefixed with `_`). It is the single entry point for the UI (Streamlit app) to trigger a full analysis.

```python
def analyze_contract(self, code: str, module_name: str = "contract") -> Dict:
    """COMPREHENSIVE ANALYSIS PIPELINE"""
    print(f"\n🔍 Analyzing {module_name}...")
    print(f" [v.1.0 - PhD Defense Version]")

    success = self._parse_and_instantiate(code, module_name)
    if not success:
        return None

    print(" └─ Generating DCR graphs...")
    graphs = self._generate_dcr_graphs(self.detected_patterns, module_name)
    self.generated_graphs = graphs

    print(" └─ Detecting ALL 13 SUWC vulnerabilities...")
    vulns = self._detect_all_vulnerabilities(code, module_name)
    self.vulnerabilities = vulns

    print(" └─ Generating fix suggestions...")
    fixes = self._generate_fixes(vulns)

    print(f"\n✅ Analysis complete!")
    print(f" Detection methods used:")
    print(f"  • Capability-based: {self.pattern_detection_methods['capability_based']}")
    print(f"  • Dynamic ACL: {self.pattern_detection_methods['dynamic_acl']}")
    print(f"  • Inline Auth: {self.pattern_detection_methods['inline_auth']}")

    return {
        "module":           module_name,
        "ontology_triples": len(self.g),
        "patterns":         self.detected_patterns,
        "dcr_graphs":       graphs,
        "vulnerabilities":  vulns,
        "fix_suggestions":  fixes,
        "statistics": {
            "functions_analyzed":    self.function_count,
            "patterns_detected":     len(self.detected_patterns),
            "dcr_graphs_generated":  len(graphs),
            "vulnerabilities_found": len(vulns),
            "fixes_available":       len(fixes),
            "detection_methods":     self.pattern_detection_methods,
            "vulnerability_breakdown": self._get_vulnerability_breakdown(vulns)
        }
    }
```

### Return Value Structure

The returned dictionary is the complete analysis artifact. Its structure:

| Key | Type | Content |
|-----|------|---------|
| `module` | `str` | Module name extracted from the contract |
| `ontology_triples` | `int` | Total number of RDF triples in the populated graph |
| `patterns` | `Dict[str, int]` | Pattern name → count of functions implementing it |
| `dcr_graphs` | `List[Dict]` | One DCR graph per detected pattern |
| `vulnerabilities` | `List[VulnerabilityDetection]` | All detected vulnerabilities |
| `fix_suggestions` | `List[Dict]` | Fix advice for each vulnerability |
| `statistics` | `Dict` | Summary counts and detection method breakdown |

---

## The Built-in Test Contract

The `if __name__ == "__main__":` block provides a **self-contained integration test** that demonstrates the analyzer's capabilities on a purpose-built DeFi contract:

```python
test_contract = """
module defense::complete_defi {
    ...
    public struct AdminCap has key { id: UID }

    public struct LiquidityPool has key {
        id: UID,
        reserve_x: Balance<SUI>,
        reserve_y: Balance<SUI>,
        total_shares: u64
    }

    // PUBLIC function — should NOT trigger AUTH-01
    public fun swap_x_to_y(pool: &mut LiquidityPool, coin_x: Coin<SUI>, ctx: &mut TxContext): Coin<SUI> {
        let amount_in = coin::value(&coin_x);
        balance::join(&mut pool.reserve_x, coin::into_balance(coin_x));
        let amount_out = amount_in;
        coin::take(&mut pool.reserve_y, amount_out, ctx)
    }

    // Inline authorization (should detect AC pattern)
    public fun withdraw(wallet: &mut Wallet, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        assert!(sender == wallet.owner, 0);  // ← Method 3 target
        let coins = balance::split(&mut wallet.balance, 100);
    }

    // Privileged function with NO cap — SHOULD trigger AUTH-01
    public fun admin_drain_swap(pool: &mut LiquidityPool, amount: u64) {
        balance::split(&mut pool.reserve_x, amount);
    }
}
"""
```

This contract is carefully crafted to verify all major detection decisions:

### Verification Checks

```python
# Check 1: No false positives on swap/stake/claim/create
false_positives = []
    for v in result['vulnerabilities']:
         if v.defect_id == "SUWC-AUTH-01":
                if v.function_name in ['swap_x_to_y', 'stake_tokens', 'claim_rewards', 'create_pool']:
                false_positives.append(v.function_name)


if false_positives:
    print(f"❌ FALSE POSITIVES DETECTED: {', '.join(false_positives)}")
else:
    print("✅ NO FALSE POSITIVES on swap/stake/claim/create functions")
```

```python
# Check 2: True positive on admin_drain_swap
if any(v.function_name == 'admin_drain_swap' for v in result['vulnerabilities']):
    print("✅ ATTACK DETECTED: admin_drain_swap correctly flagged")
else:
    print("❌ FALSE NEGATIVE: admin_drain_swap not detected")
```

```python
# Check 3: Inline authorization detected on withdraw
if result['statistics']['detection_methods']['inline_auth'] > 0:
    print("✅ INLINE AUTH DETECTED: withdraw function pattern recognized")
else:
    print("⚠️ Inline authorization not detected")
```

These three verification checks:
1. **No false positives** — user-facing DeFi functions (swap, stake, claim) must not be flagged as missing access control
2. **No false negatives** — a genuinely vulnerable drain function without a cap must be detected
3. **Method 3 coverage** — inline authorization (field-level owner checks) must be recognized as a valid protection mechanism

---

## End-to-End Data Flow Summary

The following table shows how data moves through the entire system from input code to output report:

| Stage | Input | Output | Stored In |
|-------|-------|--------|-----------|
| Comment stripping | Raw source code | Clean source code | local variable |
| Module extraction | Clean code | Module URI | `self.g` (RDF triple) |
| Struct extraction | Clean code | Struct dict per struct | `self.parsed_structs` |
| Function extraction | Clean code | Function dict per function | `self.parsed_functions` |
| Pattern detection | Per-function params + body | Pattern names | `self.detected_patterns` + `self.g` |
| Semantic op tagging | Per-function body | Operation type triples | `self.g` |
| Temporal context | All functions | Boolean flag | `self.has_temporal_context` |
| DCR graph generation | `detected_patterns` | DCR dicts | `self.generated_graphs` |
| Regex vulnerability detection | `parsed_functions`, `parsed_structs` | `VulnerabilityDetection` list | `self.vulnerabilities` |
| SPARQL vulnerability detection | `self.g` | `VulnerabilityDetection` list | merged into `self.vulnerabilities` |
| Fix generation | `vulnerabilities` | Fix dicts | returned in result |
| Export | Full result dict | `.ttl` + `.json` files | disk |

