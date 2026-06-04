# Section 2: Initialization & Ontology Loading

## The `__init__` Constructor

When an instance of `ComprehensiveSuiAnalyzer` is created, the constructor sets up every internal data structure the analyzer will need. It is divided into three logical groups: ontology components, enhancement components, and state-tracking variables.

```python
def __init__(self, ontology_path=None):
    """Initialize comprehensive analyzer with all capabilities"""
    # === ONTOLOGY COMPONENTS ===
    self.g = Graph()
    self.function_count   = 0
    self.violation_count  = 0
    self.detected_patterns = {}
    self.violations       = []
    self.dcr_mappings     = []
```

`self.g` is the central data structure — an **RDF graph** from the `rdflib` library. Every piece of information about the analyzed contract (modules, functions, detected patterns, semantic operations) gets added to this graph as **triples** (subject → predicate → object). This is what makes the analysis "ontology-driven."

---

## Namespace Declarations

```python
self.SUI     = Namespace("http://www.sui-move-ontology.com/ontology#")
self.PATTERN = Namespace("http://www.sui-move-ontology.com/patterns/v1#")
self.SUWC    = Namespace("http://www.sui-move-ontology.com/defects/v1#")
self.DCR     = Namespace("http://purl.org/net/dcr#")

self.g.bind("sui",     self.SUI)
self.g.bind("pattern", self.PATTERN)
self.g.bind("suwc",    self.SUWC)
self.g.bind("dcr",     self.DCR)
```

In RDF, every entity (class, property, individual) is identified by a **URI** — a globally unique web address. Namespaces are shorthand prefixes for these URIs, exactly like XML namespaces. For example:

- `self.SUI.Function` expands to `http://www.sui-move-ontology.com/ontology#Function`
- `self.SUWC["SUWC-AUTH-01"]` expands to `http://www.sui-move-ontology.com/defects/v1#SUWC-AUTH-01`

The `.bind()` calls register friendly short names so that when the graph is exported to Turtle (`.ttl`) format, the URIs appear as `sui:Function` rather than full URLs. This also makes SPARQL queries readable.

---

## Enhancement Components

```python
self.dcr_generator  = DCRGraphGenerator()
self.fix_suggester  = AutomatedFixSuggester()
self.vulnerabilities = []
self.generated_graphs = []
```

Two companion objects are instantiated here and reused throughout the analysis. `dcr_generator` handles the production of formal process models; `fix_suggester` handles remediation advice. By instantiating them once in `__init__`, the analyzer avoids creating them repeatedly in loops.

---

## State Variables for Detection Tracking

```python
self.pattern_detection_methods = {
    "capability_based": 0,
    "dynamic_acl": 0,
    "inline_auth": 0
}

self.parsed_structs    = {}
self.parsed_functions  = {}
self.has_temporal_context = False
```

- `pattern_detection_methods` is a counter dictionary that records **how many functions triggered each detection method**. At the end of analysis, this is printed to the console and included in the result statistics, giving transparency into which detection paths were active.
- `parsed_structs` and `parsed_functions` are dictionaries populated during parsing. They act as an in-memory cache so that later vulnerability detection stages do not have to re-parse the source code.
- `has_temporal_context` is a boolean flag set to `True` if the contract uses time-related features (e.g., Clock parameters, epoch calls). Several vulnerability checks only make sense in a temporal contract, so this flag gates them.

---

## Loading the Ontology File

```python
if ontology_path is None:
    default_path = "Sui_Move_Ontology.ttl"
    if os.path.exists(default_path):
        ontology_path = default_path

self.ontology_path = ontology_path
self._load_ontology()
self._bootstrap_reasoning_properties()
```

```python
def _load_ontology(self):
    """Load TTL ontology file"""
    try:
        start_time = time.time()
        self.g.parse(self.ontology_path, format="turtle")
        print(f"✓ Ontology loaded: {len(self.g)} triples in {time.time() - start_time:.2f}s")
    except Exception as e:
        print(f"⚠️ Could not load ontology: {str(e)}. Creating minimal structure.")
        self._create_minimal_ontology()
```

The analyzer loads the Sui Move Ontology from a `.ttl` (Turtle) file. This file defines the full OWL class hierarchy: `Module`, `Function`, `EntryFunction`, `SecurityOperation` types, `VulnerabilityCategory` individuals, and `BusinessLogicPattern` classes. When the ontology is successfully parsed, all those class/property definitions are pre-loaded into `self.g`.

If the file is not found, `_create_minimal_ontology()` adds a bare-minimum set of class declarations so the analyzer can still function without the full ontology:

```python
def _create_minimal_ontology(self):
    self.g.add((self.SUI.Module,   RDF.type, OWL.Class))
    self.g.add((self.SUI.Function, RDF.type, OWL.Class))
    self.g.add((self.SUI.EntryFunction, RDF.type, OWL.Class))
    self.g.add((self.PATTERN.AccessControlPattern,    RDF.type, OWL.Class))
    self.g.add((self.PATTERN.CircuitBreakerPattern,   RDF.type, OWL.Class))
    self.g.add((self.PATTERN.TimeIncentivizationPattern, RDF.type, OWL.Class))
    self.g.add((self.PATTERN.EscapabilityPattern,    RDF.type, OWL.Class))
```

---

## Bootstrapping the Reasoning Properties

```python
def _bootstrap_reasoning_properties(self):
    """Bootstrap the three-property semantic reasoning mechanism in-memory."""
```

This is one of the most important methods in the entire analyzer. It programmatically adds three OWL object properties into the in-memory graph, along with the specific triples that link ontology classes to SUWC defect categories using those properties.

The **three properties** define the semantic reasoning vocabulary:

| Property | Direction | Meaning |
|----------|-----------|---------|
| `addressesDefect` | Pattern → Defect | "This pattern prevents this defect" |
| `indicatesDefectRisk` | Operation → Defect | "Performing this operation signals this defect risk" |
| `mitigatesDefect` | Operation → Defect | "Performing this operation guards against this defect" |

```python
# indicatesDefectRisk triples (9 risk-signaling operations)
risk_links = [
    (self.SUI.BalanceOperation,    self.SUWC["SUWC-AUTH-01"]),
    (self.SUI.BalanceMutation,     self.SUWC["SUWC-AUTH-01"]),
    (self.SUI.OwnershipTransfer,   self.SUWC["SUWC-AUTH-02"]),
    (self.SUI.ObjectCreation,      self.SUWC["SUWC-AUTH-03"]),
    (self.SUI.ObjectDeletion,      self.SUWC["SUWC-AUTH-04"]),
    (self.SUI.SharedStateMutation, self.SUWC["SUWC-CONS-01"]),
    (self.SUI.UnboundedIteration,  self.SUWC["SUWC-CONS-02"]),
    (self.SUI.TemporalCheck,       self.SUWC["SUWC-TIME-03"]),
    (self.SUI.TimestampComparison, self.SUWC["SUWC-TIME-04"]),
]
for operation, defect in risk_links:
    self.g.add((operation, self.INDICATES, defect))
```

For example, the triple `(SUI.BalanceOperation, indicatesDefectRisk, SUWC-AUTH-01)` encodes the knowledge: "Any function that performs a balance operation *without a guard* is at risk of AUTH-01 (missing access control on a financial function)."

```python
# mitigatesDefect triples (6 mitigation-providing operations)
mitigation_links = [
    (self.SUI.InvariantCheck,       self.SUWC["SUWC-CONS-01"]),
    (self.SUI.AMMInvariantCheck,    self.SUWC["SUWC-CONS-01"]),
    (self.SUI.AdminStateControl,    self.SUWC["SUWC-CONS-01"]),
    (self.SUI.TemporalConstraint,   self.SUWC["SUWC-TIME-01"]),
    (self.SUI.DynamicFieldOperation,self.SUWC["SUWC-RES-02"]),
    (self.SUI.OptionalExtraction,   self.SUWC["SUWC-RES-03"]),
]
```

Mitigating triples encode the opposite: "If a function also performs an InvariantCheck, it is protecting against CONS-01." The SPARQL query in `_sparql_detect_vulnerabilities()` uses both sets of triples together to reason about which functions are genuinely vulnerable (risk present, mitigation absent).

This "bootstrap" is designed to be performed multiple times without changing the final result beyond the initial application. By such, adding the same triple twice to an RDF graph simply has no effect, so even if the loaded `.ttl` file already contains these properties, there is no duplication.

---

## `reset_analysis()` Method

```python
def reset_analysis(self):
    """Reset analysis state for new contract"""
    self.g = Graph()
    self.g.bind("sui", self.SUI)
    ...
    self._load_ontology()
    self._bootstrap_reasoning_properties()
    self.function_count = 0
    ...
```

When the UI (Streamlit app) analyzes a second contract, it calls `reset_analysis()` to clear all state from the previous run. The RDF graph is completely replaced with a fresh instance, and all counters and caches are zeroed. This prevents contamination of one contract's results by data from a previously analyzed contract.

