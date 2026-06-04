# Section 1: Overview, Imports & Top-Level Architecture

## Purpose of the Analyzer

The `Comprehensive_Sui_Analyzer.py` is the central analysis engine of the entire toolchain. Its role is to take a raw Sui Move smart contract (as a string of source code) and produce a structured security report that includes:

- **Detected design patterns** (e.g., Access Control, Circuit Breaker)
- **DCR process graphs** representing behavioral models of those patterns
- **Vulnerability detections** mapped to the SUWC taxonomy (13 vulnerability types)
- **Fix suggestions** for each detected vulnerability
- **RDF knowledge graph** capturing all semantic information about the contract

---

## Python Imports

```python
import rdflib
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, OWL
import re
import os
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
```

Each import serves a specific purpose:

| Import | Purpose |
|--------|---------|
| `rdflib` | Provides the RDF graph data structure, namespaces, and SPARQL query engine |
| `re` | Regular expression engine — used throughout for pattern matching on source code |
| `os` | File system operations (checking if ontology file exists) |
| `json` | Serializing analysis results to JSON report files |
| `time` | Benchmarking ontology load time |
| `datetime` | Timestamping exported report files |
| `Dict, List, Optional, Tuple` | Type annotations for cleaner, self-documenting code |

---

## External Module Imports

```python
from DCR_Graph_Generator import (
    DCRGraphGenerator, DCRProcess, DCREvent, DCRRelation
)

from Automated_Fix_Suggester import (
    AutomatedFixSuggester, VulnerabilityDetection,
    VulnerabilityCategory, SeverityLevel
)
```

The analyzer is not a monolith — it delegates two major tasks to separate companion modules:

- **`DCR_Graph_Generator`**: Generates Dynamic Condition Response (DCR) process graphs from detected patterns. A DCR graph is a formal behavioral model showing the lifecycle of events and their constraints (e.g., "pause must happen before execute can occur").

- **`Automated_Fix_Suggester`**: When a vulnerability is detected, this module generates a human-readable fix suggestion, including an example code snippet and a reference to the recommended design pattern.

The data classes `VulnerabilityDetection`, `VulnerabilityCategory`, and `SeverityLevel` are also imported from the Fix Suggester module and used throughout the analyzer to represent detected vulnerabilities in a structured way.

---

## `PatternTypes` Class

```python
class PatternTypes:
    """Pattern constants for the 4 PhD research patterns."""
    ACCESS_CONTROL       = "AccessControlPattern"
    TIME_INCENTIVIZATION = "TimeIncentivizationPattern"
    CIRCUIT_BREAKER      = "CircuitBreakerPattern"
    ESCAPABILITY         = "EscapabilityPattern"
```

This is a simple constants class. Rather than scattering raw strings like `"AccessControlPattern"` across dozens of methods, the code uses `PatternTypes.ACCESS_CONTROL` everywhere. This prevents typos and makes it easy to see at a glance exactly which patterns the system recognizes. The four patterns correspond directly to the four PhD research design patterns:

1. **AccessControlPattern** — How a contract restricts who can call sensitive functions
2. **TimeIncentivizationPattern** — How a contract enforces time-based rules (locks, vesting, deadlines)
3. **CircuitBreakerPattern** — How a contract can be paused in emergencies
4. **EscapabilityPattern** — How a contract supports safe upgrades or emergency exits

---

## High-Level Analysis Flow

The entire analysis happens through a single public method: `analyze_contract()`. Internally, it calls four private methods in sequence:

```
analyze_contract(code, module_name)
    │
    ├── _parse_and_instantiate()     → Builds the RDF knowledge graph
    │       ├── Extracts structs
    │       ├── Extracts functions
    │       ├── _detect_patterns_enhanced()   → Per-function pattern detection
    │       └── _analyze_semantic_operations() → Per-function semantic tagging
    │
    ├── _generate_dcr_graphs()       → Turns detected patterns into DCR models
    │
    ├── _detect_all_vulnerabilities() → Runs vulnerability detection pipeline
    │       ├── _detect_auth_vulnerabilities()
    │       ├── _detect_time_vulnerabilities()
    │       ├── _detect_resource_vulnerabilities()
    │       ├── _detect_constraint_vulnerabilities()
    │       └── _sparql_detect_vulnerabilities()  → Semantic reasoning layer
    │
    └── _generate_fixes()            → Produces fix suggestions for each vuln
```

This sequential pipeline ensures that each stage has all the data it needs from the previous one. For example, SPARQL-based detection in `_detect_all_vulnerabilities()` depends on the RDF graph being fully populated by `_parse_and_instantiate()` first.

