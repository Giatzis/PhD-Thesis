
<p align="center">
  <img src="https://img.shields.io/badge/Blockchain-Sui%20Move-blue?style=for-the-badge&logo=blockchain.com" alt="Blockchain"/>
  <img src="https://img.shields.io/badge/Ontology-OWL%2FRDF-green?style=for-the-badge" alt="Ontology"/>
  <img src="https://img.shields.io/badge/Method-Design%20Science%20Research-purple?style=for-the-badge" alt="DSR"/>
</p>

# Ontology-Driven Semantic Analysis of Sui Move Smart Contracts

> *A Design Science Research artifact for the detection, classification, and representation of business logic vulnerabilities/warnings in Sui Move smart contracts using ontology-driven semantic analysis.*

---

## Overview

Smart contracts on the Sui blockchain are written in Sui Move, a resource-oriented language designed to prevent low-level vulnerabilities such as reentrancy and integer overflow. However, **business logic vulnerabilities** — flaws in the intended semantic behavior of a contract — remain largely undetected by existing Static Application Security Testing (SAST) tools. These vulnerabilities arise not from syntactic errors but from incorrect or incomplete modeling of the application's intended behavior.

This doctoral research addresses that gap by constructing an **ontology-driven semantic analysis framework** that formalizes business logic vulnerability patterns in Sui Move. The framework integrates a structured taxonomy with OWL/RDF knowledge representation, SPARQL-based reasoning, and hybrid pattern detection to enable systematic, reproducible vulnerability identification.

The research follows the **Design Science Research (DSR)** methodology (Peffers et al., 2007; Hevner et al., 2004), producing a set of rigorously evaluated artifacts that contribute both practical tooling and theoretical knowledge to the blockchain security domain.

---

## Research Objectives

1. **Formalize** a comprehensive taxonomy of vulnerability classes specific to Sui Move smart contracts.
2. **Construct** an OWL/RDF ontology that encodes vulnerability patterns, contract structures, and semantic relationships.
3. **Implement** a hybrid detection engine combining SPARQL-based semantic reasoning with regex analysis.
4. **Evaluate** the framework against real-world Sui Move contracts using the FEDS (Framework for Evaluation in Design Science) methodology.

---

## Research Methodology

This thesis follows the **Design Science Research** paradigm, structured around six phases as defined by Peffers et al. (2007):

| DSR Phase | Activity in This Research |
|---|---|
| Problem Identification | Systematic literature review of Sui Move security |
| Objectives Definition | Formal specification of vulnerability classes and detection requirements |
| Design & Development | Ontology engineering (OWL/RDF), pattern library, detection engine implementation |
| Demonstration | Application to a constructed dataset of Sui Move smart contracts |
| Evaluation | FEDS-aligned metrics: precision, recall, ontology coverage, semantic consistency |
| Communication | Thesis document, peer-reviewed publication, open-source artifact release |


---

For detailed descriptions of the analyzer's features and capabilities, see the [Analyzer Functionality Documentation](./Analyzer%20Functionality%20Documentation).

## Framework Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                   Smart Contract Input Layer                        │
│          Sui Move source files (.move) / bytecode                   │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Static Analysis Engine                          │
│   AST Parsing · Regex Pattern Matching · Control Flow Extraction    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  Semantic Representation Layer                       │
│   OWL/RDF Ontology · SPARQL Reasoning · RDF Triple Store            │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Behavioral Modeling Layer (DCR Graphs)                │
│   OC-DCR Graph Generation · Temporal Pattern Detection              │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Vulnerability Report Layer                        │
│   Classified Findings · SPARQL Query Results · Streamlit Dashboard  │
└─────────────────────────────────────────────────────────────────────┘
```
---

## Getting Started

### Prerequisites

- Python 3.10+
- [Protégé](https://protege.stanford.edu/) (optional, for ontology inspection)

### Installation

```bash


# Install dependencies
python -m pip install streamlit rdflib
```

### Running the Analyzer

```bash
# Run the comprehensive Sui Move analyzer to see if running properly
python Comprehensive_Sui_Analyzer.py

# Run the evaluation test suite (42 tests)
python 42_tests.py

# Launch the Streamlit dashboard to use the analyzer
python -m streamlit run Defense_App.py
```
---

## Ontology Design

The core ontology is authored in **OWL 2 DL** and serialized as Turtle (TTL). It defines:

- **Concept hierarchy**: `VulnerabilityClass` → specific vulnerability types
- **Object properties**: `hasPattern`, `triggeredBy`, `affectsObject`, `requiresCapability`
- **Data properties**: `hasSeverity`, `hasConfidenceScore`, `detectedInFunction`
- **SWRL/SPARQL rules**: Inference rules for composite vulnerability detection

The ontology is validated using Protégé's HermiT reasoner to ensure consistency and completeness of the class hierarchy.

---

## Technologies & Tools

| Component | Technology |
|---|---|
| Smart Contract Language | Sui Move |
| Ontology Language | OWL 2 DL / RDF (Turtle) |
| Query Language | SPARQL 1.1 |
| Ontology Editor | Protégé + HermiT Reasoner |
| RDF Store / Reasoner | `rdflib` (Python) |
| Behavioral Modeling | OC-DCR graph library (Python) |
| Dashboard | Streamlit |
| Version Control | Git / GitHub |

---

## Key References

- Hevner, A. R., March, S. T., Park, J., & Ram, S. (2004). Design science in information systems research. *MIS Quarterly*, 28(1), 75–105.
- Peffers, K., Tuunanen, T., Rothenberger, M. A., & Chatterjee, S. (2007). A design science research methodology for information systems research. *Journal of Management Information Systems*, 24(3), 45–77.
- Venable, J., Pries-Heje, J., & Baskerville, R. (2016). FEDS: A framework for evaluation in design science research. *European Journal of Information Systems*, 25(1), 77–109.
- Blackshear, S., et al. (2019). Move: A language with programmable resources. *Libra Association White Paper*.
- Sui Foundation. (2023). *The Sui Smart Contract Platform*. https://docs.sui.io

---

## License

This repository is released under the [MIT License](LICENSE) for the software components. The ontology and taxonomy artifacts are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---


## Publications

- **Antonios Giatzis, Christos K. Georgiadis, Georgios Digkas**, “*A comparative analysis of ethereum solidity and sui move smart contract languages: Advantages and trade-offs*”, 6th World Symposium on Communication Engineering (WSCE), 2023.
- **Antonios Giatzis et al.**, “*Software Engineering Practices in Smart Contract Development: A Systematic Mapping Study*”, 25th International Conference on Product-Focused Software Process Improvement (PROFES), 2024.
- **Antonios Giatzis, Stamatis Papangelou, Christos K Georgiadis**, “*A Comparative Study of Solidity and Sui Move: Advancing Smart Contract Development*”, IEEE Access, 2025.
- **Antonios Giatzis, Christos K Georgiadis**, “*A Pattern-Oriented Ontology and Workflow Modeling Approach for the Sui Move Programming Language*”, Information, 2025.

---
<p align="center">
  <i>This research is conducted as part of a doctoral dissertation at the University of Macedonia, Thessaloniki.</i>
</p>
