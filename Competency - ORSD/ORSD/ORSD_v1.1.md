
# Ontology Requirements Specification Document (ORSD)

## Sui Move Security Ontology — v1.0

**Document Version:** 1.1
**Date:** April 27, 2026
**Supersedes:** v1.0 (April 25, 2026)
**Change Summary:** v1.1 corrects namespace IRIs in all SPARQL CQ queries (`suwc:`, `pattern:`), adds `owl:versionIRI` to the ontology header specification, fixes `dcterms:conformsTo` to match the canonical TTL value, adds authoritative namespace IRI table to Section 7, corrects OC-DCR event count in Section 13 (9 not 16), and adds `dcterms:` canonical URI fix note for the TTL.
**Author:** Antonios Giatzis, PhD Candidate
**Affiliation:** Department of Applied Informatics, University of Macedonia, Thessaloniki, Greece
**Ontology IRI:** `http://www.sui-move-ontology.com/ontology`
**Version IRI:** `http://www.sui-move-ontology.com/ontology/1.0`
**GitHub Repository:** https://github.com/Giatzis/PhD-Thesis
**Methodology:** LOT (Linked Open Terms) Industrial Ontology Engineering Framework

***

## 1. Purpose

The purpose of this ontology is to provide the **first formal, machine-readable semantic layer** for the Sui Move programming language. It addresses the critical semantic gap between high-level architectural intent and low-level Sui Move smart contract code — a gap that conventional code-centric security analysis tools are unable to bridge.

Specifically, the ontology serves four primary functions:

1. **Semantic formalization** of the complete Sui Move grammar (171/171 rules, 100% OBSE compliance) as a formal OWL 2 DL knowledge base, enabling machine-readable reasoning over language constructs.
2. **Vulnerability classification** via the Sui Move Weakness Classification (SUWC) taxonomy, providing a structured, severity-annotated catalogue of Sui-specific security defects organized into four categories (AUTH, TIME, RES, CONS).
3. **Pattern-to-code traceability** through a dual-layer semantic chain linking abstract business logic security patterns (the "why") to idiomatic Sui Move implementation techniques (the "how") and to the canonical code that realizes them.
4. **Behavioral specification bridging** by integrating Object-Centric Dynamic Condition Response (OC-DCR) process models with the structural ontology, enabling formal reasoning about the dynamic behavior of smart contracts, not just their static code structure.

***

## 2. Scope

The ontology covers the following domains:

- The **complete syntactic and semantic structure** of the Sui Move programming language, derived from the official Move Language Tree-Sitter Grammar specification (171 grammar rules, Move 2024 edition inclusive).
- The **Sui-specific runtime architecture**, including the object model, ownership types, programmable transaction blocks (PTBs), and on-chain deployment lifecycle.
- The **SUWC security defect taxonomy**, comprising 13 formally classified vulnerability defects across 4 categories.
- **Four canonical security design patterns** (Access Control, Circuit Breaker, Time Incentivization, Escapability), grounded in authoritative Sui Framework source code and validated against on-chain bytecode via the Sui Source Verification Service.
- The **Move Prover formal verification layer**, modeling `spec` blocks, clause types (`requires`, `ensures`, `aborts_if`, `modifies`, `invariant`), and verification coverage metadata.
- **OC-DCR process models**, providing object-centric behavioral specifications that link DCR events to Sui functions and DCR processes to Sui structs.

The ontology does **not** cover:

- Ethereum/Solidity-specific constructs or EVM semantics.
- Runtime execution trace analysis or dynamic symbolic execution.
- Automated decompilation or bytecode-level reverse engineering.

***

## 3. Implementation Language and Serialization

| Property | Value |
| :-- | :-- |
| Ontology Language | OWL 2 DL |
| Serialization Format | Turtle (`.ttl`) |
| W3C Standard | OWL 2 Web Ontology Language |
| Reasoner Tested | HermiT 1.4.3 (via Protégé 5.6.2) |
| Query Language | SPARQL 1.1 |
| Query Engine | RDFLib (Python, pure triple-store evaluation) |
| Ontology Editor | Protégé Desktop 5.6.2 |


***

## 4. Intended Uses

The ontology is intended to support the following use cases:

- **UC-01 — Security Auditing:** Enable automated or semi-automated detection of business logic flaws in Sui Move smart contracts by reasoning over the SUWC taxonomy and pattern library.
- **UC-02 — Pattern Recognition:** Identify whether a deployed contract module implements a known secure design pattern by querying the semantic chain from code constructs to implementation techniques to abstract patterns.
- **UC-03 — Behavioral Conformance Checking:** Verify that the dynamic behavior of a smart contract (modeled as an OC-DCR graph) conforms to the expected process semantics defined in the ontology.
- **UC-04 — Developer Education and IDE Integration:** Provide real-time, semantically aware feedback to developers, guiding them toward secure design patterns and flagging potential vulnerabilities during development.
- **UC-05 — Research Foundation:** Serve as a validated, citable semantic baseline for future research into automated pattern detection, LLM-assisted auditing, and cross-chain semantic interoperability.

***

## 5. Non-Functional Requirements

| ID | Requirement | Status |
| :-- | :-- | :-- |
| NFR-01 | The ontology must be logically consistent and free of internal contradictions (no unsatisfiable classes). | Verified -HermiT reasoner: 0 errors |
| NFR-02 | The ontology must achieve 100% OBSE (Ontology-Based Semantic Enrichment) compliance across all grammar rules. | 171/171 grammar rules covered |
| NFR-03 | All OWL classes must carry `rdfs:label` and `rdfs:comment` annotations. | 100% annotation coverage |
| NFR-04 | The ontology must be serialized in standard Turtle format compatible with mainstream semantic web toolchains (Protégé, Apache Jena, RDFLib). | Validated across all three |
| NFR-05 | The ontology IRI must be persistent and version-controlled, with `owl:versionIRI` and `owl:versionInfo` declared. | v1.0 — `owl:versionIRI <http://www.sui-move-ontology.com/ontology/1.0>` declared in header |
| NFR-06 | Provenance metadata must be encoded using Dublin Core Terms (`dcterms:`) and W3C PROV-O (`prov:`). | Declared in ontology header — **requires TTL fix**: `dcterms:` must bind to canonical `http://purl.org/dc/terms/` (current TTL uses non-standard `http://purl.org/dcterms#`) |
| NFR-07 | All IRI identifiers must be stable across versions to preserve backward compatibility with prior analyses. | No IRI renames between v3.5 and v1.0 |
| NFR-08 | The ontology must support SPARQL 1.1 querying against an explicit triple store (without OWL reasoning interference) for CQ validation. | Validated via RDFLib |


***

## 6. Ontology Metadata

> **⚠ TTL Implementation Note — `dcterms:` Namespace:** The canonical W3C Dublin Core Terms URI is `http://purl.org/dc/terms/`. The current TTL file declares `@prefix dcterms: <http://purl.org/dcterms#>`, which is a non-standard IRI. The TTL must be updated to use the canonical URI shown below to ensure interoperability with Protégé, Apache Jena, and Linked Data validators.

```turtle
# Required namespace prefixes for this metadata block
@prefix dcterms: <http://purl.org/dc/terms/> .
@prefix prov:    <http://www.w3.org/ns/prov#> .
@prefix owl:     <http://www.w3.org/2002/07/owl#> .
@prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:     <http://www.w3.org/2001/XMLSchema#> .

<http://www.sui-move-ontology.com/ontology>
    a owl:Ontology ;
    rdfs:label "Sui Move Ontology v1.0" ;
    owl:versionIRI <http://www.sui-move-ontology.com/ontology/1.0> ;
    owl:versionInfo "1.0" ;
    owl:priorVersion <http://www.sui-move-ontology.com/ontology/v0.1> ;
    dcterms:title "Sui Move Security Ontology" ;
    dcterms:creator "Antonios Giatzis" ;
    dcterms:abstract "First formal OWL 2 DL ontology for the Sui Move programming language, integrating a six-layer architecture (five architectural tiers) with SUWC vulnerability taxonomy, OC-DCR process models, and Move Prover verification layer future integration." ;
    dcterms:created "2024-01-15T00:00:00Z"^^xsd:dateTime ;
    dcterms:modified "2026-04-06T08:55:00Z"^^xsd:dateTime ;
    dcterms:conformsTo <http://obse-standard.org/> ;
    prov:wasGeneratedBy "LOT Ontology Engineering Methodology" ;
    owl:imports prov:, time: .
```


***

## 7. Ontology Architecture — Six Layers, Five Architectural Tiers

The ontology is structured into six distinct layers, with a foundational Grammar Layer (Layer 0) serving as the semantic anchor for all OBSE mappings. Each layer is independently queryable and extensible. Five domain-specific namespace prefixes (`sui:`, `suwc:`, `pattern:`, `dcr:`, `ocdcr:`) enforce layer separation across the ontology's architecture, while a sixth prefix (`prov:`) is imported from the W3C PROV-O vocabulary to encode ontology-level provenance metadata.

The authoritative IRI bindings for all domain namespace prefixes, as declared in the canonical Turtle serialization (`Sui_Move_Ontology-2.ttl`), are:

| Prefix | Namespace IRI |
| :-- | :-- |
| `sui:` | `http://www.sui-move-ontology.com/ontology#` |
| `suwc:` | `http://www.sui-move-ontology.com/defects/v1#` |
| `pattern:` | `http://www.sui-move-ontology.com/patterns/v1#` |
| `dcr:` | `http://purl.org/net/dcr#` |
| `ocdcr:` | `http://www.sui-move-ontology.com/ocdcr#` |
| `prov:` | `http://www.w3.org/ns/prov#` |

> All SPARQL queries in this document use these authoritative IRIs. Any prior versions of this document that listed `suwc:` as `http://www.sui-move-ontology.com/suwc#` or `pattern:` as `http://www.sui-move-ontology.com/pattern#` contained outdated namespace bindings that would produce empty result sets when executed against the canonical TTL.

> **Layer 0 — Grammar Layer (`sui:GrammarLayer`):** A foundational anchor class (`sui:GrammarLayer`) is declared in the ontology to represent the core Sui Move grammar semantics. It is the formal declaration of the grammar-driven nature of the ontology's semantic basis. The six numbered layers (Layer 0–5) of the ontology can be grouped conceptually into five architectural tiers, as Grammar (Layer 0) and Semantic (Layer 1) together form the foundational language representation tier, serving as its two Architectural sub-layers:


| Layer | Name | Namespace Prefix | Purpose | Key Classes |
| :-- | :-- | :-- | :-- | :-- |
| **Layer 1** | Semantic Layer | `sui:` | 1:1 mapping of 171 Sui Move grammar rules to OWL classes | `sui:Function`, `sui:Struct`, `sui:Object`, `sui:Expression`, `sui:Operator` |
| **Layer 2** | Security Layer (SUWC) | `suwc:` | Formal vulnerability defect taxonomy (13 defects, 4 categories) | `suwc:SUWC-AUTH-01`, `suwc:SUWC-TIME-01`, `suwc:SUWC-RES-02`, `suwc:SUWC-CONS-01` |
| **Layer 3** | Business Logic Patterns | `pattern:` / `sui:` | Dual-layer model linking abstract security goals ("why") to idiomatic Sui Move techniques ("how"), organized into Layer 3a (patterns) and Layer 3b (implementation techniques) | `pattern:AccessControlPattern`, `sui:CapabilityTechnique`, `sui:DynamicACLTechnique` |
| **Layer 4** | Behavioral Layer (OC-DCR) | `dcr:` / `ocdcr:` | Object-Centric DCR process models and behavioral specifications | `dcr:Process`, `dcr:Event`, `ocdcr:involvesEntity` |
| **Layer 5** | Verification Layer | `sui:` | Move Prover formal specification blocks and clause types | `sui:Specification`, `sui:RequiresClause`, `sui:EnsuresClause`, `sui:Invariant` |

### Layer Summary Descriptions

- **Layer 1 — Semantic Layer:** Establishes the foundational language structure through a 1:1 grammar-driven mapping of all 171 Sui Move grammar rules to OWL classes.
- **Layer 2 — Security Layer:** Encodes the SUWC vulnerability taxonomy, formally classifying 13 defects across 4 categories with severity annotations.
- **Layer 3 — Business Logic Patterns:** Formalizes the secure design pattern library through a dual sub-layer model. **Layer 3a** (`pattern:BusinessLogicPattern`) captures abstract security intent ("why"). **Layer 3b** (`sui:SuiImplementationPattern`) captures idiomatic Sui Move implementation techniques ("how"), connected through `sui:isImplementedBy` and `sui:realizesPattern` properties.
- **Layer 4 — Behavioral Layer:** Models the dynamic execution lifecycle of smart contract objects using OC-DCR process graphs, linking DCR events to Sui functions and DCR processes to Sui structs.
- **Layer 5 — Verification Layer:** Represents Move Prover formal specification blocks and clause types, enabling future integration.

***

## 8. SUWC Vulnerability Taxonomy

The ontology formally encodes 13 vulnerability defects across 4 categories, each annotated with severity level.

### Category AUTH — Authorization Defects

| ID | Name | Severity | Description |
| :-- | :-- | :-- | :-- |
| SUWC-AUTH-01 | Missing Signer Check | CRITICAL | Function lacks required signer/capability verification |
| SUWC-AUTH-02 | Capability Leakage | CRITICAL | AdminCap with `store`/`copy` ability exposed to unauthorized users |
| SUWC-AUTH-03 | Witness Pattern Violation | HIGH | One-Time Witness (OTW) struct borrowed instead of consumed |
| SUWC-AUTH-04 | Shared Object Permission Bypass | CRITICAL | Authorization check on shared object is ignored |

### Category TIME — Temporal Correctness Defects

| ID | Name | Severity | Description |
| :-- | :-- | :-- | :-- |
| SUWC-TIME-01 | Premature Release | CRITICAL | Time-locked assets released before vesting period elapses |
| SUWC-TIME-02 | Indefinite Lock | HIGH | Assets locked with impossible or missing extraction conditions |
| SUWC-TIME-03 | Timestamp Manipulation | HIGH | Relying on `timestamp_ms` instead of epoch for time-critical logic |
| SUWC-TIME-04 | Race Between Time Conditions | MEDIUM | Multiple transactions race on shared vesting/staking pool at epoch boundaries |

### Category RES — Resource Management Defects

| ID | Name | Severity | Description |
| :-- | :-- | :-- | :-- |
| SUWC-RES-01 | Hot Potato Drop | HIGH | Receipt struct with `drop` ability bypasses forced execution obligation |
| SUWC-RES-02 | Object Locking / Roach Motel | CRITICAL | Object wrapped permanently with no extraction mechanism |
| SUWC-RES-03 | Permanent Locking | CRITICAL | No way to extract assets from a locked state |

### Category CONS — Consensus/Concurrency Defects

| ID | Name | Severity | Description |
| :-- | :-- | :-- | :-- |
| SUWC-CONS-01 | Curve Invariant Violation | HIGH | Mathematical invariant (e.g., x\*y=k in AMM) breaks after state change |
| SUWC-CONS-02 | Vector-Based Denial of Service | CRITICAL | Unbounded iteration over collections causes gas exhaustion |


***

## 9. Business Logic Pattern Library (Layer 3)

Layer 3 introduces a dual-layer model organized into **Layer 3a** (abstract security intent) and **Layer 3b** (platform-specific implementation technique). The abstract level is represented by `pattern:BusinessLogicPattern` and the concrete level by `sui:SuiImplementationPattern`, connected through the `sui:isImplementedBy` and `sui:realizesPattern` properties.

The ontology defines 13 `sui:SecurityOperation` named individuals (9 `indicatesDefectRisk` rules, 4 `mitigatesDefect` rules encoded as explicit TTL triples). The analyzer additionally bootstraps a 5th `mitigatesDefect` rule at runtime (`AdminStateControl → SUWC-CONS-01`), providing semantic enrichment for contexts where admin state control operations serve as circuit-breaker mitigations for CONS-01 without an explicit invariant check.


| Pattern | Defects Addressed | Canonical Source | Sui Implementation Techniques (Layer 3b) |
| :-- | :-- | :-- | :-- |
| Access Control | AUTH-01, AUTH-02, AUTH-03, AUTH-04 | `transfer_policy.move` | `CapabilityTechnique`, `WitnessTechnique`, `DynamicACLTechnique` |
| Circuit Breaker | CONS-01, CONS-02 | `coin.move` (`DenyCapV2`) | `AdminStateControlTechnique` |
| Time Incentivization | TIME-01, TIME-02, TIME-03, TIME-04 | `linear.move` (Sui Vesting) | `EpochTimeLockTechnique` |
| Escapability | RES-01, RES-02, RES-03, AUTH-03, TIME-04 | `package.move` | `UpgradeCapTechnique`, `DynamicFieldExtractionTechnique` |


***

## 10. Competency Questions and SPARQL Validation

All 16 Competency Questions (CQs) were operationalized as SPARQL 1.1 queries and executed programmatically against the ontology using RDFLib. Evaluation was performed against the explicit triple store without OWL reasoning interference. All 16 queries returned **PASS** status (16/16).

**Correctness** is defined along two dimensions:

- **Syntactic completeness:** Each query returns a non-empty result set, confirming the ontology contains the knowledge the CQ was designed to retrieve.
- **Semantic accuracy:** The result counts match the expected outputs independently established from the authoritative source materials used during construction (the Sui Move formal grammar specification, the SUWC taxonomy design, and the canonical pattern documentation).

***

### Layer 1 — Semantic Layer CQs (CQ-01 to CQ-04)

These CQs verify that the structural and semantic grammar-driven layer correctly maps Sui Move language constructs to OWL classes.

***

**CQ-01**
> *Which OWL class maps to the Sui Move grammar rule `function_def`?*

**Purpose:** Confirms the 1:1 OBSE mapping between the grammar's `function_def` non-terminal and the `sui:Function` OWL class.
**Expected Result:** 1 class (`sui:Function`)
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?class ?comment WHERE {
    ?class a owl:Class .
    ?class rdfs:comment ?comment .
    FILTER(CONTAINS(LCASE(?comment), "function_def"))
}
```


***

**CQ-02**
> *What types of expressions are defined in the Sui Move semantic model?*

**Purpose:** Verifies that the expression subclasses (covering grammar rules 67–134) are correctly modeled as subclasses of `sui:Expression`.
**Expected Result:** 24 expression classes (base + 23 subclasses)
**Validation Result:** ✅ PASS — Result Count: 24

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?exprClass WHERE {
    ?exprClass rdfs:subClassOf* sui:Expression .
    ?exprClass a owl:Class .
}
```


***

**CQ-03**
> *What are the ownership types of a Sui Move object?*

**Purpose:** Confirms that all four `sui:OwnershipType` named individuals are present and correctly typed.
**Expected Result:** 4 individuals (`:AddressOwned`, `:Shared`, `:Immutable`, `:Wrapped`)
**Validation Result:** ✅ PASS — Result Count: 4

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?ownershipType ?label WHERE {
    ?ownershipType a sui:OwnershipType .
    ?ownershipType rdfs:label ?label .
}
```


***

**CQ-04**
> *What function visibility modifiers are defined in the ontology?*

**Purpose:** Validates that all three Sui Move visibility modifiers are modeled as individuals of `sui:Visibility`.
**Expected Result:** 3 individuals (`:public`, `:public_package`, `:private`)
**Validation Result:** ✅ PASS — Result Count: 3

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?visibility ?label WHERE {
    ?visibility a sui:Visibility .
    ?visibility rdfs:label ?label .
}
```


***

### Layer 2 — SUWC Security Taxonomy CQs (CQ-05 to CQ-09)

These CQs verify that the SUWC vulnerability taxonomy is correctly modeled, with all defects, categories, and severity annotations in place.

***

**CQ-05**
> *What are all vulnerability defects defined in the SUWC taxonomy?*

**Purpose:** Confirms the complete enumeration of all 13 SUWC defect classes.
**Expected Result:** 13 defect classes
**Validation Result:** ✅ PASS — Result Count: 13

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?defect ?label WHERE {
    ?defect a owl:Class .
    ?defect rdfs:subClassOf+ suwc:VulnerabilityCategory .
    ?defect rdfs:label ?label .
    FILTER NOT EXISTS { ?subDefect rdfs:subClassOf ?defect .
                        ?subDefect a owl:Class . }
}
```


***

**CQ-06**
> *Which vulnerability defects are classified as CRITICAL severity?*

**Purpose:** Verifies that the 7 CRITICAL-severity defects are correctly annotated in the ontology.
**Expected Result:** 7 CRITICAL defects (AUTH-01, AUTH-02, AUTH-04, TIME-01, RES-02, RES-03, CONS-02)
**Validation Result:** ✅ PASS — Result Count: 7

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?defect ?label WHERE {
    ?defect a owl:Class .
    ?defect rdfs:subClassOf+ suwc:VulnerabilityCategory .
    ?defect rdfs:comment ?comment .
    FILTER(CONTAINS(?comment, "CRITICAL"))
    ?defect rdfs:label ?label .
}
```


***

**CQ-07**
> *What vulnerability category does SUWC-AUTH-02 (Capability Leakage) belong to?*

**Purpose:** Confirms the correct categorical classification of a specific defect within the SUWC taxonomy hierarchy.
**Expected Result:** 1 result (`suwc:SUWC-AUTH`)
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?category WHERE {
    suwc:SUWC-AUTH-02 rdfs:subClassOf ?category .
    ?category rdfs:subClassOf suwc:VulnerabilityCategory .
}
```


***

**CQ-08**
> *Which security operations indicate a defect risk for SUWC-AUTH-01?*

**Purpose:** Validates that the `sui:indicatesDefectRisk` property correctly links security operations to SUWC-AUTH-01 (Missing Signer Check).
**Expected Result:** 2 operations (`sui:BalanceOperation`, `sui:BalanceMutation`)
**Validation Result:** ✅ PASS — Result Count: 2

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?operation ?label WHERE {
    ?operation a sui:SecurityOperation .
    ?operation sui:indicatesDefectRisk suwc:SUWC-AUTH-01 .
    ?operation rdfs:label ?label .
}
```


***

**CQ-09**
> *Which security operations mitigate SUWC-TIME-01 (Premature Release)?*

**Purpose:** Confirms that the `sui:mitigatesDefect` property is correctly populated for the Premature Release defect.
**Expected Result:** 1 operation (`sui:TemporalConstraint`)
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?operation ?label WHERE {
    ?operation a sui:SecurityOperation .
    ?operation sui:mitigatesDefect suwc:SUWC-TIME-01 .
    ?operation rdfs:label ?label .
}
```


***

### Layer 3a \& 3b — Business Logic Patterns and Techniques CQs (CQ-10 to CQ-12)

These CQs verify the pattern library (Layer 3a) and the dual-layer "why vs. how" semantic chain through to implementation techniques (Layer 3b).

***

**CQ-10**
> *What business logic patterns address SUWC-AUTH-01?*

**Purpose:** Confirms the `sui:addressesDefect` property correctly links the AccessControlPattern to SUWC-AUTH-01.
**Expected Result:** 1 pattern (`pattern:AccessControlPattern`)
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?pattern ?label WHERE {
    ?pattern a owl:Class .
    ?pattern rdfs:subClassOf pattern:BusinessLogicPattern .
    ?pattern sui:addressesDefect suwc:SUWC-AUTH-01 .
    ?pattern rdfs:label ?label .
}
```


***

**CQ-11**
> *Which defects does the AccessControlPattern address?*

**Purpose:** Retrieves all SUWC defects linked to the AccessControlPattern via `sui:addressesDefect`, verifying that all 4 AUTH defects are captured.
**Expected Result:** 4 defects (AUTH-01, AUTH-02, AUTH-03, AUTH-04)
**Validation Result:** ✅ PASS — Result Count: 4

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?defect ?label WHERE {
    pattern:AccessControlPattern sui:addressesDefect ?defect .
    ?defect rdfs:label ?label .
}
```


***

**CQ-12**
> *What Sui Move implementation techniques realize the AccessControlPattern?*

**Purpose:** Traverses the dual-layer semantic chain to retrieve all concrete implementation techniques linked to the AccessControlPattern via `sui:realizesPattern`.
**Expected Result:** 3 techniques (`:CapabilityTechnique`, `:WitnessTechnique`, `:DynamicACLTechnique`)
**Validation Result:** ✅ PASS — Result Count: 3

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

SELECT ?technique ?label WHERE {
    ?technique a sui:SuiImplementationPattern .
    ?technique sui:realizesPattern pattern:AccessControlPattern .
    ?technique rdfs:label ?label .
}
```


***

### Cross-Layer CQ — Full Semantic Chain (CQ-13)

This CQ validates the complete three-step semantic chain spanning Layers 2 and 3 in a single query.

***

**CQ-13**
> *What is the full chain from vulnerability defect → pattern → technique?*

**Purpose:** The most important structural CQ. Traverses the entire cross-layer semantic chain — from a SUWC defect, through the addressing business logic pattern, to the concrete Sui implementation technique — in a single query. The result of 28 distinct triples confirms all cross-layer links are correctly instantiated.
**Expected Result:** 28 unique defect → pattern → technique chains
**Validation Result:** ✅ PASS — Result Count: 28

```sparql
PREFIX suwc: <http://www.sui-move-ontology.com/defects/v1#>
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?defect ?defectLabel ?pattern ?patternLabel ?technique ?techniqueLabel WHERE {
    ?defect rdfs:subClassOf+ suwc:VulnerabilityCategory .
    ?pattern sui:addressesDefect ?defect .
    ?technique sui:realizesPattern ?pattern .
    ?defect rdfs:label ?defectLabel .
    ?pattern rdfs:label ?patternLabel .
    ?technique rdfs:label ?techniqueLabel .
}
ORDER BY ?defect ?pattern ?technique
```


***

### Layer 5 — Verification Layer CQ (CQ-14)


***

**CQ-14**
> *What formal specification clause types are defined in the Move Prover layer?*

**Purpose:** Confirms that all 8 Move Prover `SpecClause` subclasses are correctly modeled in the Verification Layer.
**Expected Result:** 8 clause types (`RequiresClause`, `EnsuresClause`, `AbortsIfClause`, `ModifiesClauseSpec`, `Invariant`, `SpecPragma`, `SpecInclude`, `SpecApply`)
**Validation Result:** ✅ PASS — Result Count: 8

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?clauseType ?label WHERE {
    ?clauseType rdfs:subClassOf sui:SpecClause .
    ?clauseType a owl:Class .
    ?clauseType rdfs:label ?label .
}
```


***

### Cross-Layer Semantic Properties CQs (CQ-15 to CQ-16)

These CQs verify the existence of cross-layer semantic properties that enable function-level vulnerability detection queries.

***

**CQ-15**
> *Is `requiresAccessControl` defined for functions (semantic detection flag)?*

**Purpose:** Confirms that the `sui:requiresAccessControl` datatype property is present in the ontology, enabling semantic flagging of functions that mandate capability-based access control enforcement.
**Expected Result:** 1 property definition
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?prop WHERE {
    sui:requiresAccessControl a owl:DatatypeProperty .
    BIND(sui:requiresAccessControl AS ?prop)
}
```


***

**CQ-16**
> *Is `performsOperation` defined, enabling function-to-SecurityOperation linking?*

**Purpose:** Confirms that the `sui:performsOperation` object property is present, enabling the linking of `sui:Function` instances to `sui:SecurityOperation` individuals — the foundation for automated vulnerability risk flagging.
**Expected Result:** 1 property definition
**Validation Result:** ✅ PASS — Result Count: 1

```sparql
PREFIX sui: <http://www.sui-move-ontology.com/ontology#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>

SELECT ?prop WHERE {
    sui:performsOperation a owl:ObjectProperty .
    BIND(sui:performsOperation AS ?prop)
}
```


***

## 11. CQ Validation Summary

| CQ | Layer | Question (Summary) | Expected | Actual | Status |
| :-- | :-- | :-- | :-- | :-- | :-- |
| CQ-01 | Layer 1 — Semantic | OWL class for `function_def` grammar rule | 1 | 1 | ✅ PASS |
| CQ-02 | Layer 1 — Semantic | Expression types in semantic model | 24 | 24 | ✅ PASS |
| CQ-03 | Layer 1 — Semantic | Ownership types of a Sui Move object | 4 | 4 | ✅ PASS |
| CQ-04 | Layer 1 — Semantic | Function visibility modifiers | 3 | 3 | ✅ PASS |
| CQ-05 | Layer 2 — SUWC | All SUWC vulnerability defects | 13 | 13 | ✅ PASS |
| CQ-06 | Layer 2 — SUWC | CRITICAL severity defects | 7 | 7 | ✅ PASS |
| CQ-07 | Layer 2 — SUWC | Category of SUWC-AUTH-02 | 1 | 1 | ✅ PASS |
| CQ-08 | Layer 2 — SUWC | Risk-indicating operations for SUWC-AUTH-01 | 2 | 2 | ✅ PASS |
| CQ-09 | Layer 2 — SUWC | Mitigating operations for SUWC-TIME-01 | 1 | 1 | ✅ PASS |
| CQ-10 | Layer 3a — Patterns | Patterns addressing SUWC-AUTH-01 | 1 | 1 | ✅ PASS |
| CQ-11 | Layer 3a — Patterns | Defects addressed by AccessControlPattern | 4 | 4 | ✅ PASS |
| CQ-12 | Layer 3b — Techniques | Techniques realizing AccessControlPattern | 3 | 3 | ✅ PASS |
| CQ-13 | Layers 2–3 — Full Chain | Full defect → pattern → technique chain | 28 | 28 | ✅ PASS |
| CQ-14 | Layer 5 — Verification | Move Prover spec clause types | 8 | 8 | ✅ PASS |
| CQ-15 | Layers 1–2 — Cross-Layer | `requiresAccessControl` property defined | 1 | 1 | ✅ PASS |
| CQ-16 | Layers 1–2 — Cross-Layer | `performsOperation` property defined | 1 | 1 | ✅ PASS |

**Overall CQ Validation: 16/16 PASS (100%)**

***

## 12. LOT Activity Traceability

This ORSD serves as the formal artifact for **LOT Activity 1 (Ontological Requirements Specification)**. The following table maps each LOT activity to its corresponding artifact or section within the PhD thesis chapter.


| LOT Activity | Description | Thesis Artifact / Section |
| :-- | :-- | :-- |
| **Activity 1** — Requirements Specification | ORSD document; 16 CQs derived and validated | This document; Section 5.1 (CQ Validation) |
| **Activity 2** — Ontology Implementation | OWL 2 DL serialization in Turtle; 6-layer architecture (5 architectural tiers); 100% OBSE compliance | Sections 3.2–3.5; GitHub v1.0 release |
| **Activity 3** — Ontology Publication | Persistent IRI with versioning and provenance metadata declared using Dublin Core Terms and W3C PROV-O; maintained under version control via GitHub | Ontology metadata header; GitHub repository |
| **Activity 4** — Ontology Evaluation | HermiT logical consistency verification; SPARQL CQ suite as regression harness; qualitative pattern validation against canonical Sui Framework sources | Sections 5.1–5.5 |
| **Activity 5** — Ontology Maintenance | Versioned changelog discipline governing all future releases; all original IRIs preserved to guarantee backward compatibility; applied manually through ontology metadata updates and GitHub version control commits | Section 5.6; Sections 6 (Limitations) |


***

## 13. Coverage Metrics

| Metric | Value |
| :-- | :-- |
| Grammar Rules Covered | 171 / 171 (100%) |
| OBSE-Compliant Mappings | 171 / 171 (100%) |
| OWL Classes | 105+ |
| OWL Properties (Object + Datatype) | 55+ |
| Named Individuals | 57 |
| SUWC Vulnerability Defects | 13 |
| SUWC Vulnerability Categories | 4 |
| Security Design Patterns | 4 |
| Implementation Techniques (Layer 3b) | 7 |
| SecurityOperation Individuals | 13 |
| `indicatesDefectRisk` Rules (TTL-encoded) | 9 |
| `mitigatesDefect` Rules (TTL-encoded) | 4 |
| `mitigatesDefect` Rules (analyzer-bootstrapped) | 1 (`AdminStateControl → SUWC-CONS-01`) |
| `addressesDefect` Rules | 15 |
| Move Prover Spec Clause Types | 8 |
| OC-DCR Process Model Events | 9 (AC: 3, TI: 2, CB: 2, ES: 2) |
| Domain Namespace Prefixes | 5 (`sui:`, `suwc:`, `pattern:`, `dcr:`, `ocdcr:`) |
| External Vocabulary Prefixes | 1 (`prov:`) |
| CQs Validated | 16 / 16 (100%) |
| HermiT Reasoner Errors | 0 |


***

## 14. Key References

- Poveda-Villalón, M., Fernández-Izquierdo, A., Fernández-López, M., García-Castro, R. (2022). LOT: An industrial oriented ontology engineering framework. *Engineering Applications of Artificial Intelligence*, 111, 104755.
- Mysten Labs (2025). Move Language Tree-Sitter Grammar. https://github.com/MystenLabs/sui/blob/main/external-crates/move/tooling/tree-sitter/src/grammar.json
- W3C (2012). OWL 2 Web Ontology Language Document Overview (Second Edition). https://www.w3.org/TR/owl2-overview/
- Harris, S., \& Seaborne, A. (2013). SPARQL 1.1 Query Language. W3C Recommendation. https://www.w3.org/TR/sparql11-query/
- RDFLib Contributors (2024). RDFLib: A Python Library for Working with RDF. https://github.com/RDFLib/rdflib
- Welc, A., \& Blackshear, S. (2023). Sui Move: Modern Blockchain Programming with Objects. ACM SIGPLAN.
- Christfort, A.K.F., Rivkin, A., Fahland, D., Hildebrandt, T.T., \& Slaats, T. (2024). Discovery of Object-Centric Declarative Models. ICPM 2024.
- Giatzis, A., \& Georgiadis, C.K. (2026). A Pattern-Oriented Ontology and Workflow Modeling Approach for the Sui Move Programming Language. *Information*, 17(1), 4.

***

