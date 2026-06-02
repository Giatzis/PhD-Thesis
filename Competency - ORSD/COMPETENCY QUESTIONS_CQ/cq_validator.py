#!/usr/bin/env python3
"""
SPARQL Competency Question Validator
Sui Move Smart Contract Security Ontology — ORSD Validation
Runs all 16 verified CQs against the ontology using RDFLib (no OWL reasoner).

Usage:
    pip install rdflib
    python cq_validator.py [path/to/ontology.ttl]
"""

import sys
from rdflib import Graph, Namespace

TTL_FILE = sys.argv[1] if len(sys.argv) > 1 else "Sui_Move_Ontology_v4.ttl"

# ── Namespaces ──────────────────────────────────────────────────────────────
SUI     = Namespace("http://www.sui-move-ontology.com/ontology#")
SUWC    = Namespace("http://www.sui-move-ontology.com/defects/v1#")
PATTERN = Namespace("http://www.sui-move-ontology.com/patterns/v1#")
DCR     = Namespace("http://purl.org/net/dcr#")

PREFIX_BLOCK = """
PREFIX sui:     <http://www.sui-move-ontology.com/ontology#>
PREFIX suwc:    <http://www.sui-move-ontology.com/defects/v1#>
PREFIX pattern: <http://www.sui-move-ontology.com/patterns/v1#>
PREFIX dcr:     <http://purl.org/net/dcr#>
PREFIX ocdcr:   <http://www.sui-move-ontology.com/ocdcr#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl:     <http://www.w3.org/2002/07/owl#>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>
"""

# ── Competency Questions ────────────────────────────────────────────────────
CQS = [
    (
        "CQ-01",
        "Layer 1 — Semantic",
        "Which OWL class maps to the Sui Move grammar rule function_def?",
        PREFIX_BLOCK + """
SELECT ?class ?label WHERE {
  ?class a owl:Class ;
         rdfs:comment ?comment ;
         rdfs:label ?label .
  FILTER(CONTAINS(LCASE(STR(?comment)), "function_def"))
}"""
    ),
    (
        "CQ-02",
        "Layer 1 — Semantic",
        "What types of expressions are defined in the Sui Move semantic model?",
        PREFIX_BLOCK + """
SELECT ?expr ?label WHERE {
  ?expr a owl:Class ;
        rdfs:subClassOf sui:Expression ;
        rdfs:label ?label .
} ORDER BY ?label"""
    ),
    (
        "CQ-03",
        "Layer 1 — Semantic",
        "What are the ownership types of a Sui Move object?",
        PREFIX_BLOCK + """
SELECT ?individual ?label WHERE {
  ?individual a sui:OwnershipType ;
              a owl:NamedIndividual ;
              rdfs:label ?label .
}"""
    ),
    (
        "CQ-04",
        "Layer 1 — Semantic",
        "What function visibility modifiers are defined in the ontology?",
        PREFIX_BLOCK + """
SELECT ?individual ?label WHERE {
  ?individual a sui:Visibility ;
              a owl:NamedIndividual ;
              rdfs:label ?label .
}"""
    ),
    (
        "CQ-05",
        "Layer 2 — SUWC",
        "What are all vulnerability defects defined in the SUWC taxonomy?",
        PREFIX_BLOCK + """
SELECT ?defect ?label WHERE {
  ?defect a owl:Class ;
          rdfs:subClassOf ?category ;
          rdfs:label ?label .
  ?category rdfs:subClassOf suwc:VulnerabilityCategory .
  FILTER(REGEX(STR(?defect), "SUWC-[A-Z]+-[0-9]+"))
  FILTER(REGEX(STR(?label), "^SUWC-[A-Z]+-[0-9]+$"))
} ORDER BY ?label"""
    ),
    (
        "CQ-06",
        "Layer 2 — SUWC",
        "Which vulnerability defects are classified as CRITICAL severity?",
        PREFIX_BLOCK + """
SELECT ?defect ?label WHERE {
  ?defect a owl:Class ;
          rdfs:subClassOf ?category ;
          rdfs:label ?label ;
          rdfs:comment ?severity .
  ?category rdfs:subClassOf suwc:VulnerabilityCategory .
  FILTER(CONTAINS(STR(?severity), "CRITICAL"))
  FILTER(REGEX(STR(?label), "^SUWC-[A-Z]+-[0-9]+$"))
} ORDER BY ?label"""
    ),
    (
        "CQ-07",
        "Layer 2 — SUWC",
        "What vulnerability category does SUWC-AUTH-02 (Capability Leakage) belong to?",
        PREFIX_BLOCK + """
SELECT ?category ?categoryLabel WHERE {
  suwc:SUWC-AUTH-02 rdfs:subClassOf ?category .
  ?category rdfs:label ?categoryLabel .
  FILTER(REGEX(STR(?categoryLabel), "^SUWC-[A-Z]+$|Defects$"))
} LIMIT 1"""
    ),
    (
        "CQ-08",
        "Layer 2 — SUWC",
        "Which security operations indicate a defect risk for SUWC-AUTH-01?",
        PREFIX_BLOCK + """
SELECT ?operation ?label WHERE {
  ?operation sui:indicatesDefectRisk suwc:SUWC-AUTH-01 ;
             rdfs:label ?label .
}"""
    ),
    (
        "CQ-09",
        "Layer 2 — SUWC",
        "Which security operations mitigate SUWC-TIME-01 (Premature Release)?",
        PREFIX_BLOCK + """
SELECT ?operation ?label WHERE {
  ?operation sui:mitigatesDefect suwc:SUWC-TIME-01 ;
             rdfs:label ?label .
}"""
    ),
    (
        "CQ-10",
        "Layer 3a — Patterns",
        "What business logic patterns address SUWC-AUTH-01?",
        PREFIX_BLOCK + """
SELECT ?pattern ?label WHERE {
  ?pattern sui:addressesDefect suwc:SUWC-AUTH-01 ;
           rdfs:label ?label .
}"""
    ),
    (
        "CQ-11",
        "Layer 3a — Patterns",
        "Which defects does the AccessControlPattern address?",
        PREFIX_BLOCK + """
SELECT ?defect ?defectLabel WHERE {
  pattern:AccessControlPattern sui:addressesDefect ?defect .
  ?defect rdfs:label ?defectLabel .
  FILTER(REGEX(STR(?defectLabel), "^SUWC-[A-Z]+-[0-9]+$"))
}"""
    ),
    (
        "CQ-12",
        "Layer 3b — Techniques",
        "What Sui Move implementation techniques realize the AccessControlPattern?",
        PREFIX_BLOCK + """
SELECT ?technique ?label ?comment WHERE {
  ?technique sui:realizesPattern pattern:AccessControlPattern ;
             rdfs:label ?label ;
             rdfs:comment ?comment .
}"""
    ),
    (
        "CQ-13",
        "Layers 2-3 — Full Chain",
        "What is the full chain from vulnerability defect to pattern to technique?",
        PREFIX_BLOCK + """
SELECT DISTINCT ?defectLabel ?patternLabel ?techniqueLabel WHERE {
  ?pattern sui:addressesDefect ?defect ;
           rdfs:label ?patternLabel .
  ?defect  rdfs:label ?defectLabel .
  ?technique sui:realizesPattern ?pattern ;
              rdfs:label ?techniqueLabel .
  FILTER(REGEX(STR(?defectLabel), "^SUWC-[A-Z]+-[0-9]+$"))
  FILTER(REGEX(STR(?patternLabel), "Pattern$"))
} ORDER BY ?defectLabel ?patternLabel"""
    ),
    (
        "CQ-14",
        "Layer 5 — Verification",
        "What formal specification clause types are defined in the Move Prover layer?",
        PREFIX_BLOCK + """
SELECT ?clause ?label WHERE {
  ?clause a owl:Class ;
          rdfs:subClassOf sui:SpecClause ;
          rdfs:label ?label .
} ORDER BY ?label"""
    ),
    (
        "CQ-15",
        "Layers 1-2 — Cross-Layer",
        "Is requiresAccessControl defined for functions (semantic detection flag)?",
        PREFIX_BLOCK + """
SELECT ?property ?domain ?range ?comment WHERE {
  sui:requiresAccessControl a owl:DatatypeProperty ;
                             rdfs:domain ?domain ;
                             rdfs:range  ?range ;
                             rdfs:comment ?comment .
}"""
    ),
    (
        "CQ-16",
        "Layers 1-2 — Cross-Layer",
        "Is performsOperation defined, enabling function-to-SecurityOperation linking?",
        PREFIX_BLOCK + """
SELECT ?property ?domain ?range ?comment WHERE {
  sui:performsOperation a owl:ObjectProperty ;
                        rdfs:domain ?domain ;
                        rdfs:range  ?range ;
                        rdfs:comment ?comment .
}"""
    ),
]

# ── Runner ──────────────────────────────────────────────────────────────────
def run():
    print(f"Loading ontology: {TTL_FILE}")
    g = Graph()
    g.parse(TTL_FILE, format="turtle")
    print(f"Graph loaded: {len(g)} triples\n")
    print("=" * 72)

    passed = 0
    failed = 0
    results_log = []

    for cq_id, layer, question, query in CQS:
        try:
            rows = list(g.query(query))
            status = "PASS" if rows else "EMPTY"
            if rows:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            rows = []
            status = f"ERROR: {e}"
            failed += 1

        print(f"[{status}] {cq_id} ({layer})")
        print(f"  Q: {question}")
        if rows:
            for i, row in enumerate(rows):
                vals = " | ".join(str(v).split("#")[-1] if v else "-" for v in row)
                print(f"    {i+1:>2}. {vals}")
        elif status == "EMPTY":
            print(f"    (no results)")
        print()
        results_log.append((cq_id, layer, question, status, len(rows)))

    print("=" * 72)
    print(f"SUMMARY: {passed} PASS | {failed} EMPTY/ERROR | {passed}/{passed+failed} total")
    print("=" * 72)

    # Write CSV log
    import csv
    with open("cq_validation_results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CQ", "Layer", "Question", "Status", "Result Count"])
        writer.writerows(results_log)
    print("\nResults saved to: cq_validation_results.csv")

if __name__ == "__main__":
    run()
