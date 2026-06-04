# Section 3: Parsing & RDF Graph Instantiation

## Role of `_parse_and_instantiate()`

This method is the **first major stage** of the analysis pipeline. Its job is to read raw Sui Move source code, extract all the structural elements (module name, structs, functions), and record everything as RDF triples in the knowledge graph. By the time this method finishes, `self.g` contains a structured semantic representation of the entire contract.

```python
def _parse_and_instantiate(self, code: str, module_name: str) -> bool:
    """Parse Move code and instantiate RDF knowledge graph"""
```

It returns `True` on success and `False` if no module definition is found (in which case the entire analysis is aborted).

---

## Step 1: Comment Stripping

Before any regex can reliably match on code structure, comments must be removed. Otherwise a pattern like `// fun fake_function(cap: &AdminCap)` inside a comment could trigger a false detection.

```python
content_clean = re.sub(r'//.*',       '', code)
content_clean = re.sub(r'/\*.*?\*/', '', content_clean, flags=re.DOTALL)
```

The first substitution removes single-line comments (`// ...`). The second removes multi-line block comments (`/* ... */`). The `re.DOTALL` flag makes `.` match newlines, which is necessary for multi-line block comments. Both patterns are replaced with empty strings, leaving clean code.

---

## Step 2: Module Extraction

```python
module_match = re.search(r'module\s+([a-zA-Z0-9_:]+)', content_clean)
if not module_match:
    print("❌ No module definition found")
    return False

module_name_extracted = module_match.group(1).replace(':', '_')
module_uri = self.SUI[f"Module_{module_name_extracted}"]
self.g.add((module_uri, RDF.type, self.SUI.Module))
self.g.add((module_uri, RDFS.label, Literal(module_name_extracted)))
```

The regex `module\s+([a-zA-Z0-9_:]+)` captures the module identifier from declarations like `module defense::complete_defi`. The `::` separator is replaced with `_` to create a valid URI fragment. Two RDF triples are then added:

- `Module_defense_complete_defi  rdf:type  sui:Module` — classifies this URI as a Module
- `Module_defense_complete_defi  rdfs:label  "defense_complete_defi"` — gives it a human-readable label

---

## Step 3: Struct Extraction

```python
struct_pattern = re.compile(
    r'(?:public\s+)?struct\s+([a-zA-Z_]\w*)\s+has\s+([^{]+)\{([^}]*)}',
    re.DOTALL
)

for match in struct_pattern.finditer(content_clean):
    struct_name = match.group(1).strip()
    abilities   = match.group(2).strip()
    fields      = match.group(3).strip()

    self.parsed_structs[struct_name] = {
        "abilities":  abilities,
        "fields":     fields,
        "full_text":  match.group(0)
    }
```

The struct regex captures three groups from declarations like:
```
public struct LiquidityPool has key {
    id: UID,
    reserve_x: Balance<SUI>,
    reserve_y: Balance<SUI>,
    total_shares: u64
}
```

- **Group 1** (`struct_name`): `LiquidityPool`
- **Group 2** (`abilities`): `key`
- **Group 3** (`fields`): the raw field text block

Each struct is stored in `self.parsed_structs` as a dictionary. This cached representation is heavily used later in vulnerability detection — for example, to check whether a struct has `store` or `copy` abilities (AUTH-02), or whether it holds financial fields (RES-02, CONS-01).

---

## Step 4: Function Extraction

The function extraction regex is one of the most detailed parts of the parser. It was specifically extended during the April 2026 refactor to also capture return types:

```python
func_pattern = re.compile(
    r'((?:public\s+(?:entry\s+)?|entry\s+)?)'   # Group 1: modifiers
    r'fun\s+'
    r'([a-zA-Z_]\w*)'                            # Group 2: function name
    r'\s*(?:<[^>]+>)?'                           # optional type parameters
    r'\s*\('
    r'([^)]*)'                                   # Group 3: parameter list
    r'\)'
    r'([^{]*?)'                                  # Group 4: return type
    r'\{',
    re.DOTALL | re.MULTILINE
)
```

For a function like:
```
public fun swap_x_to_y(pool: &mut LiquidityPool, coin_x: Coin<SUI>, ctx: &mut TxContext): Coin<SUI> {
```

The regex extracts:
- **Group 1** (modifiers): `public `
- **Group 2** (name): `swap_x_to_y`
- **Group 3** (params): `pool: &mut LiquidityPool, coin_x: Coin<SUI>, ctx: &mut TxContext`
- **Group 4** (return type): `: Coin<SUI>`

Capturing the return type was critical for **Layer 2 of the Behavioral Privilege Classifier** — a function that returns `Coin<T>` is giving assets to the caller, which is normal user-facing behavior and should **not** be classified as privileged.

---

## Step 5: Body Extraction with Brace Balancing

After the regex finds where a function starts (the opening `{`), the body is extracted by a separate method:

```python
def _extract_balanced_body(self, text, start_index):
    """Extract function body with balanced braces"""
    brace_count = 0
    i = start_index

    if i >= len(text) or text[i] != '{':
        return ""

    while i < len(text):
        if text[i] == '{':
            brace_count += 1
        elif text[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                return text[start_index + 1:i].strip()
        i += 1
    return ""
```

This is a simple **brace-balance algorithm** — a classic technique for parsing nested structures. It increments a counter for every `{` and decrements for every `}`. When the counter reaches zero again, the matching closing brace has been found. This correctly handles nested blocks (inner `if`, `loop`, `match` expressions) within a function body.

Without this, a regex like `\{.*?\}` would stop at the first closing brace it encountered, cutting off the function body prematurely.

---

## Step 6: RDF Graph Population Per Function

For each extracted function, several triples are added to the graph:

```python
func_uri = self.SUI[f"Func_{func_name}"]

is_entry = "entry" in modifiers
if is_entry:
    self.g.add((func_uri, RDF.type, self.SUI.EntryFunction))
else:
    self.g.add((func_uri, RDF.type, self.SUI.Function))

self.g.add((func_uri, RDFS.label, Literal(func_name)))
self.g.add((module_uri, self.SUI.defines, func_uri))
```

This records three facts about every function:
1. Its **type** (either `EntryFunction` or `Function`)
2. Its **label** (human-readable name, used in SPARQL query output)
3. The **`defines`** relationship from the module to the function

Then, per-function analyses are immediately run:

```python
detected_patterns = self._detect_patterns_enhanced(
    params, body, func_uri, func_name, self.parsed_structs
)
semantic_ops = self._analyze_semantic_operations(func_name, params, body, func_uri)
```

Both of these methods add further triples to the graph (`implementsPattern`, `performsOperation`) as they find relevant evidence.

---

## Step 7: Temporal Context Detection

```python
self.has_temporal_context = self._check_temporal_context()
if self.has_temporal_context:
    print(f"⏰ Temporal context detected (time-locking features present)")
```

```python
def _check_temporal_context(self) -> bool:
    # CHECK 1 — Clock parameter in any function
    for func_info in self.parsed_functions.values():
        if re.search(r'\b&?\s*Clock\b', func_info['params']):
            return True

    # CHECK 2 — clock::/epoch/timestamp in any function body
    for func_info in self.parsed_functions.values():
        if re.search(r'clock::|epoch|timestamp', func_info['body'], re.IGNORECASE):
            return True

    # CHECK 3 — FALLBACK: temporal field names in structs
    temporal_field_patterns = [
        r'unlock_time', r'lock_time', r'start_time', r'end_time',
        r'vesting_start', r'vesting_end', r'cliff_time',
        r'release_time', r'deadline', r'expiry', r'timestamp', r'schedule'
    ]
    for struct_info in self.parsed_structs.values():
        fields = struct_info['fields'].lower()
        for pattern in temporal_field_patterns:
            if re.search(pattern, fields, re.IGNORECASE):
                return True

    return False
```

This method  prioritize behavioral checks over field name checks. The rationale: a contract that actually calls `clock::timestamp_ms()` is unambiguously temporal. A contract that merely has a field named `start_time` might just be using that as metadata without any time-enforcement logic. The three-level priority order (API call → body usage → field name fallback) minimizes false context detections.

