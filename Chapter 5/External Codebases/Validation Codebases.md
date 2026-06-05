# 🔒 Validation Codebase URLs

The versions of the codebases used for external validation as of September 24, 2025.<br><br>

---

## 1. Access Control Pattern

**File:** `transfer_policy.move`  
**Commit:** `c3de14d`  
**Description:** Access control implementation for kiosk transfer policies.

**Raw URL:**  
```text
https://raw.githubusercontent.com/MystenLabs/sui/c3de14d/crates/sui-framework/packages/sui-framework/sources/kiosk/transfer_policy.move
```

---

## 2. Circuit Breaker Pattern

**File:** `coin.move`  
**Commit:** `c3de14d`  
**Description:** Implements circuit-breaking logic within Sui’s coin module.

**Raw URL:**  
```text
https://raw.githubusercontent.com/MystenLabs/sui/c3de14d/crates/sui-framework/packages/sui-framework/sources/coin.move
```

---

## 3. Escapability Pattern

**File:** `package.move`  
**Commit:** `c3de14d`  
**Description:** Demonstrates the escapability pattern for Move packages.

**Raw URL:**  
```text
https://raw.githubusercontent.com/MystenLabs/sui/c3de14d/crates/sui-framework/packages/sui-framework/sources/package.move
```

---

## 4. Time Incentivization Pattern

**Example:** `linear.move` (from Sui Docs)  
**Description:** Illustrates linear vesting strategies and time-based tokenomics.


---

### 🧩 Notes

- All URLs point to **immutable** commit-specific versions for reproducible validation (except the Time Incentivization Pattern which is downloaded, since it is not in Github and in case of changes or moving to other directory).
- Duplicate links were removed for clarity.
- You can use `curl` or `wget` for quick download, for example:
  ```bash
  curl -O https://raw.githubusercontent.com/MystenLabs/sui/c3de14d/crates/sui-framework/packages/sui-framework/sources/coin.move
  ```
