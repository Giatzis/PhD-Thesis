# **All Sui Move Test Contracts (42 Tests)**

This document contains all 42 Sui Move smart contract test cases exactly as used in the 42\_tests.py evaluation suite script.

## **Test Suite Organization**

* **Pattern Detection Tests (14 tests):** Test detection of 4 security design patterns  
* **Heuristic Classification Tests (12 tests):** Test privileged vs. public operation classification  
* **Regex Coverage Tests (5 tests):** Test capability and pattern recognition edge cases  
* **False Positive/Negative Tests (6 tests):** Test semantic understanding of business logic  
* **Integration Tests (5 tests):** Test complete DeFi protocols, DCR graphs, RDF ontology, pipeline linkage, and cross-category detection

## **1\. PATTERN DETECTION TESTS (14 tests)**

### **1.1 Access Control Pattern \- AdminCap**

module test::access\_control {  
    struct AdminCap has key, store { id: UID }  
    public entry fun admin\_only\_function(\_admin: \&AdminCap, ctx: \&mut TxContext) {}  
}

### **1.2 Access Control Pattern \- OwnerCap**

module test::owner {  
    struct OwnerCap has key, store { id: UID }  
    public entry fun owner\_only\_function(\_owner: \&OwnerCap, ctx: \&mut TxContext) {}  
}

### **1.3 Access Control Pattern \- TreasuryCap**

module test::treasury {  
    use sui::coin::TreasuryCap;  
    public entry fun mint\_tokens\<T\>(treasury: \&mut TreasuryCap\<T\>, ctx: \&mut TxContext) {}  
}

### **1.4 Access Control Pattern \- Dynamic ACL (Table)**

module test::dynamic\_acl {  
    use sui::table::{Self, Table};  
    use sui::tx\_context::{Self, TxContext};  
    struct Registry has key { id: UID, admins: Table\<address, bool\>      }  
    public entry fun admin\_function(registry: \&Registry, ctx: \&mut TxContext) {  
        let sender \= tx\_context::sender(ctx);  
        assert\!(table::contains(\&registry.admins, sender), 0);  
    }  
}

### **1.5 Access Control Pattern \- Dynamic ACL (VecSet)**

module test::vecset\_acl {  
    use sui::vec\_set::{Self, VecSet};  
    use sui::tx\_context::{Self, TxContext};  
    struct Whitelist has key { id: UID, members: VecSet\<address\> }  
    public entry fun member\_only\_function(whitelist: \&Whitelist, ctx: \&mut TxContext) {  
        let sender \= tx\_context::sender(ctx);  
        assert\!(vec\_set::contains(\&whitelist.members, \&sender), 0);  
    }  
}

### **1.6 Access Control Pattern \- Inline Authorization**

module test::inline\_auth {  
    struct Wallet has key { id: UID, owner: address, balance: u64 }  
    public entry fun withdraw(wallet: \&mut Wallet, ctx: \&mut TxContext) {  
        assert\!(wallet.owner \== tx\_context::sender(ctx), 0);  
    }  
}

### **1.7 Circuit Breaker Pattern \- PauseCap**

module test::pause {  
    struct PauseCap has key, store { id: UID }  
    struct Protocol has key { id: UID, paused: bool }  
    public entry fun pause(\_cap: \&PauseCap, protocol: \&mut Protocol, ctx: \&mut TxContext) { protocol.paused \= true; }  
    public entry fun unpause(\_cap: \&PauseCap, protocol: \&mut Protocol, ctx: \&mut TxContext) { protocol.paused \= false; }  
}

### **1.8 Circuit Breaker Pattern \- EmergencyCap**

module test::emergency {  
    struct EmergencyCap has key, store { id: UID }  
    public entry fun emergency\_shutdown(\_cap: \&EmergencyCap, ctx: \&mut TxContext) {}  
}

### **1.9 Circuit Breaker Pattern \- DenyCap**

module test::deny {  
    use sui::coin::DenyCap;  
    public entry fun deny\_address\<T\>(cap: \&mut DenyCap\<T\>, ctx: \&mut TxContext) {}  
}

### **1.10 Time Incentivization Pattern \- Clock Parameter**

module test::vesting {  
    use sui::clock::{Self, Clock};  
    struct VestingWallet has key { id: UID, unlock\_time: u64, balance: u64 }  
    public entry fun claim(wallet: \&mut VestingWallet, clock: \&Clock, ctx: \&mut TxContext) {  
        let current\_time \= clock::timestamp\_ms(clock);  
        assert\!(current\_time \>= wallet.unlock\_time, 0);  
    }  
}

### **1.11 Time Incentivization Pattern \- Temporal Check**

module test::timelock {  
    use sui::clock::{Self, Clock};  
    struct TimeLock has key { id: UID, release\_time: u64 }  
    public entry fun unlock(lock: \&TimeLock, clock: \&Clock, ctx: \&mut TxContext) {  
        assert\!(clock::timestamp\_ms(clock) \>= lock.release\_time, 0);  
    }  
}

### **1.12 Escapability Pattern \- UpgradeCap**

module test::upgrade {  
    struct UpgradeCap has key, store { id: UID }  
    public entry fun authorize\_upgrade(cap: \&UpgradeCap, ctx: \&mut TxContext) {}  
}

### **1.13 Escapability Pattern \- MigrationCap**

module test::migration {  
    struct MigrationCap has key, store { id: UID }  
    public entry fun migrate\_state(\_cap: \&MigrationCap, ctx: \&mut TxContext) {}  
}

### **1.14 Multiple Patterns in Contract**

module test::multi {  
    use sui::clock::{Self, Clock};  
    struct AdminCap has key, store { id: UID }  
    struct PauseCap has key, store { id: UID }  
    struct UpgradeCap has key, store { id: UID }  
    struct Protocol has key { id: UID, paused: bool, upgrade\_delay: u64 }  
    public entry fun pause(\_cap: \&PauseCap, protocol: \&mut Protocol, ctx: \&mut TxContext) { protocol.paused \= true; }  
    public entry fun admin\_upgrade(\_admin: \&AdminCap, \_upgrade: \&UpgradeCap, protocol: \&mut Protocol, clock: \&Clock, ctx: \&mut TxContext) {  
        assert\!(\!protocol.paused, 0);  
        let current\_time \= clock::timestamp\_ms(clock);  
        assert\!(current\_time \>= protocol.upgrade\_delay, 0);  
    }  
}

## **2\. HEURISTIC CLASSIFICATION TESTS (12 tests)**

### **2.1 Privileged: admin\_set\_config**

module test::admin {  
    use sui::balance::{Self, Balance};  
    use sui::sui::SUI;  
    struct Config has key, store { id: UID, val: u64, reserve: Balance\<SUI\> }  
    public fun admin\_set\_config(config: \&mut Config) { config.val \= 1; }  
}

### **2.2 Privileged: owner\_withdraw**

module test::owner {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    use sui::transfer;  
    struct Vault has key, store { id: UID, balance: Balance\<SUI\>, owner: address }  
    public fun owner\_withdraw(vault: \&mut Vault, amount: u64, ctx: \&mut TxContext) {  
        let coin \= coin::take(\&mut vault.balance, amount, ctx);  
        transfer::public\_transfer(coin, vault.owner);  
    }  
}

### **2.3 Privileged: drain\_funds**

module test::drain {  
    use sui::balance::{Self, Balance};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, balance: Balance\<SUI\> }  
    public fun drain\_funds(pool: \&mut Pool) { let \_ \= balance::split(\&mut pool.balance, 100); }  
}

### **2.4 Privileged: pause\_protocol**

module test::pause {  
    use sui::balance::{Self, Balance};  
    use sui::sui::SUI;  
    struct Proto has key, store { id: UID, paused: bool, reserve: Balance\<SUI\> }  
    public fun pause\_protocol(proto: \&mut Proto) { proto.paused \= true; }  
}

### **2.5 Privileged: upgrade\_contract**

module test::upgrade {  
    struct Config has key, store { id: UID, version: u64 }  
    public fun upgrade\_contract(config: \&mut Config) { config.version \= config.version \+ 1; }  
}

### **2.6 Privileged: admin\_drain\_swap (Priority Override)**

module test::exploit {  
    use sui::balance::{Self, Balance};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, balance: Balance\<SUI\> }  
    public fun admin\_drain\_swap(pool: \&mut Pool) { let \_ \= balance::split(\&mut pool.balance, 100); }  
}

### **2.7 Public: swap\_x\_to\_y**

module test::dex {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, rx: Balance\<SUI\>, ry: Balance\<SUI\> }  
    public fun swap\_x\_to\_y(pool: \&mut Pool, coin\_in: Coin\<SUI\>, ctx: \&mut TxContext): Coin\<SUI\> {  
        balance::join(\&mut pool.rx, coin::into\_balance(coin\_in));  
        coin::take(\&mut pool.ry, 100, ctx)  
    }  
}

### **2.8 Public: stake\_tokens**

module test::staking {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, staked: Balance\<SUI\> }  
    public fun stake\_tokens(pool: \&mut Pool, tokens: Coin\<SUI\>) {  
        balance::join(\&mut pool.staked, coin::into\_balance(tokens));  
    }  
}

### **2.9 Public: claim\_rewards**

module test::rewards {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, rewards: Balance\<SUI\> }  
    public fun claim\_rewards(pool: \&mut Pool, ctx: \&mut TxContext): Coin\<SUI\> {  
        coin::take(\&mut pool.rewards, 100, ctx)  
    }  
}

### **2.10 Public: deposit\_funds**

module test::vault {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Vault has key, store { id: UID, balance: Balance\<SUI\> }  
    public fun deposit\_funds(vault: \&mut Vault, coin: Coin\<SUI\>) {  
        balance::join(\&mut vault.balance, coin::into\_balance(coin));  
    }  
}

### **2.11 Public: new\_pool**

module test::factory {  
    struct Pool has key { id: UID, val: u64 }  
    public fun new\_pool(ctx: \&mut TxContext): Pool { Pool { id: object::new(ctx), val: 0 } }  
}

### **2.12 Public: get\_balance**

module test::query {  
    struct Vault has key { id: UID, amount: u64 }  
    public fun get\_balance(vault: \&Vault): u64 { vault.amount }  
}

## **3\. REGEX COVERAGE TESTS (5 tests)**

### **3.1 Capability Detection with Whitespace**

module test::whitespace {  
    struct   AdminCap   has   key , store   { id  :  UID }  
    public   entry   fun   admin\_function  ( \_cap :  &  AdminCap  , ctx  :  \&mut  TxContext )   {}  
}

### **3.2 Clock Detection with Various Formats**

module test::clock\_formats {  
    use sui::clock::{Self, Clock};  
    public fun test1(clock:\&Clock, ctx: \&mut TxContext) {}  
    public fun test2(clock: & Clock, ctx: \&mut TxContext) {}  
    public fun test3(clock :\&Clock, ctx: \&mut TxContext) {}  
}

### **3.3 Generic Capability Names**

module test::generic\_caps {  
    struct PublisherCap has key { id: UID }  
    struct ManagerCap has key { id: UID }  
}

### **3.4 Multiple Capabilities in Same Function**

module test::multi\_cap {  
struct AdminCap has key { id: UID }  
struct OwnerCap has key { id: UID }  
public entry fun dual\_auth(\_admin: \&AdminCap, \_owner: \&OwnerCap, ctx: \&mut TxContext) {}  
}

### **3.5 Nested Generic Types**

module test::nested {  
    use std::option::Option;  
    struct AdminCap has key { id: UID }  
    public fun complex\_param(cap: Option\<\&AdminCap\>, ctx: \&mut TxContext) {}  
}

## **4\. FALSE POSITIVE/NEGATIVE TESTS (6 tests)**

### **4.1 No False Positive: swap**

module test::dex {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Pool has key { id: UID, r: Balance\<SUI\> }  
    public fun swap(pool: \&mut Pool, c: Coin\<SUI\>, ctx: \&mut TxContext): Coin\<SUI\> {  
        balance::join(\&mut pool.r, coin::into\_balance(c));  
        coin::take(\&mut pool.r, 100, ctx)  
    }  
}

### **4.2 No False Positive: add\_liquidity**

module test::liquidity {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    struct Pool has key { id: UID, r: Balance\<SUI\> }  
    public fun add\_liquidity(pool: \&mut Pool, c: Coin\<SUI\>) {  
        balance::join(\&mut pool.r, coin::into\_balance(c));  
    }  
}

### **4.3 No False Positive: create\_pool**

module test::factory {  
    struct Pool has key { id: UID, val: u64 }  
    public fun create\_pool(ctx: \&mut TxContext): Pool { Pool { id: object::new(ctx), val: 0 } }  
}

### **4.4 No False Positive: claim with Inline Authorization**

module test::rewards {  
    struct RewardPool has key { id: UID, owner: address }  
    public fun claim(pool: \&mut RewardPool, ctx: \&mut TxContext) {  
        let sender \= tx\_context::sender(ctx);  
        assert\!(pool.owner \== sender, 0);  
    }  
}

### **4.5 No False Negative: admin\_drain\_swap**

module test::exploit {  
    use sui::balance::{Self, Balance};  
    use sui::sui::SUI;  
    struct Pool has key, store { id: UID, balance: Balance\<SUI\> }  
    public fun admin\_drain\_swap(pool: \&mut Pool) { let \_ \= balance::split(\&mut pool.balance, 100); }  
}

### **4.6 No False Negative: emergency\_withdraw**

module test::emergency {  
    use sui::balance::{Self, Balance};  
    use sui::coin::{Self, Coin};  
    use sui::sui::SUI;  
    use sui::transfer;  
    struct Vault has key, store { id: UID, balance: Balance\<SUI\>, admin: address }  
    public fun emergency\_withdraw(vault: \&mut Vault, amount: u64, ctx: \&mut TxContext) {  
        let coin \= coin::take(\&mut vault.balance, amount, ctx);  
        transfer::public\_transfer(coin, vault.admin);  
    }  
}

## **5\. INTEGRATION TESTS (5 tests)**

### **5.1 Complete DeFi Protocol**

module test::defi {  
    use sui::clock::{Self, Clock};  
    struct AdminCap has key, store { id: UID }  
    struct PauseCap has key, store { id: UID }  
    struct UpgradeCap has key, store { id: UID }  
    struct Pool has key { id: UID, reserve\_x: u64, reserve\_y: u64, fee: u64, paused: bool }  
    public fun swap(pool: \&mut Pool, amount: u64, ctx: \&mut TxContext) { assert\!(\!pool.paused, 0); }  
    public fun set\_fee(\_admin: \&AdminCap, pool: \&mut Pool, new\_fee: u64) { pool.fee \= new\_fee; }  
    public fun pause(\_cap: \&PauseCap, pool: \&mut Pool) { pool.paused \= true; }  
    public fun upgrade(\_admin: \&AdminCap, \_upgrade: \&UpgradeCap, clock: \&Clock, ctx: \&mut TxContext) {  
        let \_ \= clock::timestamp\_ms(clock);  
    }  
}

### **5.2 DCR Graph Generation**

module test::graphs {  
    use sui::clock::{Self, Clock};  
    struct AdminCap has key, store { id: UID }  
    struct PauseCap has key, store { id: UID }  
    struct UpgradeCap has key, store { id: UID }  
    struct Protocol has key { id: UID, paused: bool, upgrade\_delay: u64 }  
    public fun pause(\_cap: \&PauseCap, protocol: \&mut Protocol) { protocol.paused \= true; }  
    public fun unpause(\_cap: \&PauseCap, protocol: \&mut Protocol) { protocol.paused \= false; }  
    public fun admin\_upgrade(\_admin: \&AdminCap, \_upgrade: \&UpgradeCap, protocol: \&Protocol, clock: \&Clock) {  
        assert\!(\!protocol.paused, 0);  
        let \_ \= clock::timestamp\_ms(clock);  
    }  
}

### **5.3 RDF Ontology Population**

module test::ontology {  
    struct AdminCap has key, store { id: UID }  
    public entry fun privileged\_operation(\_admin: \&AdminCap, ctx: \&mut TxContext) {}  
}

### **5.4 Full Pipeline: Vulnerability → Fix → Pattern Linkage**

module test::pipeline {  
    use sui::clock::{Self, Clock};  
    struct AdminCap has key, store { id: UID }  
    struct Vault has key { id: UID, paused: bool }  
    public fun deposit(\_admin: \&AdminCap, vault: \&mut Vault) {}  
    public fun timed\_claim(vault: \&mut Vault, clock: \&Clock, ctx: \&mut TxContext) {  
        assert\!(\!vault.paused, 0);  
        let \_ \= clock::timestamp\_ms(clock);  
    }  
}

### **5.5 Cross-Category: AUTH \+ CONS in Same Contract**

module test::cross {  
use sui::balance::{Self, Balance};  
use sui::coin::{Self, Coin};  
use sui::sui::SUI;  
struct Pool has key, store { id: UID, rx: Balance, ry: Balance, fee: u64 }  
public fun admin\_set\_fee(pool: \&mut Pool) { pool.fee \= 100; }  
public fun swap(pool: \&mut Pool, c: Coin, ctx: \&mut TxContext): Coin {  
balance::join(\&mut pool.rx, coin::into\_balance(c));  
coin::take(\&mut pool.ry, 100, ctx)  
}  
}  
