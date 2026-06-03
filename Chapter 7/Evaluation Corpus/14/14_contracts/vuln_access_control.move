// vuln_access_control.move
// ============================================================================
// VULNERABLE CONTRACT 1: Access Control Vulnerabilities
// Demonstrates: SUWC-AUTH-01, SUWC-AUTH-02, SUWC-AUTH-03, SUWC-AUTH-04
// Pattern: AccessControlPattern (absence / misuse)
// ============================================================================

module vulnerable::token_sale;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::transfer;

const E_NOT_ENOUGH: u64 = 1;

// AUTH-02: Capability with dangerous abilities (store + copy = leakable)
public struct SaleCap has key, store, copy {
    id: UID,
    sale_id: ID,
}

public struct TokenSale has key, store {
    id: UID,
    price: u64,
    balance: Balance<SUI>,
    is_active: bool,
    total_sold: u64,
    // FIX: Added owner address field so emergency_withdraw can drain
    //      to a stored address rather than returning Coin<SUI>.
    //      This is also realistic: a token sale contract typically records
    //      the deployer's address for fund collection.
    owner: address,
}

// AUTH-03: One-Time-Witness passed by reference (should be by value)
fun init(witness: &TOKEN_SALE, ctx: &mut TxContext) {
    let sale = TokenSale {
        id: object::new(ctx),
        price: 1000,
        balance: balance::zero(),
        is_active: true,
        total_sold: 0,
        // FIX: Record deployer as owner at init time
        owner: tx_context::sender(ctx),
    };
    transfer::share_object(sale);
}

// AUTH-01: Privileged function modifies state WITHOUT capability check
// Anyone can call this to change the token price
public fun set_price(
    sale: &mut TokenSale,
    new_price: u64,
) {
    // BUG: No SaleCap required! Anyone can change the price.
    sale.price = new_price;
}

// AUTH-01 + AUTH-04: Privileged — drains sale balance without capability

public fun withdraw_funds(
    sale: &mut TokenSale,
    amount: u64,
    ctx: &mut TxContext,
) {
    // BUG: No admin capability check — anyone can drain the sale!
    assert!(sale.balance.value() >= amount, E_NOT_ENOUGH);
    let coin = coin::take(&mut sale.balance, amount, ctx);
    // Sends to stored owner address, not tx_context::sender.
    // This makes the outflow unambiguous: it is NOT a user withdrawal.
    transfer::public_transfer(coin, sale.owner);
}

// AUTH-01: Another privileged function without capability
public fun toggle_sale(
    sale: &mut TokenSale,
) {
    // BUG: Anyone can enable/disable the sale
    sale.is_active = !sale.is_active;
}

// This function is OK (not privileged - just a purchase)
public fun buy_token(
    sale: &mut TokenSale,
    payment: Coin<SUI>,
) {
    let amount = coin::value(&payment);
    assert!(amount >= sale.price, E_NOT_ENOUGH);
    balance::join(&mut sale.balance, coin::into_balance(payment));
    sale.total_sold = sale.total_sold + 1;
}