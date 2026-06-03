// ============================================================================
// SUWC-RES Category Vulnerable Contract
// Demonstrates ALL 3 Resource Management defects:
//   SUWC-RES-01: Hot Potato Drop (2 structs with drop ability)
//   SUWC-RES-02: Object Locking / Roach Motel (2 wrappers without unwrap)
//   SUWC-RES-03: Permanent Locking (1 transfer to @0x0)
//
// Purpose: Validate analyzer coverage of the entire RES category.
// Design: All function names use public DeFi conventions (wrap, burn, get,
//         deposit, create) to isolate RES findings from AUTH contamination.
// ============================================================================

module vulnerable_suwc::res_asset_manager {

    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;

    const E_INSUFFICIENT: u64 = 1;

    // RES-01: Hot potato Receipt with drop ability (should NOT have drop)
    public struct FlashLoanReceipt has drop {
        pool_id: ID,
        amount: u64,
    }

    // RES-01: Hot potato Proof with drop ability (should NOT have drop)
    public struct SwapProof has drop {
        amount_in: u64,
        amount_out: u64,
    }

    // RES-02: Wrapper struct — no unwrap/extract/take function exists
    public struct AssetWrapper has key, store {
        id: UID,
        inner_balance: Balance<SUI>,
        metadata: vector<u8>,
    }

    // RES-02: Container struct — no unwrap/extract/take function exists
    public struct TokenContainer has key, store {
        id: UID,
        tokens: Balance<SUI>,
        locked: bool,
    }

    public struct Pool has key, store {
        id: UID,
        reserves: Balance<SUI>,
    }

    // Issues flash loan receipt (RES-01: receipt has drop, can be silently discarded)
    public fun get_flash_loan(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext,
    ): (Coin<SUI>, FlashLoanReceipt) {
        let coin = coin::take(&mut pool.reserves, amount, ctx);
        let receipt = FlashLoanReceipt {
            pool_id: object::id(pool).to_inner(),
            amount,
        };
        (coin, receipt)
    }

    // Repay flash loan — should be forced by hot potato, but receipt has drop
    public fun deposit_repayment(
        pool: &mut Pool,
        coin: Coin<SUI>,
        receipt: FlashLoanReceipt,
    ) {
        let FlashLoanReceipt { pool_id: _, amount: _ } = receipt;
        balance::join(&mut pool.reserves, coin::into_balance(coin));
    }

    // Creates swap proof (RES-01: proof has drop, can be silently discarded)
    public fun create_swap_proof(amount_in: u64, amount_out: u64): SwapProof {
        SwapProof { amount_in, amount_out }
    }

    // Wrap assets into wrapper — no corresponding unwrap (RES-02: Roach Motel)
    public fun wrap_assets(
        coin: Coin<SUI>,
        metadata: vector<u8>,
        ctx: &mut TxContext,
    ): AssetWrapper {
        AssetWrapper {
            id: object::new(ctx),
            inner_balance: coin::into_balance(coin),
            metadata,
        }
    }

    // Store tokens in container — no extraction possible (RES-02: Roach Motel)
    public fun wrap_tokens(
        coin: Coin<SUI>,
        ctx: &mut TxContext,
    ): TokenContainer {
        TokenContainer {
            id: object::new(ctx),
            tokens: coin::into_balance(coin),
            locked: true,
        }
    }

    // RES-03: Transfer to burn address @0x0 — permanent asset lock
    public fun burn_to_null(object: Pool) {
        transfer::public_transfer(object, @0x0);
    }

    // Public deposit — should NOT trigger AUTH-01
    public fun deposit(
        pool: &mut Pool,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut pool.reserves, coin::into_balance(coin));
    }
}
