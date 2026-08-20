mod allowlist;
mod authority;
mod blocklist;
mod code_inspection;
mod constant_fee_manager;
mod constant_fee_policy_config;
mod expiration;
mod faucet;
mod faucet_metadata;
mod faucet_policy_config;
mod fee_collection;
mod fee_manager;
mod fee_sponsorship;
mod min_burn_amount_config;
mod non_fungible_faucet;
mod ownable2step;
mod p2id;
mod p2ide;
mod pausable;
mod pswap;
pub(crate) mod rbac;
mod send_note;
mod swap;
pub(crate) mod transfer_policy;
mod tx_fee;

use miden_protocol::transaction::ExecutedTransaction;

const DEFAULT_EXPIRATION_BLOCK_DELTA: u32 = 20;

/// Asserts that the transaction's expiration was limited to the default expiration block delta
/// applied by standard procedures that read mutable account state.
#[track_caller]
fn assert_default_expiration_limit(executed: &ExecutedTransaction) {
    assert_eq!(
        executed.expiration_block_num(),
        executed.block_header().block_num() + DEFAULT_EXPIRATION_BLOCK_DELTA,
        "the procedure should enforce the default expiration limit",
    );
}
