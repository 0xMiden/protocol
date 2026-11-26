mod allowlist;
mod authority;
mod blocklist;
mod code_inspection;
mod constant_fee_manager;
mod constant_fee_policy_config;
mod credit_issuance;
mod encrypted_assets_policy;
mod expiration;
mod faucet;
mod faucet_factory;
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
mod schema_commitment;
mod send_note;
mod supply_restriction;
mod swap;
pub(crate) mod transfer_policy;
mod tx_fee;

use anyhow::Context;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountBuilder,
    AccountComponent,
    AccountProcedureRoot,
    AccountType,
    StorageSlot,
};
use miden_protocol::asset::AssetAmount;
use miden_protocol::transaction::ExecutedTransaction;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::utils::DEFAULT_EXPIRATION_BLOCK_DELTA;

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

/// Returns a fungible faucet component with token symbol `SYM`, 8 decimals and a maximum supply
/// of 1_000_000.
fn fungible_faucet() -> anyhow::Result<FungibleFaucet> {
    Ok(FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?)
}

/// Returns a builder for a public account with a [`fungible_faucet`], whose ID is derived from
/// `[seed; 32]`. Callers add the authority, the token policy manager and any other components.
fn fungible_faucet_account(seed: u8) -> anyhow::Result<AccountBuilder> {
    Ok(AccountBuilder::new([seed; 32])
        .account_type(AccountType::Public)
        .with_component(fungible_faucet()?))
}

/// Compiles `code` into a component named `name` with `storage_slots`, and returns the root of
/// its `procedure` together with the component.
fn policy_component(
    name: &str,
    procedure: &str,
    storage_slots: Vec<StorageSlot>,
    code: impl ToString,
) -> anyhow::Result<(AccountProcedureRoot, AccountComponent)> {
    let code = CodeBuilder::default().compile_component_code(name, code)?;
    let component =
        AccountComponent::new(code, storage_slots, AccountComponentMetadata::mock(name))?;
    let root = component
        .get_procedure_root_by_path(format!("{name}::{procedure}").as_str())
        .with_context(|| format!("{name} should export {procedure}"))?;

    Ok((root, component))
}
