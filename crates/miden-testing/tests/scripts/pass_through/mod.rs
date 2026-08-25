//! Tests for the canonical pass-through transaction scripts, one module per shape of output the
//! assets are forwarded into.

use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_standards::account::auth::AuthPassThrough;
use miden_standards::account::pass_through::PassThroughSweep;
use miden_standards::account::wallets::BasicWallet;

mod single_p2id;

/// Builds the stateless account a pass-through transaction runs on: `AuthPassThrough` so any
/// change to the account fails the transaction, `BasicWallet` so input notes can deposit into it,
/// and `PassThroughSweep` for the account procedure the scripts call.
pub(crate) fn pass_through_account() -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([42; 32])
        .with_component(AuthPassThrough)
        .with_component(BasicWallet)
        .with_component(PassThroughSweep)
        .account_type(AccountType::Public)
        .build_existing()?)
}
