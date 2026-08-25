//! Tests for the canonical pass-through transaction scripts, one module per shape of output the
//! assets are forwarded into.

use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::pass_through::PassThrough;
use miden_standards::account::wallets::BasicWallet;

mod single_p2id;

/// Builds the stateless account a pass-through transaction runs on: `NoAuth` so the nonce is only
/// bumped when the account state actually changes, `BasicWallet` so input notes can deposit into
/// it, and `PassThrough` for the account procedures the scripts call.
fn pass_through_account() -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([42; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_component(PassThrough)
        .account_type(AccountType::Public)
        .build_existing()?)
}
