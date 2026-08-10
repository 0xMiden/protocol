//! Shared scaffolding for the price oracle tests.
//!
//! No mock oracle is hand-written in MASM: the tests deploy the shipped [`PriceOracle`] and
//! [`PriceFeed`] components and seed their storage, so what is exercised is the real code rather
//! than a stand-in that can drift from it.

use miden_protocol::Word;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3,
};
use miden_standards::account::access::Authority;
use miden_standards::account::oracle::{PriceEntry, PriceFeed, PriceOracle, QuoteId};
use miden_standards::account::wallets::BasicWallet;
use miden_testing::Auth;

/// The asset the tests convert from.
pub fn source_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)
}

/// The asset the tests convert to.
pub fn target_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2)?)
}

/// A faucet the feed publishes no price for.
pub fn unpriced_faucet() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_3)?)
}

/// The quote unit the test feed publishes in. It cancels out of every rate, so it never reaches the
/// oracle interface; it is fixed here only to keep the feed internally consistent.
pub fn usd() -> anyhow::Result<QuoteId> {
    Ok(QuoteId::from_symbol("USD")?)
}

/// Returns the asset id word of a fungible asset issued by the given faucet.
pub fn asset_id_of(faucet_id: AccountId) -> anyhow::Result<Word> {
    Ok(FungibleAsset::new(faucet_id, 1)?.id().into())
}

/// Builds an oracle account: a feed publishing the given prices, wired as the implementation behind
/// the stable oracle wrapper.
pub fn oracle_account(prices: &[(AccountId, PriceEntry)]) -> anyhow::Result<Account> {
    let mut feed = PriceFeed::new(usd()?);
    for (faucet_id, entry) in prices {
        feed = feed.with_price(*faucet_id, *entry);
    }

    Ok(AccountBuilder::new([31; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(Authority::AuthControlled)
        .with_component(feed)
        .with_component(
            PriceOracle::new().with_implementation(PriceFeed::compute_conversion_rate_root()),
        )
        .build_existing()?)
}

/// Builds a consumer account that reaches the oracle through a transaction script.
pub fn consumer_account(seed: [u8; 32]) -> anyhow::Result<Account> {
    Ok(AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?)
}
