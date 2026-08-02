//! Every `miden-standards` config note is bound to its target account via a
//! `NetworkAccountTarget` attachment (see #3455). A decoy with the real target's manager/owner
//! setup passes sender-based authorization, so only the target-account check stops it. This
//! replaces the near-identical "decoy cannot consume a note meant for another target" test that
//! used to be copy-pasted per config-note family (#3459): each family contributes only a
//! `decoy_scenario` arrange function, registered below via `#[case::name(...)]`.
//!
//! Covers `miden-standards` config notes only. `agglayer::pause` and `B2AggNote` have their own
//! equivalent tests, left standalone due to a different shape (extra post-conditions / heavier
//! bridge setup); `ConfigAggBridgeNote`, `DeregisterAggFaucetNote`, `RemoveGerNote`,
//! `UpdateGerNote`, and `ClaimNote` each define a target-mismatch guard with no Rust test yet.

use miden_protocol::account::{Account, AccountId};
use miden_protocol::errors::MasmError;
use miden_protocol::note::Note;
use miden_testing::{MockChain, assert_transaction_executor_error};
use rstest::rstest;

use crate::{auth, scripts};

/// A decoy-consumption scenario: the decoy account, the chain it lives in, the note, the account
/// it's actually bound to (must differ from `decoy`), and the error its guard should raise.
pub(crate) struct DecoyScenario {
    pub(crate) decoy: AccountId,
    pub(crate) mock_chain: MockChain,
    pub(crate) note: Note,
    pub(crate) target: AccountId,
    pub(crate) expected_error: MasmError,
}

type BuildDecoyScenario = fn() -> anyhow::Result<DecoyScenario>;

/// Commits `decoy` to a fresh chain, returning its ID alongside the chain. `decoy` must be a
/// `build_existing()` account - `MockChainBuilder::build` panics on a newly-seeded one.
pub(crate) fn chain_with_decoy(decoy: Account) -> anyhow::Result<(AccountId, MockChain)> {
    let decoy_id = decoy.id();
    let mut builder = MockChain::builder();
    builder.add_account(decoy)?;
    Ok((decoy_id, builder.build()?))
}

#[rstest]
#[case::pausable(scripts::pausable::config::decoy_scenario)]
#[case::ownable2step(scripts::ownable2step::config::decoy_scenario)]
#[case::rbac(scripts::rbac::config::decoy_scenario)]
#[case::allowlist(scripts::allowlist::config::decoy_scenario)]
#[case::blocklist(scripts::blocklist::config::decoy_scenario)]
#[case::faucet_policy(scripts::faucet_policy_config::decoy_scenario)]
#[case::faucet_metadata(scripts::faucet_metadata::config::decoy_scenario)]
#[case::network_account(auth::network_account::decoy_scenario)]
#[case::constant_fee_policy(scripts::constant_fee_policy_config::decoy_scenario)]
#[tokio::test]
async fn decoy_account_cannot_consume_note_of_another_target(
    #[case] build_scenario: BuildDecoyScenario,
) -> anyhow::Result<()> {
    let scenario = build_scenario()?;
    assert_ne!(scenario.decoy, scenario.target, "the decoy is the note's target - vacuous");

    let result = scenario
        .mock_chain
        .build_transaction(scenario.decoy)
        .unauthenticated_input_note(scenario.note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, scenario.expected_error);
    Ok(())
}
