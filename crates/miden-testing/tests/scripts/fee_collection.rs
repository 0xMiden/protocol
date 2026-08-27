use alloc::sync::Arc;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use anyhow::Context;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::note::{Note, NoteAssets, NoteId, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::{RawOutputNote, RawOutputNotes, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::{AuthNetworkAccount, NetworkAccount, SponsorshipPolicy};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicy, FeePolicyManager};
use miden_standards::account::note_creator::NoteCreator;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_EXPECTED_FEE_ASSET_MISMATCH,
    ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED,
    ERR_FEE_MANAGER_SPONSORED_NOTE_NOT_FOUND,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET,
    ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH,
    ERR_FEE_POLICY_FEE_ASSET_MISMATCH,
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
    ERR_NETWORK_ACCOUNT_FEE_ASSET_NOT_NATIVE,
    ERR_NETWORK_ACCOUNT_SPONSORED_FEES_EXCEED_COLLECTED,
    ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{
    FeeSponsorshipNote,
    FeeSponsorshipNoteStorage,
    NetworkAccountTarget,
    P2idNote,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockTransaction, assert_transaction_executor_error};
use rand::SeedableRng;
use rand::rngs::Xoshiro256PlusPlus;
use rand::seq::SliceRandom;
use rstest::rstest;

use crate::scripts::fee_manager::{
    FEE_AMOUNT,
    build_fee_account_with_switching,
    create_fee_manager_note_script,
    custom_fee_amount_for,
    custom_fee_policy,
    fee_faucet_id,
};

// COLLECT SPONSORED FEES
// ================================================================================================

/// Returns a fungible asset of `amount` units issued by the fee faucet (the asset the fee policy
/// manager accepts fees in).
fn fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(fee_faucet_id()?, amount)?.into())
}

/// Returns a fungible asset of `amount` units issued by a faucet other than the fee faucet.
fn other_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(
        FungibleAsset::new(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?, amount)?
            .into(),
    )
}

/// The faucet issuing the chain's native fee asset, which the auth procedure's `pay_fee` funds
/// network-note sponsorships in (via `tx::get_fee_asset_id`, not the account's configured asset).
fn native_fee_faucet_id() -> anyhow::Result<AccountId> {
    Ok(ACCOUNT_ID_FEE_FAUCET.try_into()?)
}

/// Returns a fungible asset of `amount` units of the native fee asset.
fn native_fee_asset(amount: u64) -> anyhow::Result<Asset> {
    Ok(FungibleAsset::new(native_fee_faucet_id()?, amount)?.into())
}

// In a real deployment `collect_sponsored_fees` runs inside the `AuthNetworkAccount` auth
// procedure, always priced in the fee manager's configured asset. This test-only component exposes
// a variant that deliberately passes a wrong expected fee asset, letting
// `collect_rejects_expected_fee_asset_mismatch` exercise the mismatch guard - a case the auth flow
// cannot reach.
const FEE_COLLECTOR_NAME: &str = "test::fee_collector";

static FEE_COLLECTOR_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let src = r#"
        use miden::standards::fees

        @account_procedure
        pub proc collect_sponsored_fees_wrong_asset
            # pass an expected fee asset that differs from the manager's configured fee asset
            push.1.2.3.4
            # => [WRONG_FEE_ASSET_ID, pad(16)]

            exec.fees::collect_sponsored_fees drop
            # => [pad(16)]
        end
        "#;
    CodeBuilder::default()
        .compile_component_code(FEE_COLLECTOR_NAME, src)
        .expect("fee collector component should compile")
});

/// The test-only account component exposing the wrong-asset `collect_sponsored_fees` variant.
fn fee_collector_component() -> anyhow::Result<AccountComponent> {
    Ok(AccountComponent::new(
        FEE_COLLECTOR_CODE.clone(),
        vec![],
        AccountComponentMetadata::mock(FEE_COLLECTOR_NAME),
    )?)
}

/// Builds a network account with a `BasicWallet` and a `FeePolicyManager`. When `fee_entry` is
/// provided, the fee policy manager schedules the given fee for that note script root;
/// `allowed_note_roots` seeds the note-script allowlist (the FEE_SPONSORSHIP root is added by
/// [`NetworkAccount::builder`]).
fn network_account(
    fee_entry: Option<(NoteScriptRoot, AssetAmount)>,
    allowed_note_roots: BTreeSet<NoteScriptRoot>,
) -> anyhow::Result<Account> {
    let mut policy = BasicConstantFeePolicy::new();
    if let Some((root, fee)) = fee_entry {
        policy = policy.with_fee(root, fee);
    }
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(policy.into())
        .build();

    Ok(NetworkAccount::builder([7; 32], allowed_note_roots, fee_policy_manager)?
        .with_component(BasicWallet)
        .build_existing()?)
}

/// A network account plus the feature notes it can consume and the FEE_SPONSORSHIP notes bound to
/// them.
struct Test {
    mock_chain: MockChain,
    network_account: Account,
    feature_notes: Vec<Note>,
    sponsorship_notes: Vec<Note>,
}

#[bon::bon]
impl Test {
    /// Builds a network account together with its feature notes and their FEE_SPONSORSHIP notes.
    ///
    /// The feature notes are P2ANY notes without assets, so they all share one script root. The
    /// account allowlists that root, which lets it consume every feature note.
    ///
    /// Use [`TestBuilder::sponsorship`] to add the FEE_SPONSORSHIP notes.
    #[builder]
    fn new(
        #[builder(field)] sponsorships: Vec<(usize, Asset)>,
        /// Fee the fee schedule charges for each feature note. Without this fee the feature note
        /// script root stays unscheduled.
        feature_note_fee: Option<AssetAmount>,
        /// Number of feature notes to create. Defaults to 1.
        #[builder(default = 1)]
        num_feature_notes: usize,
    ) -> anyhow::Result<Self> {
        let mut rng = RandomCoin::new(Word::empty());
        let mut builder = MockChain::builder();
        let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

        let feature_notes: Vec<Note> = (0..num_feature_notes)
            .map(|_| builder.add_p2any_note(sponsor.id(), NoteType::Public, []))
            .collect::<anyhow::Result<_>>()?;
        let num_unique_notes = feature_notes.iter().map(Note::id).collect::<BTreeSet<_>>().len();
        assert_eq!(feature_notes.len(), num_unique_notes, "feature notes should be unique");

        // All feature notes share one script root, so one schedule entry prices all of them.
        let mut allowed_note_roots = BTreeSet::new();
        let mut fee_entry = None;
        if let Some(feature_note) = feature_notes.first() {
            allowed_note_roots.insert(feature_note.script().root());
            fee_entry = feature_note_fee.map(|fee| (feature_note.script().root(), fee));
        }

        let network_account = network_account(fee_entry, allowed_note_roots)?;
        builder.add_account(network_account.clone())?;

        // The sponsorship notes target the network account, so they can only be built once it
        // exists.
        let mut sponsorship_notes = Vec::new();
        for (feature_note_idx, asset) in sponsorships {
            let feature_note = feature_notes.get(feature_note_idx).with_context(|| {
                format!("sponsorship should name an existing feature note, got {feature_note_idx}")
            })?;
            let note = Note::from(
                FeeSponsorshipNote::builder()
                    .sender(sponsor.id())
                    .target_account(network_account.id())
                    .feature_note_id(feature_note.id())
                    .asset(asset)
                    .generate_serial_number(&mut rng)
                    .build()?,
            );
            builder.add_output_note(RawOutputNote::Full(note.clone()));
            sponsorship_notes.push(note);
        }

        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        Ok(Test {
            mock_chain,
            network_account,
            feature_notes,
            sponsorship_notes,
        })
    }
}

impl<S: test_builder::State> TestBuilder<S> {
    /// Adds a FEE_SPONSORSHIP note that carries `asset` and pays for the feature note at
    /// `feature_note_idx`. More than one sponsorship note can pay for the same feature note.
    ///
    /// The notes keep the order in which they were added.
    fn sponsorship(mut self, feature_note_idx: usize, asset: Asset) -> Self {
        self.sponsorships.push((feature_note_idx, asset));
        self
    }
}

/// Consumes the given input notes against the network account - triggering the auth procedure's
/// fee collection - and returns the account's fee-asset balance after the transaction.
async fn collect_fee_balance(
    mock_chain: MockChain,
    mut network_account: Account,
    input_notes: &[NoteId],
) -> anyhow::Result<u64> {
    let mut builder = mock_chain.build_transaction(network_account.id());
    for note_id in input_notes {
        builder = builder.authenticated_input_note(*note_id);
    }
    let executed = builder.build()?.execute().await?;

    network_account.apply_patch(executed.account_patch())?;
    Ok(network_account
        .vault()
        .get_balance(AssetId::new_fungible(fee_faucet_id()?))?
        .as_u64())
}

/// A feature note bound to a sponsorship note that covers its fee is collected: the aggregated fee
/// equals the sponsored amount, whether the sponsorship covers the fee exactly or with a surplus -
/// including for a 0-priced feature note, which owes nothing yet still has its sponsorship
/// collected - and regardless of whether the sponsorship is consumed before or after the note it
/// pays for.
#[rstest]
#[tokio::test]
async fn collects_sponsored_fee_for_a_bound_pair(
    #[values(0, FEE_AMOUNT)] feature_note_fee: u64,
    #[values(FEE_AMOUNT, FEE_AMOUNT + 250)] sponsored_amount: u64,
    #[values(false, true)] sponsorship_first: bool,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(feature_note_fee)?)
        .sponsorship(0, fee_asset(sponsored_amount)?)
        .build()?;
    let input_notes = if sponsorship_first {
        [sponsorship_notes[0].id(), feature_notes[0].id()]
    } else {
        [feature_notes[0].id(), sponsorship_notes[0].id()]
    };

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance, sponsored_amount,
        "the account should collect the sponsored fee into its vault"
    );

    Ok(())
}

/// Several FEE_SPONSORSHIP notes may be bound to the same feature note, topping up its fee between
/// them. Uses three input notes, so the fee table's element count is not a multiple of the word
/// size and its zeroing has to round up.
#[rstest]
#[case::even_split(FEE_AMOUNT / 2, FEE_AMOUNT / 2)]
#[case::uneven_split(FEE_AMOUNT - 1, 1)]
#[tokio::test]
async fn multiple_sponsorships_top_up_one_feature_note(
    #[case] first_amount: u64,
    #[case] second_amount: u64,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .sponsorship(0, fee_asset(first_amount)?)
        .sponsorship(0, fee_asset(second_amount)?)
        .build()?;
    let input_notes = [feature_notes[0].id(), sponsorship_notes[0].id(), sponsorship_notes[1].id()];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance,
        first_amount + second_amount,
        "both sponsorships should be collected and together cover the feature note's fee"
    );

    Ok(())
}

/// Sponsorships are attributed to the feature note they name. Tests random orders of five input
/// notes - two feature notes and three sponsorships - through a fixed seed.
#[rstest]
#[tokio::test]
async fn sponsorships_are_attributed_by_note_id(
    #[values(0, 1, 2, 3)] seed: u8,
) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(0, fee_asset(FEE_AMOUNT)?)
        .sponsorship(1, fee_asset(FEE_AMOUNT / 2)?)
        .sponsorship(1, fee_asset(FEE_AMOUNT / 2)?)
        .build()?;

    let mut input_notes = [
        feature_notes[0].id(),
        feature_notes[1].id(),
        sponsorship_notes[0].id(),
        sponsorship_notes[1].id(),
        sponsorship_notes[2].id(),
    ];

    let mut rng = Xoshiro256PlusPlus::from_seed([seed; 32]);
    input_notes.shuffle(&mut rng);

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance,
        2 * FEE_AMOUNT,
        "both sponsorships should pay for the note they name regardless of position"
    );

    Ok(())
}

/// A surplus on one feature note does not pay for another note's fee: fees are tracked per note, so
/// an over-funded note cannot subsidize an unfunded one.
#[tokio::test]
async fn over_sponsoring_one_note_does_not_cover_another() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(0, fee_asset(2 * FEE_AMOUNT)?)
        .build()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .authenticated_input_note(feature_notes[1].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED);

    Ok(())
}

/// `collect_sponsored_fees` rejects an expected fee asset that differs from the fee policy
/// manager's configured fee asset, so a caller cannot price fees in one asset while collecting
/// sponsorship payments in another.
#[tokio::test]
async fn collect_rejects_expected_fee_asset_mismatch() -> anyhow::Result<()> {
    let account = AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager: FeePolicyManager::mock(fee_faucet_id()?),
            sponsorship_policy: SponsorshipPolicy::default(),
        })
        .with_component(BasicWallet)
        .with_component(fee_collector_component()?)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    let mock_chain = builder.build()?;

    let src = r#"
        use test::fee_collector

        @transaction_script
        pub proc main
            call.fee_collector::collect_sponsored_fees_wrong_asset
            # => [pad(16)]

            dropw dropw dropw dropw
        end
        "#;
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_package(&*FEE_COLLECTOR_CODE)?
        .compile_tx_script(src)?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_EXPECTED_FEE_ASSET_MISMATCH);

    Ok(())
}

/// The owner switches the active fee policy from the basic constant fee policy to the user-defined
/// custom policy via `set_fee_policy`. Under the network auth procedure the same transaction then
/// prices the consumed `set_fee_policy` note through the just-activated custom policy, so it must
/// be paired with a FEE_SPONSORSHIP note funded with exactly that custom fee. The transaction
/// succeeding proves the switch took effect and that the custom policy - not the basic constant fee
/// schedule - priced the note: had the switch not happened, the basic constant policy prices the
/// note at 0 and the sponsorship note would be rejected as unpaired.
#[tokio::test]
async fn set_fee_policy_switches_to_custom_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let set_policy_note_script =
        create_fee_manager_note_script("set_fee_policy", custom_fee_policy()?.root().as_word());
    let mut rng = RandomCoin::new([Felt::from(600u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    // The custom policy prices the set_fee_policy note on its (empty) storage commitment with a
    // timeframe and priority of 0 - the values fee collection passes - so the fee is known ahead of
    // time and the sponsorship can cover it exactly.
    let custom_fee =
        custom_fee_amount_for(set_policy_note.recipient().storage().commitment(), 0, 0);

    // Allowlist the set_fee_policy note; `build_fee_account_with_switching` allowlists the
    // FEE_SPONSORSHIP note that pays its fee.
    let account = build_fee_account_with_switching(
        owner_account_id,
        BTreeSet::from([set_policy_note.script().root()]),
    )?;

    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(owner_account_id)
            .target_account(account.id())
            .feature_note_id(set_policy_note.id())
            .asset(fee_asset(custom_fee.as_u64())?)
            .generate_serial_number(&mut rng)
            .build()?,
    );

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Consuming the switch note (which activates the custom policy) followed by its sponsorship
    // note succeeds only if the custom policy is active and prices the note at the sponsored
    // fee.
    mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_policy_note.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Fees from several feature/sponsorship pairs are aggregated into a single total. Uses four input
/// notes, so the fee table's element count is an exact multiple of the word size.
#[tokio::test]
async fn aggregates_fees_across_pairs() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .num_feature_notes(2)
        .sponsorship(0, fee_asset(FEE_AMOUNT)?)
        .sponsorship(1, fee_asset(FEE_AMOUNT)?)
        .build()?;
    let input_notes = [
        feature_notes[0].id(),
        sponsorship_notes[0].id(),
        feature_notes[1].id(),
        sponsorship_notes[1].id(),
    ];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance,
        2 * FEE_AMOUNT,
        "fees from both pairs should be aggregated into the account's vault"
    );

    Ok(())
}

/// `set_fee_policy` rejects policy roots outside the allowed policy roots map, even if the root
/// is a procedure of the account.
#[tokio::test]
async fn set_fee_policy_rejects_non_allowed_root() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    // The set_fee_policy note aborts inside its note script, before the auth allowlist check runs,
    // so the allowlist can stay empty.
    let account = build_fee_account_with_switching(owner_account_id, BTreeSet::new())?;

    // This root exists in the account code, but is not in the fee policy allowlist.
    let invalid_policy_root = AuthNetworkAccount::get_fee_policy_root().as_word();
    let set_policy_note_script =
        create_fee_manager_note_script("set_fee_policy", invalid_policy_root);
    let mut rng = RandomCoin::new([Felt::from(601u32); 4].into());
    let set_policy_note = NoteBuilder::new(owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_policy_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

/// A feature note whose script root has no fee schedule entry aborts fee collection: unscheduled
/// note scripts must be priced explicitly (with 0 for free ones) rather than defaulting to free.
#[tokio::test]
async fn unscheduled_feature_note_aborts_fee_collection() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        ..
    } = Test::builder().build()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_NOTE_SCRIPT_NOT_IN_FEE_SCHEDULE);

    Ok(())
}

/// A feature note whose script root is scheduled with an explicit 0 fee requires no sponsorship
/// and contributes nothing to the total.
#[tokio::test]
async fn zero_fee_feature_note_requires_no_sponsorship() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        ..
    } = Test::builder().feature_note_fee(AssetAmount::ZERO).build()?;
    let input_notes = [feature_notes[0].id()];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(balance, 0, "a 0-fee feature note should collect no fee");

    Ok(())
}

/// A non-owner cannot switch the active fee policy via `set_fee_policy`.
#[tokio::test]
async fn non_owner_cannot_set_fee_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);
    let non_owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([5; 32]);

    // The set_fee_policy note aborts inside its note script, before the auth allowlist check runs,
    // so the allowlist can stay empty.
    let account = build_fee_account_with_switching(owner_account_id, BTreeSet::new())?;

    let set_policy_note_script =
        create_fee_manager_note_script("set_fee_policy", custom_fee_policy()?.root().as_word());
    let mut rng = RandomCoin::new([Felt::from(602u32); 4].into());
    let set_policy_note = NoteBuilder::new(non_owner_account_id, &mut rng)
        .note_type(NoteType::Private)
        .code(set_policy_note_script.as_str())
        .build()?;

    let mut builder = MockChain::builder();
    builder.add_account(account.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_policy_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(set_policy_note.id())
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// A priced feature note whose fee is not fully covered aborts the transaction, whether no
/// sponsorship is bound to it at all or the bound one falls short.
#[rstest]
#[case::no_sponsorship(None)]
#[case::underfunded(Some(FEE_AMOUNT - 1))]
#[tokio::test]
async fn uncovered_feature_note_fee_is_rejected(
    #[case] sponsored_amount: Option<u64>,
) -> anyhow::Result<()> {
    let mut test_builder = Test::builder().feature_note_fee(AssetAmount::new(FEE_AMOUNT)?);
    if let Some(amount) = sponsored_amount {
        test_builder = test_builder.sponsorship(0, fee_asset(amount)?);
    }
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = test_builder.build()?;

    let mut builder = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id());
    for sponsorship_note in &sponsorship_notes {
        builder = builder.authenticated_input_note(sponsorship_note.id());
    }
    let result = builder.build()?.execute().await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_INPUT_NOTE_FEE_NOT_COVERED);

    Ok(())
}

/// A sponsorship note carrying an asset other than the account's fee asset aborts the transaction.
#[tokio::test]
async fn sponsorship_with_wrong_asset_is_rejected() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = Test::builder()
        .feature_note_fee(AssetAmount::new(FEE_AMOUNT)?)
        .sponsorship(0, other_asset(FEE_AMOUNT)?)
        .build()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET);

    Ok(())
}

/// A FEE_SPONSORSHIP note whose feature note is absent aborts fee collection. Such a note is
/// reclaimable by its own script, so this pins that reclaiming a sponsorship and collecting fees
/// cannot happen in the same transaction.
#[tokio::test]
async fn sponsorship_for_absent_feature_note_is_rejected() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;
    let network_account = network_account(
        Some((feature_note.script().root(), AssetAmount::new(FEE_AMOUNT)?)),
        BTreeSet::from([feature_note.script().root()]),
    )?;
    builder.add_account(network_account.clone())?;

    // The network account is the reclaimer, so consuming the sponsorship without its feature note
    // takes the note script's reclaim path rather than aborting there.
    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())
            .feature_note_id(feature_note.id())
            .asset(fee_asset(FEE_AMOUNT)?)
            .reclaimer(network_account.id())
            .reclaim_height(BlockNumber::from(1u32))
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SPONSORED_NOTE_NOT_FOUND);

    Ok(())
}

/// A custom fee policy charging [`FEE_AMOUNT`] in `fee_asset_id` for a note whose assets
/// commitment matches `fee_asset_note_commitment`, and in `other_fee_asset_id` for any other
/// note. This prices two feature notes in different fee assets within a single transaction,
/// exercising the fee policy manager's fee asset consistency check during fee collection.
fn asset_commitment_fee_policy(
    fee_asset_note_commitment: Word,
    fee_asset_id: Word,
    other_fee_asset_id: Word,
) -> anyhow::Result<FeePolicy> {
    const POLICY_NAME: &str = "test::fees::asset_commitment_fee";
    let masm_source = format!(
        r#"
        use miden::core::word
        use miden::standards::assets::fungible_asset

        #! Fee policy pricing a note in one of two assets, selected by its assets commitment.
        #!
        #! Inputs:  [RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]
        #! Outputs: [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc compute_note_fee
            # compare the note's assets commitment against the fee-asset note
            dupw.1 push.{fee_asset_note_commitment} exec.word::eq
            # => [is_fee_asset_note, RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]

            # price in the fee asset when the note matches, otherwise in a different asset
            if.true
                push.{fee_asset_id}
            else
                push.{other_fee_asset_id}
            end
            # => [FEE_ASSET_ID, RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]

            push.{fee_amount} exec.fungible_asset::create_value swapw
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, RECIPIENT, ASSETS_COMMITMENT, ATTACHMENTS_COMMITMENT, timeframe, priority, pad(2)]

            # drop the note parameters
            repeat.4 movupw.2 dropw end
            # => [FEE_ASSET_ID, FEE_ASSET_VALUE, pad(8)]
        end
        "#,
        fee_amount = FEE_AMOUNT,
    );

    let code = CodeBuilder::default().compile_component_code(POLICY_NAME, &masm_source)?;
    let root = code
        .get_procedure_root_by_path(format!("{POLICY_NAME}::compute_note_fee").as_str())
        .expect("asset commitment fee policy should export compute_note_fee");
    let component =
        AccountComponent::new(code, vec![], AccountComponentMetadata::mock(POLICY_NAME))?;

    Ok(FeePolicy::custom(root, [component])?)
}

/// Two priced feature notes whose fees are charged in different assets cannot be collected in the
/// same transaction. A custom fee policy prices the first feature note in the fee faucet's asset
/// and the second (which carries a different asset, so its assets commitment differs) in a
/// different faucet's asset. The first pair is collected; pricing the second feature note in an
/// asset other than the manager's configured fee asset is rejected by the manager's fee asset
/// consistency check before the second note's own sponsor is sought.
#[tokio::test]
async fn feature_notes_priced_in_different_assets_are_rejected() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let fee_asset_id = AssetId::new_fungible(fee_faucet_id()?).to_word();
    let other_fee_asset_id =
        AssetId::new_fungible(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?).to_word();

    // The two feature notes carry different assets, so the P2ID notes (which share one script root)
    // have distinct assets commitments. The policy keys on those commitments to price the first in
    // the fee asset and the second in a different asset.
    let feature_note_a_asset = fee_asset(1)?;
    let feature_note_b_asset = other_asset(1)?;
    let policy = asset_commitment_fee_policy(
        NoteAssets::new(vec![feature_note_a_asset])?.commitment(),
        fee_asset_id,
        other_fee_asset_id,
    )?;

    // Both feature notes are P2ID notes sharing one script root; allowlist it.
    let network_account = NetworkAccount::builder(
        [7; 32],
        BTreeSet::from([P2idNote::script_root()]),
        FeePolicyManager::builder()
            .fee_faucet_id(fee_faucet_id()?)
            .active_fee_policy(policy)
            .build(),
    )?
    .with_component(BasicWallet)
    .build_existing()?;

    builder.add_account(network_account.clone())?;

    // The P2ID feature notes target the network account so it can consume them.
    let feature_note_a = builder.add_p2id_note(
        sponsor.id(),
        network_account.id(),
        &[feature_note_a_asset],
        NoteType::Public,
    )?;
    let feature_note_b = builder.add_p2id_note(
        sponsor.id(),
        network_account.id(),
        &[feature_note_b_asset],
        NoteType::Public,
    )?;

    // Only the first feature note is sponsored; the second is rejected before its sponsor is
    // sought.
    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())
            .feature_note_id(feature_note_a.id())
            .asset(fee_asset(FEE_AMOUNT)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_note_a.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(feature_note_b.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_FEE_ASSET_MISMATCH);

    Ok(())
}

// CREATE NETWORK NOTE SPONSORSHIPS
// ================================================================================================

// A network account's own auth procedure sponsors every network output note automatically (via
// `pay_fee` -> `create_network_note_sponsorships`), so the sponsor only needs to create the note.

/// Builds the transaction script that creates `num_notes` network notes targeted at `target_id`.
///
/// The notes differ only in their serial numbers, so they get different note IDs. Each block of
/// note creation code leaves the operand stack as it found it, which lets the blocks follow each
/// other.
fn create_network_notes_tx_script(
    target_id: AccountId,
    num_notes: u32,
) -> anyhow::Result<TransactionScript> {
    // The created notes carry a standard note script so the host can assemble the public note.
    let script_root = P2idNote::script_root().as_word();
    let target_prefix = target_id.prefix().as_felt();
    let target_suffix = target_id.suffix();

    let create_note_blocks: String = (0..num_notes)
        .map(|note_idx| {
            format!(
                r#"
            # => [pad(16)]

            # compute the recipient of the storage-less network note
            push.{script_root}
            push.{serial_num}
            push.0.0
            # => [storage_ptr = 0, num_storage_items = 0, SERIAL_NUM, SCRIPT_ROOT, pad(16)]

            exec.note::compute_and_store_recipient
            # => [RECIPIENT, pad(16)]

            # tag the note for the target network account, then create it via the NoteCreator
            push.NOTE_TYPE_PUBLIC push.{target_prefix} exec.note_tag::create_account_target
            # => [tag, note_type, RECIPIENT, pad(16)]

            call.::miden::standards::note::note_creator::create_note
            # => [note_idx, pad(21)]

            movdn.15 dropw dropw dropw drop drop drop
            # => [note_idx, pad(6)]

            # attach the network account target so the auth procedure sponsors the note
            push.0 push.{target_prefix} push.{target_suffix}
            # => [target_id_suffix, target_id_prefix, exec_hint_tag = 0, note_idx, pad(6)]

            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT, note_idx, pad(6)]

            exec.output_note::add_word_attachment
            # => [pad(6)]
"#,
                serial_num = Word::from([21u32, 22, 23, 24 + note_idx]),
            )
        })
        .collect();

    let tx_script_src = format!(
        r#"
        use miden::protocol::note
        use miden::protocol::output_note

        use miden::standards::attachments::network_account_target
        use miden::standards::note::note_tag

        use {{NOTE_TYPE_PUBLIC}} from miden::protocol::note

        @transaction_script
        pub proc main
            {create_note_blocks}
        end
        "#
    );

    Ok(CodeBuilder::default().compile_tx_script(tx_script_src)?)
}

/// A sponsor account and a target network account, plus the script creating network notes targeted
/// at the target.
///
/// The sponsor runs that script. Its auth procedure then creates one FEE_SPONSORSHIP note for each
/// created network note, funded from the sponsor's vault.
///
/// [`SponsorshipPolicy::AtMostCollectedFees`] is the default. The sponsor collects in its
/// configured fee asset but funds sponsorships in the native one, so the default configures it with
/// the native fee faucet to make the two amounts comparable.
struct SponsorshipTest {
    mock_chain: MockChain,
    sponsor: Account,
    /// The network account the created notes are targeted at.
    target_id: AccountId,
    tx_script: TransactionScript,
    foreign_inputs: (Account, AccountWitness),
    /// The feature notes and their FEE_SPONSORSHIP notes, which the sponsor consumes to collect
    /// fees. Empty when no feature note was requested.
    input_notes: Vec<NoteId>,
}

#[bon::bon]
impl SponsorshipTest {
    /// Builds a [`SponsorshipTest`].
    ///
    /// The target charges [`FEE_AMOUNT`] for each network note, so the sponsor must fund each
    /// sponsorship note with that amount. Its vault holds exactly the total it must fund.
    ///
    /// The build order is fixed by three dependencies: the target ID goes into the transaction
    /// script, the script root and the feature note script root go into the sponsor's allowlists,
    /// and the sponsorship notes name the sponsor as their target account.
    #[builder]
    fn new(
        /// Faucet whose asset the target charges its fee in. Defaults to the native fee faucet.
        target_fee_faucet: Option<AccountId>,
        /// Faucet whose asset the sponsor collects fees in. Defaults to the native fee faucet.
        sponsor_fee_faucet: Option<AccountId>,
        /// How much the sponsor may sponsor. Defaults to
        /// [`SponsorshipPolicy::AtMostCollectedFees`].
        #[builder(default)]
        sponsorship_policy: SponsorshipPolicy,
        /// Number of network notes the transaction script creates. Defaults to 1.
        #[builder(default = 1)]
        num_network_notes: u32,
        /// Number of feature notes the sponsor consumes to collect fees. Each one is priced at
        /// [`FEE_AMOUNT`] and comes with a FEE_SPONSORSHIP note that covers it. Defaults to 0, in
        /// which case the sponsor collects nothing.
        #[builder(default)]
        num_collected_notes: u32,
    ) -> anyhow::Result<Self> {
        let target_fee_faucet = target_fee_faucet.unwrap_or(native_fee_faucet_id()?);
        let sponsor_fee_faucet = sponsor_fee_faucet.unwrap_or(native_fee_faucet_id()?);

        // The target is only queried for its fee policy via FPI, so its auth never runs and its
        // allowlists can stay empty.
        let target_policy = BasicConstantFeePolicy::new()
            .with_fee(P2idNote::script_root(), AssetAmount::new(FEE_AMOUNT)?);
        let target_fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(target_fee_faucet)
            .active_fee_policy(target_policy.into())
            .build();
        let target = AccountBuilder::new([9; 32])
            .account_type(AccountType::Public)
            .with_components(AuthNetworkAccount::new(BTreeSet::new(), target_fee_policy_manager)?)
            .with_component(BasicWallet)
            .build_existing()?;

        let tx_script = create_network_notes_tx_script(target.id(), num_network_notes)?;

        let mut rng = RandomCoin::new(Word::empty());
        let mut builder = MockChain::builder();
        builder.add_account(target.clone())?;

        let funder = builder.add_existing_wallet(Auth::IncrNonce)?;
        let feature_notes: Vec<Note> = (0..num_collected_notes)
            .map(|_| builder.add_p2any_note(funder.id(), NoteType::Public, []))
            .collect::<anyhow::Result<_>>()?;

        // The feature notes are P2ANY notes without assets, so they all share one script root. The
        // sponsor prices that root and allowlists it, which lets it consume every feature note. It
        // also runs the note creation script, so that root must be allowlisted as well.
        let mut sponsor_policy = BasicConstantFeePolicy::new();
        let mut sponsor_allowed_notes = BTreeSet::new();
        if let Some(feature_note) = feature_notes.first() {
            sponsor_policy = sponsor_policy
                .with_fee(feature_note.script().root(), AssetAmount::new(FEE_AMOUNT)?);
            sponsor_allowed_notes.insert(feature_note.script().root());
        }
        let sponsor_fee_policy_manager = FeePolicyManager::builder()
            .fee_faucet_id(sponsor_fee_faucet)
            .active_fee_policy(sponsor_policy.into())
            .build();
        let sponsor = AccountBuilder::new([8; 32])
            .account_type(AccountType::Public)
            .with_components(
                AuthNetworkAccount::new(sponsor_allowed_notes, sponsor_fee_policy_manager)?
                    .with_allowed_tx_scripts(BTreeSet::from([tx_script.root()]))
                    .with_sponsorship_policy(sponsorship_policy),
            )
            .with_component(NoteCreator)
            .with_assets([native_fee_asset(u64::from(num_network_notes) * FEE_AMOUNT)?])
            .build_existing()?;
        builder.add_account(sponsor.clone())?;

        // The sponsorship notes target the sponsor, so they can only be built once it exists.
        let mut input_notes = Vec::new();
        for feature_note in &feature_notes {
            let sponsorship_note = Note::from(
                FeeSponsorshipNote::builder()
                    .sender(feature_note.metadata().sender())
                    .target_account(sponsor.id())
                    .feature_note_id(feature_note.id())
                    .asset(Asset::from(FungibleAsset::new(sponsor_fee_faucet, FEE_AMOUNT)?))
                    .generate_serial_number(&mut rng)
                    .build()?,
            );
            builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));
            input_notes.extend([feature_note.id(), sponsorship_note.id()]);
        }

        let mut mock_chain = builder.build()?;
        mock_chain.prove_next_block()?;

        let foreign_inputs = mock_chain.get_foreign_account_inputs(target.id())?;

        Ok(SponsorshipTest {
            mock_chain,
            sponsor,
            target_id: target.id(),
            tx_script,
            foreign_inputs,
            input_notes,
        })
    }
}

impl SponsorshipTest {
    /// Builds the sponsor's transaction. It runs the note creation script and consumes the feature
    /// notes together with their sponsorship notes.
    ///
    /// The target is passed as a foreign account, since the sponsorship step reads its fee policy
    /// through FPI.
    fn transaction(&self) -> anyhow::Result<MockTransaction> {
        let mut builder = self
            .mock_chain
            .build_transaction(self.sponsor.id())
            .foreign_accounts([self.foreign_inputs.clone()])
            .tx_script(self.tx_script.clone());
        for note_id in &self.input_notes {
            builder = builder.authenticated_input_note(*note_id);
        }

        builder.build()
    }
}

/// Asserts that the output note at `network_note_idx` is a created network note and that the output
/// note at `sponsorship_note_idx` is the FEE_SPONSORSHIP note that pays for it.
///
/// The sponsorship note must name the network note as its feature note and carry the target's fee
/// in the native fee asset.
fn assert_network_note_is_sponsored(
    output_notes: &RawOutputNotes,
    network_note_idx: usize,
    sponsorship_note_idx: usize,
) -> anyhow::Result<()> {
    let network_note = output_notes.get_note(network_note_idx);
    let sponsorship_note = output_notes.get_note(sponsorship_note_idx);

    let network_recipient =
        network_note.recipient().expect("recipient should exist for public notes");
    assert_eq!(network_recipient.script().root(), P2idNote::script_root());

    let sponsorship_recipient =
        sponsorship_note.recipient().expect("recipient should exist for public notes");
    assert_eq!(sponsorship_recipient.script().root(), FeeSponsorshipNote::script_root());

    // The sponsorship note names the network note it pays for.
    let sponsorship_storage =
        FeeSponsorshipNoteStorage::try_from(sponsorship_recipient.storage().items())?;
    assert_eq!(sponsorship_storage.feature_note_id(), network_note.id());

    // The sponsorship note carries exactly the target's fee in the native fee asset.
    assert_eq!(sponsorship_note.assets().as_slice(), &[native_fee_asset(FEE_AMOUNT)?]);

    Ok(())
}

/// A network note whose target charges its fee in the native fee asset is sponsored by the auth
/// procedure: the sponsorship note is funded with the fee from the sponsor's vault.
///
/// The sponsor collects nothing, so this also covers [`SponsorshipPolicy::Unlimited`] permitting a
/// sponsorship that no collected fee backs. Its configured fee asset is not the native one, which
/// shows that sponsorship notes are always funded in the native fee asset.
#[tokio::test]
async fn create_sponsorships_funds_note_in_native_fee_asset() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder()
        .sponsor_fee_faucet(fee_faucet_id()?)
        .sponsorship_policy(SponsorshipPolicy::Unlimited)
        .build()?;
    let mut sponsor = test.sponsor.clone();

    let executed = test.transaction()?.execute().await?;

    // The transaction script creates the network note, then the auth procedure appends its
    // sponsorship note.
    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 2);
    assert_network_note_is_sponsored(output_notes, 0, 1)?;

    // The network note is tagged for the target network account via its attachment.
    let network_target = NetworkAccountTarget::try_from(output_notes.get_note(0).attachments())?;
    assert_eq!(network_target.target_id(), test.target_id);

    sponsor.apply_patch(executed.account_patch())?;
    assert_eq!(
        sponsor
            .vault()
            .get_balance(AssetId::new_fungible(native_fee_faucet_id()?))?
            .as_u64(),
        0,
        "the sponsorship note should be funded with the fee from the sponsor's vault"
    );

    Ok(())
}

/// A network note whose target charges a non-zero fee in an asset other than the native fee asset
/// is rejected: fee asset conversion is not supported yet.
#[tokio::test]
async fn create_sponsorships_reject_target_with_different_fee_asset() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder()
        .target_fee_faucet(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)
        .sponsorship_policy(SponsorshipPolicy::Unlimited)
        .build()?;

    let result = test.transaction()?.execute().await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH);

    Ok(())
}

/// One transaction that collects two sponsorship input notes and creates two sponsorship output
/// notes, so the collection loop and the creation loop both run more than once.
///
/// Each created network note gets its own sponsorship note. The two collected fees cover the two
/// sponsored fees exactly, so [`SponsorshipPolicy::AtMostCollectedFees`] accepts the transaction.
#[tokio::test]
async fn sponsors_and_collects_multiple_notes() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder().num_network_notes(2).num_collected_notes(2).build()?;

    let executed = test.transaction()?.execute().await?;

    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 4);

    // The transaction script creates both network notes, then the auth procedure appends their
    // sponsorship notes in the same order.
    assert_network_note_is_sponsored(output_notes, 0, 2)?;
    assert_network_note_is_sponsored(output_notes, 1, 3)?;

    Ok(())
}

// SPONSORSHIP POLICY
// ================================================================================================

/// Under [`SponsorshipPolicy::AtMostCollectedFees`], a sponsorship that no collected fee backs is
/// rejected.
#[tokio::test]
async fn sponsoring_more_than_collected_is_rejected() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder().build()?;

    let result = test.transaction()?.execute().await;

    assert_transaction_executor_error!(result, ERR_NETWORK_ACCOUNT_SPONSORED_FEES_EXCEED_COLLECTED);

    Ok(())
}

/// Under [`SponsorshipPolicy::AtMostCollectedFees`], a sponsorship the collected fees cover is
/// accepted.
#[tokio::test]
async fn sponsoring_within_collected_is_accepted() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder().num_collected_notes(1).build()?;

    let executed = test.transaction()?.execute().await?;

    assert_eq!(executed.output_notes().num_notes(), 2);
    assert_network_note_is_sponsored(executed.output_notes(), 0, 1)?;

    Ok(())
}

/// Under [`SponsorshipPolicy::AtMostCollectedFees`], sponsoring while configured with a fee asset
/// other than the native one is rejected: the collected and sponsored amounts would be denominated
/// in different assets, so the cap would not bound anything.
#[tokio::test]
async fn sponsoring_with_a_non_native_fee_asset_is_rejected() -> anyhow::Result<()> {
    let test = SponsorshipTest::builder().sponsor_fee_faucet(fee_faucet_id()?).build()?;

    let result = test.transaction()?.execute().await;

    assert_transaction_executor_error!(result, ERR_NETWORK_ACCOUNT_FEE_ASSET_NOT_NATIVE);

    Ok(())
}
