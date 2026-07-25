use alloc::sync::Arc;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteAssets, NoteId, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
};
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicy, FeePolicyManager};
use miden_standards::account::wallets::{BasicWallet, NoteCreator};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_EXPECTED_FEE_ASSET_MISMATCH,
    ERR_FEE_MANAGER_FEATURE_NOTE_MISSING_SPONSORSHIP,
    ERR_FEE_MANAGER_SPONSORSHIP_FEE_TOO_LOW,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_FEATURE_NOTE,
    ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH,
    ERR_FEE_MANAGER_UNEXPECTED_SPONSORSHIP_NOTE,
    ERR_FEE_POLICY_FEE_ASSET_MISMATCH,
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
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
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
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
/// network-note sponsorships in (via `tx::get_fee_faucet_id`, not the account's configured asset).
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

/// Builds an `AuthNetworkAccount`-authenticated network account with a `BasicWallet` and a
/// `FeePolicyManager`. When `fee_entry` is provided, the fee policy manager schedules the
/// given fee for that note script root; `allowed_note_roots` seeds the note-script allowlist.
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

    Ok(AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: allowed_note_roots,
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager,
        })
        .with_component(BasicWallet)
        .build_existing()?)
}

/// A network account plus a set of feature notes, each optionally paired with a FEE_SPONSORSHIP
/// note carrying the assets specified for it.
struct Test {
    mock_chain: MockChain,
    network_account: Account,
    feature_notes: Vec<Note>,
    sponsorship_notes: Vec<Note>,
}

/// Builds a [`Test`] with one feature note (a 0-asset P2ANY note, so all feature notes share
/// the same script root) per entry in `sponsorships`. An entry of `Some(asset)` creates a
/// FEE_SPONSORSHIP note bound to that feature note and carrying `asset`; `None` leaves the feature
/// note unpaired. The feature note script root is priced in the fee schedule with
/// `feature_note_fee` when provided, and left unscheduled otherwise.
fn build_test(
    feature_note_fee: Option<AssetAmount>,
    sponsorships: Vec<Option<Asset>>,
) -> anyhow::Result<Test> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let feature_notes: Vec<Note> = sponsorships
        .iter()
        .map(|_| builder.add_p2any_note(sponsor.id(), NoteType::Public, []))
        .collect::<anyhow::Result<_>>()?;

    let fee_entry = feature_note_fee.map(|fee| (feature_notes[0].script().root(), fee));

    // The account consumes the feature notes (all sharing one P2ANY root) and their FEE_SPONSORSHIP
    // notes, so both roots must be allowlisted for the auth procedure to reach fee collection.
    let mut allowed_note_roots = BTreeSet::from([FeeSponsorshipNote::script_root()]);
    if let Some(feature_note) = feature_notes.first() {
        allowed_note_roots.insert(feature_note.script().root());
    }
    let network_account = network_account(fee_entry, allowed_note_roots)?;
    builder.add_account(network_account.clone())?;

    let mut sponsorship_notes = Vec::new();
    for (feature_note, asset) in feature_notes.iter().zip(&sponsorships) {
        let Some(asset) = asset else { continue };
        let note = Note::from(
            FeeSponsorshipNote::builder()
                .sender(sponsor.id())
                .target_account(network_account.id())
                .feature_note_id(feature_note.id())
                .asset(*asset)
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

/// A feature note paired with a sponsorship note that covers its fee is collected: the aggregated
/// fee equals the sponsored amount, whether the sponsorship covers the fee exactly or with a
/// surplus.
#[rstest]
#[case::exact_cover(FEE_AMOUNT)]
#[case::over_cover(FEE_AMOUNT + 250)]
#[tokio::test]
async fn collects_sponsored_fee_for_a_pair(#[case] sponsored_amount: u64) -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = build_test(Some(AssetAmount::new(FEE_AMOUNT)?), vec![Some(fee_asset(sponsored_amount)?)])?;
    let input_notes = [feature_notes[0].id(), sponsorship_notes[0].id()];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance, sponsored_amount,
        "the account should collect the sponsored fee into its vault"
    );

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
        &create_fee_manager_note_script("set_fee_policy", custom_fee_policy()?.root().as_word());
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

    // Allowlist both the set_fee_policy note and the FEE_SPONSORSHIP note that pays its fee.
    let account = build_fee_account_with_switching(
        owner_account_id,
        BTreeSet::from([set_policy_note.script().root(), FeeSponsorshipNote::script_root()]),
        BTreeSet::new(),
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

/// Fees from several feature/sponsorship pairs are aggregated into a single total.
#[tokio::test]
async fn aggregates_fees_across_pairs() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = build_test(
        Some(AssetAmount::new(FEE_AMOUNT)?),
        vec![Some(fee_asset(FEE_AMOUNT)?), Some(fee_asset(FEE_AMOUNT)?)],
    )?;
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
    // so the allowlists can stay empty.
    let account =
        build_fee_account_with_switching(owner_account_id, BTreeSet::new(), BTreeSet::new())?;

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
    } = build_test(None, vec![None])?;

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
    } = build_test(Some(AssetAmount::ZERO), vec![None])?;
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
    // so the allowlists can stay empty.
    let account =
        build_fee_account_with_switching(owner_account_id, BTreeSet::new(), BTreeSet::new())?;

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

/// A priced feature note that is not followed by a sponsorship note aborts the transaction.
#[tokio::test]
async fn priced_feature_note_without_sponsorship_is_rejected() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        ..
    } = build_test(Some(AssetAmount::new(FEE_AMOUNT)?), vec![None])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_FEATURE_NOTE_MISSING_SPONSORSHIP);

    Ok(())
}

/// A sponsorship note encountered as a current note - here consumed before its feature note - is
/// rejected as unpaired.
#[tokio::test]
async fn sponsorship_note_as_current_note_is_rejected() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = build_test(Some(AssetAmount::new(FEE_AMOUNT)?), vec![Some(fee_asset(FEE_AMOUNT)?)])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .authenticated_input_note(feature_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_UNEXPECTED_SPONSORSHIP_NOTE);

    Ok(())
}

/// A sponsorship note whose fee amount does not cover the feature note's required fee aborts the
/// transaction.
#[tokio::test]
async fn sponsorship_below_required_fee_is_rejected() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        sponsorship_notes,
    } = build_test(Some(AssetAmount::new(FEE_AMOUNT)?), vec![Some(fee_asset(FEE_AMOUNT - 1)?)])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SPONSORSHIP_FEE_TOO_LOW);

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
    } = build_test(Some(AssetAmount::new(FEE_AMOUNT)?), vec![Some(other_asset(FEE_AMOUNT)?)])?;

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

/// A well-formed FEE_SPONSORSHIP note carrying the correct fee asset, but sitting next to a priced
/// feature note it does not actually sponsor (its stored feature note ID names a different note),
/// is rejected. This guards against pairing a sponsorship with an unintended, wrongly-priced
/// feature note.
#[tokio::test]
async fn sponsorship_for_wrong_feature_note_is_rejected() -> anyhow::Result<()> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Two priced feature notes sharing the same script root.
    let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;
    let other_feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

    // Both feature notes are P2ANY notes and so share one script root; allowlist it and the
    // FEE_SPONSORSHIP root.
    let network_account = network_account(
        Some((feature_note.script().root(), AssetAmount::new(FEE_AMOUNT)?)),
        BTreeSet::from([feature_note.script().root(), FeeSponsorshipNote::script_root()]),
    )?;
    builder.add_account(network_account.clone())?;

    // The sponsorship note sponsors `other_feature_note`, yet below it is consumed right after
    // `feature_note`, where `collect_sponsored_fees` looks for `feature_note`'s sponsor.
    let sponsorship_note = Note::from(
        FeeSponsorshipNote::builder()
            .sender(sponsor.id())
            .target_account(network_account.id())
            .feature_note_id(other_feature_note.id())
            .asset(fee_asset(FEE_AMOUNT)?)
            .generate_serial_number(&mut rng)
            .build()?,
    );
    builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // `other_feature_note` is consumed too so the sponsorship note's own pairing check passes; the
    // mismatch is caught by `collect_sponsored_fees` at the `feature_note`/sponsorship pair first.
    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_note.id())
        .authenticated_input_note(sponsorship_note.id())
        .authenticated_input_note(other_feature_note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SPONSORSHIP_WRONG_FEATURE_NOTE);

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

    // Both feature notes are P2ID notes sharing one script root; allowlist it and the
    // FEE_SPONSORSHIP root.
    let network_account = AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::from([
                P2idNote::script_root(),
                FeeSponsorshipNote::script_root(),
            ]),
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager: FeePolicyManager::builder()
                .fee_faucet_id(fee_faucet_id()?)
                .active_fee_policy(policy)
                .build(),
        })
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
// Note creation goes through the standard `NoteCreator` component's `create_note` procedure (the
// only note operation restricted to the account context); the sponsor's tx script computes the
// recipient and tag, calls into it, and adds the network account target attachment itself.

/// A sponsor account (funded with [`FEE_AMOUNT`] of the fee asset) and a target network account
/// whose fee policy manager charges [`FEE_AMOUNT`] in the asset of the given faucet, plus the
/// script creating a network note targeted at it; the sponsor's auth procedure sponsors the note.
struct CreateTest {
    mock_chain: MockChain,
    sponsor: Account,
    tx_script: TransactionScript,
    foreign_inputs: (Account, miden_protocol::block::account_tree::AccountWitness),
}

fn build_create_test(target_fee_faucet: AccountId) -> anyhow::Result<CreateTest> {
    // The created note carries a standard note script so the host can assemble the public note.
    let script_root = P2idNote::script_root();
    let serial_num = Word::from([21u32, 22, 23, 24]);

    // The target is only queried for its fee policy via FPI, so its auth never runs and its
    // allowlists can stay empty. It is built first because its ID is embedded in the creator tx
    // script, whose root the sponsor must in turn allowlist.
    let target_policy =
        BasicConstantFeePolicy::new().with_fee(script_root, AssetAmount::new(FEE_AMOUNT)?);
    let target_fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(target_fee_faucet)
        .active_fee_policy(target_policy.into())
        .build();
    let target = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::new(),
            fee_policy_manager: target_fee_policy_manager,
        })
        .with_component(BasicWallet)
        .build_existing()?;

    let tx_script_src = format!(
        r#"
        use miden::protocol::note
        use miden::protocol::output_note

        use miden::standards::attachments::network_account_target
        use miden::standards::note_tag

        use {{NOTE_TYPE_PUBLIC}} from miden::protocol::note

        @transaction_script
        pub proc main
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
        end
        "#,
        target_prefix = target.id().prefix().as_felt(),
        target_suffix = target.id().suffix(),
        script_root = script_root.as_word(),
        serial_num = serial_num,
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_src)?;

    // The sponsor runs the tx script that creates a network note, so its root must be allowlisted.
    let sponsor_fee_policy_manager = FeePolicyManager::mock(fee_faucet_id()?);
    let sponsor = AccountBuilder::new([8; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::NetworkAccount {
            allowed_script_roots: BTreeSet::new(),
            allowed_tx_script_roots: BTreeSet::from([tx_script.root()]),
            fee_policy_manager: sponsor_fee_policy_manager,
        })
        .with_component(NoteCreator)
        .with_assets([native_fee_asset(FEE_AMOUNT)?])
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(sponsor.clone())?;
    builder.add_account(target.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let foreign_inputs = mock_chain.get_foreign_account_inputs(target.id())?;

    Ok(CreateTest {
        mock_chain,
        sponsor,
        tx_script,
        foreign_inputs,
    })
}

/// A network note whose target charges its fee in the native fee asset is sponsored by the auth
/// procedure: the sponsorship note is funded with the fee from the sponsor's vault.
#[tokio::test]
async fn create_sponsorships_funds_note_in_native_fee_asset() -> anyhow::Result<()> {
    let CreateTest {
        mock_chain,
        mut sponsor,
        tx_script,
        foreign_inputs,
    } = build_create_test(native_fee_faucet_id()?)?;
    let target_id = foreign_inputs.0.id();

    let executed = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([foreign_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    // The tx creates the feature note, which the auth procedure pairs with a sponsorship note.
    let output_notes = executed.output_notes();
    assert_eq!(
        output_notes.num_notes(),
        2,
        "the transaction should create the feature note and its sponsorship note"
    );
    let feature_note = output_notes
        .iter()
        .find(|note| {
            note.recipient()
                .is_some_and(|recipient| recipient.script().root() == P2idNote::script_root())
        })
        .expect("the P2ID feature note should be created");
    let sponsorship_note = output_notes
        .iter()
        .find(|note| {
            note.recipient().is_some_and(|recipient| {
                recipient.script().root() == FeeSponsorshipNote::script_root()
            })
        })
        .expect("the sponsorship note should be created");

    // The sponsorship note names the feature note it pays for.
    let sponsorship_storage = FeeSponsorshipNoteStorage::try_from(
        sponsorship_note
            .recipient()
            .expect("a public sponsorship note has recipient details")
            .storage()
            .items(),
    )?;
    assert_eq!(
        sponsorship_storage.feature_note_id(),
        feature_note.id(),
        "the sponsorship note should sponsor the feature note"
    );

    // It carries exactly the target's fee in the native fee asset.
    assert_eq!(
        sponsorship_note.assets().iter().copied().collect::<Vec<_>>(),
        vec![native_fee_asset(FEE_AMOUNT)?],
        "the sponsorship note should carry the target's fee in the native fee asset"
    );

    // The feature note is tagged for the target network account via its attachment.
    let network_target = NetworkAccountTarget::try_from(feature_note.attachments())?;
    assert_eq!(
        network_target.target_id(),
        target_id,
        "the feature note should target the network account"
    );

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
    let CreateTest {
        mock_chain,
        sponsor,
        tx_script,
        foreign_inputs,
    } = build_create_test(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)?;

    let result = mock_chain
        .build_transaction(sponsor.id())
        .foreign_accounts([foreign_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH);

    Ok(())
}
