use alloc::sync::Arc;
use std::sync::LazyLock;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::note::{Note, NoteId, NoteScriptRoot, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1;
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_protocol::{Felt, Word};
use miden_standards::account::fees::{ConstantFeePolicy, FeeManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_FEE_MANAGER_FEATURE_NOTE_MISSING_SPONSORSHIP,
    ERR_FEE_MANAGER_SPONSORSHIP_FEE_TOO_LOW,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_ASSET,
    ERR_FEE_MANAGER_SPONSORSHIP_WRONG_FEATURE_NOTE,
    ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH,
    ERR_FEE_MANAGER_UNEXPECTED_SPONSORSHIP_NOTE,
    ERR_FEE_POLICY_ROOT_NOT_ALLOWED,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::{FeeSponsorshipNote, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use rstest::rstest;

use crate::scripts::fee_manager::{
    FEE_AMOUNT,
    build_fee_account_with_switching,
    create_set_fee_policy_note_script,
    custom_fee_policy,
    estimate_note_fee_tx_script_code,
    fee_faucet_id,
    priced_root,
};

// COLLECT SPONSORED FEES
// ================================================================================================

/// Returns a fungible asset of `amount` units issued by the fee faucet (the asset the fee manager
/// accepts fees in).
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

// `collect_sponsored_fees` is `exec`-only and reads the active account's storage, so it must run
// inside a registered account procedure. This test-only component wraps it in an
// `@account_procedure` that the transaction scripts below `call` into, mirroring how a network
// account's own auth procedure would `exec` it.
const FEE_COLLECTOR_NAME: &str = "test::fee_collector";

static FEE_COLLECTOR_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let src = r#"
        use miden::standards::fees

        @account_procedure
        pub proc collect_sponsored_fees
            exec.fees::collect_sponsored_fees drop
            # => [pad(16)]
        end
        "#;
    CodeBuilder::default()
        .compile_component_code(FEE_COLLECTOR_NAME, src)
        .expect("fee collector component should compile")
});

/// The test-only account component exposing `collect_sponsored_fees` as an account procedure.
fn fee_collector_component() -> anyhow::Result<AccountComponent> {
    Ok(AccountComponent::new(
        FEE_COLLECTOR_CODE.clone(),
        vec![],
        AccountComponentMetadata::mock(FEE_COLLECTOR_NAME),
    )?)
}

/// Builds a network account with a `BasicWallet`, a `FeeManager`, and the test fee-collector
/// component. When `priced_root` is provided, the fee manager schedules [`FEE_AMOUNT`] for that
/// note script root.
fn network_account(priced_root: Option<NoteScriptRoot>) -> anyhow::Result<Account> {
    let mut policy = ConstantFeePolicy::new();
    if let Some(root) = priced_root {
        policy = policy.with_fee(root, AssetAmount::new(FEE_AMOUNT)?);
    }
    let fee_manager = FeeManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(policy.into())
        .build();

    Ok(AccountBuilder::new([7; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(fee_manager)
        .with_component(fee_collector_component()?)
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
/// note unpaired. The feature note script root is priced in the fee schedule when
/// `price_feature_notes` is set.
fn build_test(price_feature_notes: bool, sponsorships: Vec<Option<Asset>>) -> anyhow::Result<Test> {
    let mut rng = RandomCoin::new(Word::empty());
    let mut builder = MockChain::builder();
    let sponsor = builder.add_existing_wallet(Auth::IncrNonce)?;

    let feature_notes: Vec<Note> = sponsorships
        .iter()
        .map(|_| builder.add_p2any_note(sponsor.id(), NoteType::Public, []))
        .collect::<anyhow::Result<_>>()?;

    let priced_root = price_feature_notes.then(|| feature_notes[0].script().root());
    let network_account = network_account(priced_root)?;
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

/// A transaction script that runs `collect_sponsored_fees`.
fn collect_tx_script() -> anyhow::Result<TransactionScript> {
    let src = r#"
        use test::fee_collector

        @transaction_script
        pub proc main
            call.fee_collector::collect_sponsored_fees
            # => [pad(16)]

            dropw dropw dropw dropw
        end
        "#;

    Ok(CodeBuilder::default()
        .with_dynamically_linked_library(&*FEE_COLLECTOR_CODE)?
        .compile_tx_script(src)?)
}

/// Runs `collect_sponsored_fees` for the given input notes against the network account and returns
/// the account's fee-asset balance after the transaction.
async fn collect_fee_balance(
    mock_chain: MockChain,
    mut network_account: Account,
    input_notes: &[NoteId],
) -> anyhow::Result<u64> {
    let mut builder = mock_chain.build_transaction(network_account.id());
    for note_id in input_notes {
        builder = builder.authenticated_input_note(*note_id);
    }
    let executed = builder.tx_script(collect_tx_script()?).build()?.execute().await?;

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
    } = build_test(true, vec![Some(fee_asset(sponsored_amount)?)])?;
    let input_notes = [feature_notes[0].id(), sponsorship_notes[0].id()];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(
        balance, sponsored_amount,
        "the account should collect the sponsored fee into its vault"
    );

    Ok(())
}

/// The owner switches the active fee policy from the constant fee policy to the user-defined
/// custom policy via `set_fee_policy`, after which `estimate_note_fee` prices the previously
/// priced root with the custom policy's logic instead of the schedule.
#[tokio::test]
async fn set_fee_policy_switches_to_custom_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let set_policy_note_script =
        create_set_fee_policy_note_script(custom_fee_policy()?.root().as_word());
    let mut rng = RandomCoin::new([Felt::from(600u32); 4].into());
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
    let tx_context = mock_chain
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // With the custom policy active, the previously priced root is priced by the custom logic:
    // the fee value echoes the STORAGE_COMMITMENT supplied to the estimate script instead of the
    // scheduled amount, while the fee asset ID still comes from the manager's storage.
    let storage_commitment = Word::from([11u32, 12, 13, 14]);
    let tx_script_code = estimate_note_fee_tx_script_code(
        storage_commitment,
        AssetId::new_fungible(fee_faucet_id()?).to_word(),
        storage_commitment,
    );
    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    mock_chain
        .build_tx_context(account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(priced_root().as_word())
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
    } = build_test(true, vec![Some(fee_asset(FEE_AMOUNT)?), Some(fee_asset(FEE_AMOUNT)?)])?;
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

    let account = build_fee_account_with_switching(owner_account_id)?;

    // This root exists in the account code, but is not in the fee policy allowlist.
    let invalid_policy_root = FeeManager::get_fee_policy_root().as_word();
    let set_policy_note_script = create_set_fee_policy_note_script(invalid_policy_root);
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
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_POLICY_ROOT_NOT_ALLOWED);

    Ok(())
}

/// A feature note whose script root is unpriced requires no sponsorship and contributes nothing to
/// the total.
#[tokio::test]
async fn unpriced_feature_note_requires_no_sponsorship() -> anyhow::Result<()> {
    let Test {
        mock_chain,
        network_account,
        feature_notes,
        ..
    } = build_test(false, vec![None])?;
    let input_notes = [feature_notes[0].id()];

    let balance = collect_fee_balance(mock_chain, network_account, &input_notes).await?;

    assert_eq!(balance, 0, "an unpriced feature note should collect no fee");

    Ok(())
}

/// A non-owner cannot switch the active fee policy via `set_fee_policy`.
#[tokio::test]
async fn non_owner_cannot_set_fee_policy() -> anyhow::Result<()> {
    let owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([4; 32]);
    let non_owner_account_id =
        AccountId::builder().account_type(AccountType::Private).build_with_seed([5; 32]);

    let account = build_fee_account_with_switching(owner_account_id)?;

    let set_policy_note_script =
        create_set_fee_policy_note_script(custom_fee_policy()?.root().as_word());
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
        .build_tx_context(account.id(), &[set_policy_note.id()], &[])?
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
    } = build_test(true, vec![None])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .tx_script(collect_tx_script()?)
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
    } = build_test(true, vec![Some(fee_asset(FEE_AMOUNT)?)])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .authenticated_input_note(feature_notes[0].id())
        .tx_script(collect_tx_script()?)
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
    } = build_test(true, vec![Some(fee_asset(FEE_AMOUNT - 1)?)])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .tx_script(collect_tx_script()?)
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
    } = build_test(true, vec![Some(other_asset(FEE_AMOUNT)?)])?;

    let result = mock_chain
        .build_transaction(network_account.id())
        .authenticated_input_note(feature_notes[0].id())
        .authenticated_input_note(sponsorship_notes[0].id())
        .tx_script(collect_tx_script()?)
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

    let network_account = network_account(Some(feature_note.script().root()))?;
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
        .tx_script(collect_tx_script()?)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_SPONSORSHIP_WRONG_FEATURE_NOTE);

    Ok(())
}

// CREATE NETWORK NOTE SPONSORSHIPS
// ================================================================================================

// `create_network_note_sponsorships` is `exec`-only and must run while the native account is the
// active account, so this test-only component wraps it in an `@account_procedure`. The wrapper
// first creates a storage-less output note targeted at a network account (carrying a
// `NetworkAccountTarget` attachment) and then sponsors the transaction's network notes.
const SPONSORSHIP_CREATOR_NAME: &str = "test::sponsorship_creator";

static SPONSORSHIP_CREATOR_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let src = r#"
        use {NOTE_TYPE_PUBLIC} from miden::protocol::note
        use miden::protocol::note
        use miden::protocol::output_note

        use miden::standards::attachments::network_account_target
        use miden::standards::fees
        use miden::standards::note_tag

        #! Creates a storage-less output note targeted at the given network account, then runs
        #! `create_network_note_sponsorships` to sponsor it.
        #!
        #! Inputs:  [SERIAL_NUM, SCRIPT_ROOT, target_id_suffix, target_id_prefix, pad(6)]
        #! Outputs: [pad(16)]
        #!
        #! Invocation: call
        @account_procedure
        pub proc create_note_and_sponsorships
            push.0.0
            # => [storage_ptr = 0, num_storage_items = 0, SERIAL_NUM, SCRIPT_ROOT,
            #     target_id_suffix, target_id_prefix, pad(6)]

            exec.note::compute_and_store_recipient
            # => [RECIPIENT, target_id_suffix, target_id_prefix, pad(6)]

            push.NOTE_TYPE_PUBLIC dup.6 exec.note_tag::create_account_target
            # => [tag, note_type, RECIPIENT, target_id_suffix, target_id_prefix, pad(6)]

            exec.output_note::create
            # => [note_idx, target_id_suffix, target_id_prefix, pad(6)]

            movdn.2 push.0 movdn.2
            # => [target_id_suffix, target_id_prefix, exec_hint_tag = 0, note_idx, pad(6)]

            exec.network_account_target::new
            # => [attachment_scheme, NOTE_ATTACHMENT, note_idx, pad(6)]

            exec.output_note::add_word_attachment
            # => [pad(16)]

            exec.fees::create_network_note_sponsorships
            # => [pad(16)]
        end
        "#;
    CodeBuilder::default()
        .compile_component_code(SPONSORSHIP_CREATOR_NAME, src)
        .expect("sponsorship creator component should compile")
});

/// The test-only account component exposing the creator wrapper as an account procedure.
fn sponsorship_creator_component() -> anyhow::Result<AccountComponent> {
    Ok(AccountComponent::new(
        SPONSORSHIP_CREATOR_CODE.clone(),
        vec![],
        AccountComponentMetadata::mock(SPONSORSHIP_CREATOR_NAME),
    )?)
}

/// A sponsor account (funded with [`FEE_AMOUNT`] of the fee asset) and a target network account
/// whose fee manager charges [`FEE_AMOUNT`] in the asset of the given faucet, plus the script
/// creating and sponsoring a network note targeted at it.
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

    let sponsor_fee_manager = FeeManager::builder()
        .fee_faucet_id(fee_faucet_id()?)
        .active_fee_policy(ConstantFeePolicy::new().into())
        .build();
    let sponsor = AccountBuilder::new([8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(sponsor_fee_manager)
        .with_component(sponsorship_creator_component()?)
        .with_assets([fee_asset(FEE_AMOUNT)?])
        .build_existing()?;

    let target_policy =
        ConstantFeePolicy::new().with_fee(script_root, AssetAmount::new(FEE_AMOUNT)?);
    let target_fee_manager = FeeManager::builder()
        .fee_faucet_id(target_fee_faucet)
        .active_fee_policy(target_policy.into())
        .build();
    let target = AccountBuilder::new([9; 32])
        .account_type(AccountType::Public)
        .with_auth_component(Auth::IncrNonce)
        .with_component(BasicWallet)
        .with_components(target_fee_manager)
        .build_existing()?;

    let mut builder = MockChain::builder();
    builder.add_account(sponsor.clone())?;
    builder.add_account(target.clone())?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx_script_src = format!(
        r#"
        use test::sponsorship_creator

        @transaction_script
        pub proc main
            # => [pad(16)]

            push.{target_prefix} push.{target_suffix}
            push.{script_root}
            push.{serial_num}
            # => [SERIAL_NUM, SCRIPT_ROOT, target_id_suffix, target_id_prefix, pad(16)]

            call.sponsorship_creator::create_note_and_sponsorships
            # => [pad(16), pad(10)]

            dropw dropw drop drop
            # => [pad(16)]
        end
        "#,
        target_prefix = target.id().prefix().as_felt(),
        target_suffix = target.id().suffix(),
        script_root = script_root.as_word(),
        serial_num = serial_num,
    );
    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&*SPONSORSHIP_CREATOR_CODE)?
        .compile_tx_script(tx_script_src)?;

    let foreign_inputs = mock_chain.get_foreign_account_inputs(target.id())?;

    Ok(CreateTest {
        mock_chain,
        sponsor,
        tx_script,
        foreign_inputs,
    })
}

/// A network note whose target charges its fee in the sponsor's configured fee asset is
/// sponsored: the sponsorship note is funded with the fee from the sponsor's vault.
#[tokio::test]
async fn create_sponsorships_funds_note_in_configured_fee_asset() -> anyhow::Result<()> {
    let CreateTest {
        mock_chain,
        mut sponsor,
        tx_script,
        foreign_inputs,
    } = build_create_test(fee_faucet_id()?)?;

    let executed = mock_chain
        .build_tx_context(sponsor.id(), &[], &[])?
        .foreign_accounts([foreign_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    sponsor.apply_patch(executed.account_patch())?;
    assert_eq!(
        sponsor.vault().get_balance(AssetId::new_fungible(fee_faucet_id()?))?.as_u64(),
        0,
        "the sponsorship note should be funded with the fee from the sponsor's vault"
    );

    Ok(())
}

/// A network note whose target charges a non-zero fee in an asset other than the sponsor's
/// configured fee asset is rejected: fee asset conversion is not supported yet.
#[tokio::test]
async fn create_sponsorships_reject_target_with_different_fee_asset() -> anyhow::Result<()> {
    let CreateTest {
        mock_chain,
        sponsor,
        tx_script,
        foreign_inputs,
    } = build_create_test(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1)?)?;

    let result = mock_chain
        .build_tx_context(sponsor.id(), &[], &[])?
        .foreign_accounts([foreign_inputs])
        .tx_script(tx_script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FEE_MANAGER_TARGET_FEE_ASSET_MISMATCH);

    Ok(())
}
