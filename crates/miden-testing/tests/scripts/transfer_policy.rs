//! Helpers shared by the sibling `blocklist` and `allowlist` transfer policy suites, plus the
//! tests for the policy-manager dispatcher itself.
//!
//! Both suites exercise the same two shapes: a faucet that can also *receive* a foreign faucet's
//! asset (so it is subject to that faucet's transfer policy), and a mint driven through the
//! standard [`MintNote`] (so the send policy is reached the way production code reaches it).

extern crate alloc;

use alloc::vec;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId, AccountType};
use miden_protocol::asset::{
    Asset,
    AssetAmount,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::crypto::rand::EidosRandomCoin;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::ERR_PAUSABLE_IS_PAUSED;
use miden_standards::note::{MintNote, MintNoteStorage, P2idNote};
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

use super::assert_default_expiration_limit;

// FAUCET FIXTURES
// ================================================================================================

/// Builds a fungible faucet that can also receive assets (via [`BasicWallet`]), so it can be the
/// recipient of a *foreign* faucet's asset and thus be subject to that faucet's transfer policy.
///
/// Its own asset callbacks are disabled: this faucet is never the issuer under test.
pub(crate) fn add_faucet_with_wallet(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("OTH")?)
        .symbol("OTH".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([44u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet with asset callbacks enabled and [`TransferPolicy::allow_all`] active
/// on both send and receive.
fn add_faucet_with_allow_all_transfer(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("ALL")?)
        .symbol("ALL".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::allow_all())
                .active_receive_policy(TransferPolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet whose send and receive policies are registered only as reserved
/// alternatives, so the asset callbacks are installed while both active roots are empty.
fn add_faucet_with_reserved_only_transfer(
    builder: &mut MockChainBuilder,
    pausable: Pausable,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("RSV")?)
        .symbol("RSV".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([46u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_component(pausable)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .allowed_send_policy(TransferPolicy::allow_all())
                .allowed_receive_policy(TransferPolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// MINT NOTE FIXTURE
// ================================================================================================

/// A [`MintNote`] together with what the faucet is expected to emit when it consumes the note.
pub(crate) struct MintNoteFixture {
    /// The MINT note to consume against the faucet.
    pub note: Note,
    /// The asset the faucet is expected to mint.
    pub asset: FungibleAsset,
    /// The recipient digest of the output note the faucet is expected to create.
    pub recipient_digest: Word,
}

/// Builds a MINT note instructing `faucet_id` to mint `amount` units of its own asset into a
/// private P2ID note for `target`.
///
/// This replaces a hand-written `mint_and_send` transaction script: the mint runs through the
/// standard MINT note, and minting is what crosses the send transfer policy, since the MINT note
/// seals the output note holding the minted asset while the faucet is itself the native account.
pub(crate) fn build_mint_note(
    sender: AccountId,
    faucet_id: AccountId,
    target: AccountId,
    amount: u64,
    rng_seed: u32,
) -> anyhow::Result<MintNoteFixture> {
    let asset = FungibleAsset::new(faucet_id, amount)?;
    let tag = NoteTag::with_account_target(target);

    let output_note = Note::from(
        P2idNote::builder()
            .sender(faucet_id)
            .target(target)
            .assets(vec![asset])
            .note_type(NoteType::Private)
            .serial_number(Word::default())
            .build()?,
    );
    let recipient_digest = output_note.recipient().digest();

    let mut rng = EidosRandomCoin::new([Felt::from(rng_seed); 4].into());
    let note: Note = MintNote::builder()
        .sender(sender)
        .mint_storage(MintNoteStorage::new_private(recipient_digest, asset, tag))
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    Ok(MintNoteFixture { note, asset, recipient_digest })
}

/// Asserts that `executed` created exactly one output note, addressed to the recipient the MINT
/// note named, carrying exactly the minted asset.
pub(crate) fn assert_minted_note(
    executed: &ExecutedTransaction,
    mint: &MintNoteFixture,
) -> anyhow::Result<()> {
    assert_eq!(executed.output_notes().num_notes(), 1);

    let note = executed.output_notes().get_note(0);
    assert_eq!(note.recipient_digest(), mint.recipient_digest);

    let expected_asset: Asset = mint.asset.into();
    assert_eq!(note.assets().num_assets(), 1);
    assert_eq!(note.assets().iter().next(), Some(&expected_asset));

    Ok(())
}

// DISPATCHER TESTS
// ================================================================================================

/// The receive callback reads the issuing faucet's pause flag and active policy root through FPI,
/// which reflects the executor-chosen reference block. The dispatcher must therefore limit the
/// transaction's expiration even when the active policy sets no limit of its own.
#[tokio::test]
async fn receive_callback_applies_default_expiration_limit() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_allow_all_transfer(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let note =
        builder.add_p2id_note(faucet.id(), target.id(), &[Asset::from(asset)], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let executed = mock_chain
        .build_transaction(target.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    assert_default_expiration_limit(&executed);

    Ok(())
}

#[tokio::test]
async fn send_callback_applies_default_expiration_limit() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_allow_all_transfer(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mint = build_mint_note(target.id(), faucet.id(), target.id(), 100, 11)?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(mint.note.clone())
        .build()?
        .execute()
        .await?;

    assert_minted_note(&executed, &mint)?;
    assert_default_expiration_limit(&executed);

    Ok(())
}

/// With no active receive policy the dispatcher takes the empty-root branch. It must still limit
/// the expiration, otherwise a transfer anchored before `set_receive_policy` activates a policy
/// would stay valid indefinitely.
#[tokio::test]
async fn receive_callback_applies_default_expiration_limit_without_active_policy()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_reserved_only_transfer(&mut builder, Pausable::unpaused())?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let note =
        builder.add_p2id_note(faucet.id(), target.id(), &[Asset::from(asset)], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let executed = mock_chain
        .build_transaction(target.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    assert_default_expiration_limit(&executed);

    Ok(())
}

/// With no active send policy the dispatcher takes the empty-root branch. It must still limit the
/// expiration, otherwise a mint anchored before `set_send_policy` activates a policy would stay
/// valid indefinitely.
#[tokio::test]
async fn send_callback_applies_default_expiration_limit_without_active_policy() -> anyhow::Result<()>
{
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_reserved_only_transfer(&mut builder, Pausable::unpaused())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mint = build_mint_note(target.id(), faucet.id(), target.id(), 100, 12)?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(mint.note.clone())
        .build()?
        .execute()
        .await?;

    assert_minted_note(&executed, &mint)?;
    assert_default_expiration_limit(&executed);

    Ok(())
}

/// The pause flag is account-wide, so a paused faucet must reject transfers of its asset even
/// when no receive policy is active.
#[tokio::test]
async fn receive_callback_rejects_paused_faucet_without_active_policy() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_reserved_only_transfer(&mut builder, Pausable::paused())?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let note =
        builder.add_p2id_note(faucet.id(), target.id(), &[Asset::from(asset)], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_IS_PAUSED);

    Ok(())
}

/// Sealing a note invokes the issuing faucet's send callback once, which applies the pause check
/// and expiration limit and then invokes the active send policy for each of the faucet's assets in
/// the note, with the note index as `custom_data`. Assets of other faucets are skipped.
///
/// The note holds a fungible and a non-fungible asset of the faucet, separated by an asset of
/// another faucet. The policy asserts its inputs and, in the rejecting case, rejects non-fungible
/// assets, so the transaction fails only if the policy also runs for the faucet's second asset.
#[rstest::rstest]
#[case::accepted(false)]
#[case::second_asset_rejected(true)]
#[tokio::test]
async fn send_callback_applies_policy_to_each_asset_of_the_faucet(
    #[case] reject_non_fungible: bool,
) -> anyhow::Result<()> {
    const NOTE_IDX: u16 = 1;
    const ERR_NON_FUNGIBLE_ASSET_REJECTED: MasmError =
        MasmError::from_static_str("send policy rejects non-fungible assets");

    let component_name = "tests::send_policy";
    let composition_check = if reject_non_fungible {
        format!(
            "exec.asset::id_to_composition neq.COMPOSITION_NONE
            assert.err=\"{}\"",
            ERR_NON_FUNGIBLE_ASSET_REJECTED.message()
        )
    } else {
        String::new()
    };
    let policy_code = CodeBuilder::default().compile_component_code(
        component_name,
        format!(
            r#"
            use miden::protocol::account_id
            use miden::protocol::active_account
            use miden::protocol::asset
            use {{COMPOSITION_NONE}} from miden::protocol::asset

            #! Inputs:  [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]
            #! Outputs: [pad(16)]
            @account_procedure
            pub proc check_policy
                dup.8 push.{NOTE_IDX} assert_eq.err="send policy received an unexpected note index"
                # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

                exec.asset::id_to_faucet_id exec.active_account::get_id exec.account_id::eq
                assert.err="send policy received an asset of another faucet"
                # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

                {composition_check}
                # => [ASSET_ID, ASSET_VALUE, note_idx, pad(7)]

                dropw dropw drop
                # => [pad(16)]
            end
            "#
        ),
    )?;
    let policy_component =
        AccountComponent::new(policy_code, vec![], AccountComponentMetadata::mock(component_name))?;
    let policy_root = policy_component
        .get_procedure_root_by_path(format!("{component_name}::check_policy").as_str())
        .expect("send policy procedure should exist");
    let send_policy = TransferPolicy::custom(policy_root, [policy_component])?;

    let mut builder = MockChain::builder();
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SND")?)
        .symbol("SND".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;
    let faucet = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([47u8; 32])
            .account_type(AccountType::Public)
            .with_component(faucet)
            .with_component(Authority::AuthControlled)
            .with_components(
                TokenPolicyManager::builder()
                    .active_mint_policy(MintPolicy::allow_all())
                    .active_burn_policy(BurnPolicy::allow_all())
                    .active_send_policy(send_policy)
                    .build(),
            ),
        AccountState::Exists,
    )?;
    let other_faucet = add_faucet_with_wallet(&mut builder)?;

    let note_assets = [
        Asset::from(FungibleAsset::new(faucet.id(), 100)?),
        Asset::from(FungibleAsset::new(other_faucet.id(), 50)?),
        Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet.id(), vec![1, 2]))),
    ];
    let sender = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, note_assets)?;
    let mock_chain = builder.build()?;

    let move_assets_code = note_assets
        .iter()
        .map(|asset| {
            format!(
                "push.{asset_value} push.{asset_id} dup.8 movdn.8
                # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx]

                exec.util::move_asset_to_note
                # => [note_idx]",
                asset_value = asset.to_value_word(),
                asset_id = asset.to_id_word(),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
        r#"
        use miden::protocol::output_note
        use mock::util

        @transaction_script
        pub proc main
            # note 0 holds no assets
            exec.util::create_default_note exec.output_note::seal
            # => []

            exec.util::create_default_note
            # => [note_idx]

            {move_assets_code}

            exec.output_note::seal
            # => []
        end
        "#
    ))?;

    let result = mock_chain
        .build_transaction(sender.id())
        .tx_script(tx_script)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(faucet.id())?])
        .build()?
        .execute()
        .await;

    if reject_non_fungible {
        assert_transaction_executor_error!(result, ERR_NON_FUNGIBLE_ASSET_REJECTED);
    } else {
        let executed = result?;
        assert_eq!(
            executed.output_notes().get_note(usize::from(NOTE_IDX)).assets().num_assets(),
            3
        );
        assert_default_expiration_limit(&executed);
    }

    Ok(())
}
