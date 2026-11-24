//! Helpers shared by the sibling `blocklist` and `allowlist` transfer policy suites, plus the
//! tests for the policy-manager dispatcher itself.
//!
//! Both suites exercise the same two shapes: a faucet that can also *receive* a foreign faucet's
//! asset (so it is subject to that faucet's transfer policy), and a mint driven through the
//! standard [`MintNote`] (so the send policy is reached the way production code reaches it).

extern crate alloc;

use alloc::vec;

use anyhow::Context;
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
use miden_protocol::errors::tx_kernel::ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_COMMITMENT_WITHOUT_ATTACHMENTS;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{Authority, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    AllowlistStorage,
    BurnPolicy,
    MintPolicy,
    ReceivePolicy,
    SendPolicy,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{ERR_ACCOUNT_IS_BLOCKED, ERR_PAUSABLE_IS_PAUSED};
use miden_standards::note::{MintNote, MintNoteStorage, P2idNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;

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

/// Builds a fungible faucet with asset callbacks enabled and [`SendPolicy::allow_all`] and
/// [`ReceivePolicy::allow_all`] active.
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
                .active_send_policy(SendPolicy::allow_all())
                .active_receive_policy(ReceivePolicy::allow_all())
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
                .allowed_send_policy(SendPolicy::allow_all())
                .allowed_receive_policy(ReceivePolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet with the given active send and receive policies.
fn add_faucet_with_transfer_policies(
    builder: &mut MockChainBuilder,
    send_policy: SendPolicy,
    receive_policy: ReceivePolicy,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("MRG")?)
        .symbol("MRG".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([48u8; 32])
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(send_policy)
                .active_receive_policy(receive_policy)
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// CUSTOM TRANSFER POLICY FIXTURE
// ================================================================================================

/// The amount the custom receive policy of [`CustomTransferPolicies`] expects.
const TRANSFER_AMOUNT: u64 = 100;

/// The index of the output note the custom send policy of [`CustomTransferPolicies`] expects.
const SEND_NOTE_IDX: u16 = 1;

const ERR_CUSTOM_POLICY_REJECTED: MasmError =
    MasmError::from_static_str("custom transfer policy rejects the transfer");

/// A send and a receive policy that assert their inputs and then accept or reject every transfer.
struct CustomTransferPolicies {
    send: SendPolicy,
    receive: ReceivePolicy,
}

impl CustomTransferPolicies {
    fn new(accepts: bool) -> anyhow::Result<Self> {
        let component_name = "tests::custom_transfer_policy";
        let accepts = u8::from(accepts);
        let rejection_error = ERR_CUSTOM_POLICY_REJECTED;
        let error = rejection_error.message();
        let code = CodeBuilder::default().compile_component_code(
            component_name,
            format!(
                r#"
                #! Inputs:  [note_idx, pad(15)]
                #! Outputs: [pad(16)]
                @account_procedure
                pub proc check_send_policy
                    push.{SEND_NOTE_IDX} assert_eq.err="unexpected note index"
                    push.{accepts} assert.err="{error}"
                end

                #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
                #! Outputs: [pad(16)]
                @account_procedure
                pub proc check_receive_policy
                    dropw push.0.0.0.{TRANSFER_AMOUNT}
                    assert_eqw.err="unexpected asset value"
                    push.{accepts} assert.err="{error}"
                end
                "#
            ),
        )?;
        let component =
            AccountComponent::new(code, vec![], AccountComponentMetadata::mock(component_name))?;
        let procedure_root = |name: &str| {
            component
                .get_procedure_root_by_path(format!("{component_name}::{name}").as_str())
                .with_context(|| format!("procedure {name} should exist"))
        };

        Ok(Self {
            send: SendPolicy::custom(procedure_root("check_send_policy")?, [component.clone()])?,
            receive: ReceivePolicy::custom(
                procedure_root("check_receive_policy")?,
                [component.clone()],
            )?,
        })
    }
}

/// Executes a transaction in which the `sender` consumes the P2ID `note` and moves its asset to a
/// new output note, which invokes the send policy of the faucet that issued the asset.
async fn execute_send(
    mock_chain: &MockChain,
    sender: AccountId,
    note: &Note,
    asset: FungibleAsset,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let asset = Asset::from(asset);
    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
        r#"
        use miden::protocol::output_note
        use mock::util

        @transaction_script
        pub proc main
            # note 0 holds no assets, so the send policy is only invoked for note 1
            exec.util::create_default_note exec.output_note::seal
            # => []

            exec.util::create_default_note
            # => [note_idx]

            push.{asset_value} push.{asset_id} dup.8 movdn.8
            # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx]

            exec.util::move_asset_to_note exec.output_note::seal
            # => []
        end
        "#,
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    ))?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(asset.faucet_id())?;
    Ok(mock_chain
        .build_transaction(sender)
        .authenticated_input_note(note.id())
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await)
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
    let note = build_mint_note_for(sender, &output_note, rng_seed)?;

    Ok(MintNoteFixture { note, asset, recipient_digest })
}

/// Builds a MINT note, created by `sender`, instructing the faucet to mint `output_note`. For a
/// public output note, the MINT note holds the output note's recipient; for a private one, only its
/// recipient digest.
pub(crate) fn build_mint_note_for(
    sender: AccountId,
    output_note: &Note,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let asset = *output_note.assets().iter().next().context("output note should hold an asset")?;
    let tag = output_note.metadata().tag();
    let mint_storage = match output_note.metadata().note_type() {
        NoteType::Public => {
            MintNoteStorage::new_public_output(output_note.recipient().clone(), asset, tag)?
        },
        NoteType::Private => {
            MintNoteStorage::new_private_output(output_note.recipient().digest(), asset, tag)
        },
    };

    let mut rng = EidosRandomCoin::new([Felt::from(rng_seed); 4].into());
    Ok(MintNote::builder()
        .sender(sender)
        .mint_storage(mint_storage)
        .generate_serial_number(&mut rng)
        .build()?
        .into())
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

// NOTE SEALING FIXTURE
// ================================================================================================

/// The index of the note that the send policy tests, such as [`execute_note_sealing_tx`], seal
/// through the send policy.
///
/// It is not 0, so that a send policy that returns the note index on top of its outputs returns a
/// non-zero number of attachments.
pub(crate) const SEALED_NOTE_IDX: usize = 1;

/// Builds a custom send policy that returns no attachments together with the provided attachment
/// list commitment, which the kernel accepts only if it is the empty word.
fn custom_send_policy(attachment_list_commitment: Word) -> anyhow::Result<SendPolicy> {
    let component_name = "tests::attachment_send_policy";
    let policy_code = CodeBuilder::default().compile_component_code(
        component_name,
        format!(
            "
            #! Inputs:  [note_idx, pad(15)]
            #! Outputs: [0, ATTACHMENT_LIST_COMMITMENT, pad(11)]
            @account_procedure
            pub proc check_send_policy
                drop
                # => [pad(16)]

                push.{attachment_list_commitment} push.0
                exec.::miden::core::sys::truncate_stack
                # => [0, ATTACHMENT_LIST_COMMITMENT, pad(11)]
            end
            "
        ),
    )?;
    let policy_component =
        AccountComponent::new(policy_code, vec![], AccountComponentMetadata::mock(component_name))?;
    let policy_root = policy_component
        .get_procedure_root_by_path(format!("{component_name}::check_send_policy").as_str())
        .expect("send policy procedure should exist");

    Ok(SendPolicy::custom(policy_root, [policy_component])?)
}

/// Executes a transaction in which an account holding an asset of a faucet creates and seals an
/// empty note, then creates a private note at [`SEALED_NOTE_IDX`], adds a single-word attachment to
/// it, moves the asset into it and seals it.
///
/// The faucet activates the send policy that `send_policy` returns for the ID of the note's
/// creator, if any. It also registers [`SendPolicy::allow_all`] as a reserved alternative, so the
/// send callback is installed even when no send policy is active.
///
/// Returns the note as the transaction script creates it and the execution result.
async fn execute_note_sealing_tx(
    send_policy: impl FnOnce(AccountId) -> anyhow::Result<Option<SendPolicy>>,
) -> anyhow::Result<(Note, Result<ExecutedTransaction, TransactionExecutorError>)> {
    let mut builder = MockChain::builder();
    // the sender is created before the faucet so that the send policy can name it
    let mut sender = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let sender_id = sender.id();

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("ATT")?)
        .symbol("ATT".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;
    let faucet = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([48u8; 32])
            .account_type(AccountType::Public)
            .with_component(faucet)
            .with_component(Authority::AuthControlled)
            .with_components(
                TokenPolicyManager::builder()
                    .active_mint_policy(MintPolicy::allow_all())
                    .active_burn_policy(BurnPolicy::allow_all())
                    .maybe_active_send_policy(send_policy(sender_id)?)
                    .allowed_send_policy(SendPolicy::allow_all())
                    .build(),
            ),
        AccountState::Exists,
    )?;

    let asset = Asset::from(FungibleAsset::new(faucet.id(), 100)?);
    sender.vault_mut().add_asset(asset)?;
    builder.add_account(sender)?;
    let mock_chain = builder.build()?;

    let creator_attachment =
        NoteAttachment::with_word(NoteAttachmentScheme::new(10)?, Word::from([1, 2, 3, 4u32]));
    let note = NoteBuilder::new(sender_id, EidosRandomCoin::new(Word::empty()))
        .note_type(NoteType::Private)
        .add_assets([asset])
        .attachment(creator_attachment.clone())
        .build()?;

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
        "
        use miden::protocol::output_note
        use mock::util

        @transaction_script
        pub proc main
            # note 0 holds no assets
            exec.util::create_default_note exec.output_note::seal
            # => []

            push.{recipient} push.{note_type} push.{tag}
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            push.{asset_value} push.{asset_id} dup.8 movdn.8
            # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx, pad(15)]

            exec.util::move_asset_to_note
            # => [note_idx, pad(15)]

            dup push.{attachment_word} push.{attachment_scheme}
            # => [attachment_scheme, ATTACHMENT, note_idx, note_idx, pad(15)]

            exec.output_note::add_word_attachment
            # => [note_idx, pad(15)]

            exec.output_note::seal
            # => [pad(15)]

            exec.::miden::core::sys::truncate_stack
        end
        ",
        recipient = note.recipient().digest(),
        note_type = note.metadata().note_type() as u8,
        tag = note.metadata().tag(),
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
        attachment_word = creator_attachment.content().as_words()[0],
        attachment_scheme = creator_attachment.attachment_scheme().as_u16(),
    ))?;

    let result = mock_chain
        .build_transaction(sender_id)
        .tx_script(tx_script)
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(faucet.id())?])
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await;

    Ok((note, result))
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
/// and expiration limit and then invokes the active send policy with the note index. The policy
/// reads the note's assets itself and inspects the ones issued by its faucet.
///
/// The note holds a fungible and a non-fungible asset of the faucet, separated by an asset of
/// another faucet. The policy asserts the note index and, in the rejecting cases, rejects the
/// faucet's non-fungible assets, so the transaction fails whether that asset comes first or last.
#[rstest::rstest]
#[case::accepted(false, false)]
#[case::last_asset_rejected(true, false)]
#[case::first_asset_rejected(true, true)]
#[tokio::test]
async fn send_policy_inspects_the_faucet_assets_of_the_note(
    #[case] reject_non_fungible: bool,
    #[case] non_fungible_first: bool,
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
        String::from("nop")
    };
    let policy_code = CodeBuilder::default().compile_component_code(
        component_name,
        format!(
            r#"
            use miden::protocol::account_id
            use miden::protocol::active_account
            use miden::protocol::asset
            use miden::protocol::output_note
            use {{ASSET_SIZE, COMPOSITION_NONE}} from miden::protocol::asset

            #! Inputs:  [note_idx, pad(15)]
            #! Outputs: [pad(16)]
            @locals(128)
            @account_procedure
            pub proc check_send_policy
                dup push.{NOTE_IDX} assert_eq.err="send policy received an unexpected note index"
                # => [note_idx, pad(15)]

                locaddr.0 exec.output_note::get_assets
                # => [num_assets, pad(15)]

                mul.ASSET_SIZE locaddr.0 dup movdn.2 add swap
                # => [asset_ptr, assets_end_ptr, pad(15)]

                dup dup.2 neq
                while.true
                    dup exec.asset::load
                    # => [ASSET_ID, ASSET_VALUE, asset_ptr, assets_end_ptr, pad(15)]

                    exec.asset::id_to_faucet_id exec.active_account::get_id exec.account_id::eq
                    # => [is_own_asset, ASSET_ID, ASSET_VALUE, asset_ptr, assets_end_ptr, pad(15)]

                    if.true
                        {composition_check}
                    end
                    # => [ASSET_ID, ASSET_VALUE, asset_ptr, assets_end_ptr, pad(15)]

                    dropw dropw add.ASSET_SIZE
                    # => [asset_ptr, assets_end_ptr, pad(15)]

                    dup dup.2 neq
                end
                # => [asset_ptr, assets_end_ptr, pad(15)]

                drop drop
                # => [pad(16)]
            end
            "#
        ),
    )?;
    let policy_component =
        AccountComponent::new(policy_code, vec![], AccountComponentMetadata::mock(component_name))?;
    let policy_root = policy_component
        .get_procedure_root_by_path(format!("{component_name}::check_send_policy").as_str())
        .expect("send policy procedure should exist");
    let send_policy = SendPolicy::custom(policy_root, [policy_component])?;

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

    let fungible = Asset::from(FungibleAsset::new(faucet.id(), 100)?);
    let other_faucet_asset = Asset::from(FungibleAsset::new(other_faucet.id(), 50)?);
    let non_fungible =
        Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet.id(), vec![1, 2])));
    let note_assets = if non_fungible_first {
        [non_fungible, other_faucet_asset, fungible]
    } else {
        [fungible, other_faucet_asset, non_fungible]
    };
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

/// A send policy that returns no attachment, including each bundled send policy, and a faucet
/// without an active send policy leave the sealed note as its creator built it.
#[rstest::rstest]
#[case::custom(|_| custom_send_policy(Word::empty()).map(Some))]
#[case::allow_all(|_| Ok(Some(SendPolicy::allow_all())))]
#[case::basic_blocklist(|_| Ok(Some(SendPolicy::empty_basic_blocklist())))]
#[case::basic_allowlist(|sender| {
    Ok(Some(SendPolicy::with_basic_allowlist(AllowlistStorage::with_allowed_accounts([sender]))))
})]
#[case::supply_restriction(|_| Ok(Some(SendPolicy::empty_supply_restriction())))]
#[case::merged(|_| {
    Ok(Some(SendPolicy::merge([SendPolicy::allow_all(), SendPolicy::empty_basic_blocklist()])?))
})]
#[case::no_active_policy(|_| Ok(None))]
#[tokio::test]
async fn send_policy_without_attachment_leaves_the_note_unchanged(
    #[case] send_policy: fn(AccountId) -> anyhow::Result<Option<SendPolicy>>,
) -> anyhow::Result<()> {
    let (note, result) = execute_note_sealing_tx(send_policy).await?;
    let executed = result?;

    let output_note = executed.output_notes().get_note(SEALED_NOTE_IDX);
    assert_eq!(output_note.attachments(), note.attachments());
    assert_eq!(output_note.id(), note.id());

    Ok(())
}

/// The kernel validates the send policy's outputs, so a send policy that returns no attachments
/// with a non-empty attachment list commitment fails the transaction.
#[tokio::test]
async fn send_policy_list_commitment_without_attachments_fails() -> anyhow::Result<()> {
    let (_, result) =
        execute_note_sealing_tx(|_| custom_send_policy(Word::from([5, 6, 7, 8u32])).map(Some))
            .await?;

    assert_transaction_executor_error!(
        result,
        ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_COMMITMENT_WITHOUT_ATTACHMENTS
    );

    Ok(())
}

// MERGED POLICIES TESTS
// ================================================================================================

/// The policy that is merged in [`all_merged_policies_must_accept`].
#[derive(Debug, Clone, Copy)]
enum MergedPolicy {
    Send,
    Receive,
}

/// A merged policy accepts a transfer only if all merged policies accept it.
///
/// The transaction receives and then sends the asset, so it invokes both the send and the receive
/// policy. The policy that is not merged accepts every transfer.
#[rstest::rstest]
#[case::all_accept(true, true, None)]
#[case::first_rejects(false, true, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[case::second_rejects(true, false, Some(ERR_CUSTOM_POLICY_REJECTED))]
#[case::both_reject_in_order(false, false, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[tokio::test]
async fn all_merged_policies_must_accept(
    #[values(MergedPolicy::Send, MergedPolicy::Receive)] merged_policy: MergedPolicy,
    #[case] blocklist_accepts: bool,
    #[case] custom_policy_accepts: bool,
    #[case] expected_error: Option<MasmError>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let blocked_accounts = (!blocklist_accepts).then_some(account.id());
    let custom_policies = CustomTransferPolicies::new(custom_policy_accepts)?;

    let mut send_policy = SendPolicy::allow_all();
    let mut receive_policy = ReceivePolicy::allow_all();
    match merged_policy {
        MergedPolicy::Send => {
            send_policy = SendPolicy::merge([
                SendPolicy::with_basic_blocklist(blocked_accounts),
                custom_policies.send,
            ])?;
        },
        MergedPolicy::Receive => {
            receive_policy = ReceivePolicy::merge([
                ReceivePolicy::with_basic_blocklist(blocked_accounts),
                custom_policies.receive,
            ])?;
        },
    }
    let faucet = add_faucet_with_transfer_policies(&mut builder, send_policy, receive_policy)?;

    let asset = FungibleAsset::new(faucet.id(), TRANSFER_AMOUNT)?;
    let note = builder.add_p2id_note(
        faucet.id(),
        account.id(),
        &[Asset::from(asset)],
        NoteType::Public,
    )?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = execute_send(&mock_chain, account.id(), &note, asset).await?;

    match expected_error {
        Some(expected_error) => assert_transaction_executor_error!(result, expected_error),
        None => assert_default_expiration_limit(&result?),
    }

    Ok(())
}
