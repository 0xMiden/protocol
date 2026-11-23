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
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountProcedureRoot,
    AccountType,
    StorageMapKey,
    StorageSlotName,
};
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
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::access::{Authority, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BasicBlocklist,
    BurnPolicy,
    MintPolicy,
    ReceivePolicy,
    SendPolicy,
    TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_ACCOUNT_IS_BLOCKED,
    ERR_PAUSABLE_IS_PAUSED,
    ERR_TRANSFER_POLICY_ROOT_IS_ZERO,
    ERR_TRANSFER_POLICY_ROOT_NOT_ALLOWED,
    ERR_TRANSFER_POLICY_ROOT_NOT_IN_ACCOUNT,
    ERR_TRANSFER_POLICY_ROOTS_EMPTY,
    ERR_TRANSFER_POLICY_ROOTS_NOT_WORD_ALIGNED,
    ERR_TRANSFER_POLICY_ROOTS_TOO_MANY,
};
use miden_standards::note::{MintNote, MintNoteStorage, P2idNote};
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
                .build()?,
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
                .build()?,
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet whose send and receive policies are registered only as reserved
/// alternatives, so the asset callbacks are installed while no policy is active.
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
                .build()?,
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet whose active send and receive policies are each the basic blocklist and
/// the given custom policy.
fn add_faucet_with_multiple_transfer_policies(
    builder: &mut MockChainBuilder,
    blocked_accounts: Vec<AccountId>,
    custom_policies: CustomTransferPolicies,
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
                .active_send_policy(SendPolicy::with_basic_blocklist(blocked_accounts.clone()))
                .active_send_policy(custom_policies.send)
                .active_receive_policy(ReceivePolicy::with_basic_blocklist(blocked_accounts))
                .active_receive_policy(custom_policies.receive)
                .build()?,
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// CUSTOM TRANSFER POLICY FIXTURE
// ================================================================================================

/// The amount the custom receive policy of [`CustomTransferPolicies`] expects.
pub(crate) const TRANSFER_AMOUNT: u64 = 100;

/// The index of the output note the custom send policy of [`CustomTransferPolicies`] expects.
const SEND_NOTE_IDX: u16 = 1;

pub(crate) const ERR_CUSTOM_POLICY_REJECTED: MasmError =
    MasmError::from_static_str("custom transfer policy rejects the transfer");

/// A send and a receive policy that assert their inputs and then accept or reject every transfer.
pub(crate) struct CustomTransferPolicies {
    pub send: SendPolicy,
    pub receive: ReceivePolicy,
}

impl CustomTransferPolicies {
    pub(crate) fn new(accepts: bool) -> anyhow::Result<Self> {
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

/// Returns the commitment to a list of transfer policy roots and its preimage.
fn policy_roots_preimage(roots: &[AccountProcedureRoot]) -> (Word, Vec<Felt>) {
    let elements: Vec<Felt> =
        roots.iter().flat_map(|root| root.as_word().into_elements()).collect();
    (Hasher::hash_elements(&elements), elements)
}

/// Returns the commitment to a list of transfer policy roots.
pub(crate) fn policy_roots_commitment(roots: &[AccountProcedureRoot]) -> Word {
    policy_roots_preimage(roots).0
}

/// Returns the active send and receive policy roots stored by the faucet.
pub(crate) fn active_transfer_policies(faucet: &Account) -> anyhow::Result<(Vec<Word>, Vec<Word>)> {
    let storage = faucet.storage();
    let [num_send_roots, num_receive_roots, ..] = storage
        .get_item(TokenPolicyManager::num_active_transfer_policies_slot())?
        .into_elements();
    let roots = |slot_name: &StorageSlotName, num_roots: Felt| {
        (0..u32::try_from(num_roots.as_canonical_u64())?)
            .map(|index| {
                Ok(storage.get_map_item(slot_name, StorageMapKey::from_array([0, 0, 0, index]))?)
            })
            .collect::<anyhow::Result<Vec<Word>>>()
    };

    Ok((
        roots(TokenPolicyManager::active_send_policies_slot(), num_send_roots)?,
        roots(TokenPolicyManager::active_receive_policies_slot(), num_receive_roots)?,
    ))
}

/// Executes a transaction in which the `sender` consumes the P2ID `note` and moves its asset to a
/// new output note, which invokes the send policy of the faucet that issued the asset.
pub(crate) async fn execute_send(
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

/// Executes a transaction against the faucet in which the transaction script passes the commitment
/// to `elements` to the `set_{kind}_policy_roots_commitment` procedure.
async fn execute_set_transfer_policy_roots(
    mock_chain: &MockChain,
    faucet: AccountId,
    kind: &str,
    elements: Vec<Felt>,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let commitment = Hasher::hash_elements(&elements);
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::standards::faucets::policies::policy_manager

        @transaction_script
        pub proc main
            padw padw padw push.{commitment}
            call.policy_manager::set_{kind}_policy_roots_commitment
            dropw dropw dropw dropw
        end
        "#
    ))?;

    Ok(mock_chain
        .build_transaction(faucet)
        .tx_script(tx_script)
        .add_advice_map_entry(commitment, elements)
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
        .mint_storage(MintNoteStorage::new_private_output(recipient_digest, asset, tag))
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

/// The receive callback reads the issuing faucet's pause flag and active policy roots through FPI,
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

/// With no active receive policy the dispatcher invokes no policy. It must still limit the
/// expiration, otherwise a transfer anchored before `set_receive_policy_roots_commitment` activates
/// a policy would stay valid indefinitely.
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

/// With no active send policy the dispatcher invokes no policy. It must still limit the
/// expiration, otherwise a mint anchored before `set_send_policy_roots_commitment` activates a
/// policy would stay valid indefinitely.
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
                    .build()?,
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

// MULTIPLE POLICIES TESTS
// ================================================================================================

/// A note is accepted only if all active send policies accept it.
#[rstest::rstest]
#[case::all_accept(false, true, None)]
#[case::first_rejects(true, true, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[case::second_rejects(false, false, Some(ERR_CUSTOM_POLICY_REJECTED))]
#[case::both_reject_in_list_order(true, false, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[tokio::test]
async fn all_active_send_policies_must_accept(
    #[case] is_sender_blocked: bool,
    #[case] custom_policy_accepts: bool,
    #[case] expected_error: Option<MasmError>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let sender = builder.add_existing_wallet(Auth::IncrNonce)?;
    let blocked_accounts = Vec::from_iter(is_sender_blocked.then_some(sender.id()));
    // The sender obtains the asset in the same transaction, so no receive policy may be active.
    let faucet = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([49u8; 32])
            .account_type(AccountType::Public)
            .with_component(
                FungibleFaucet::builder()
                    .name(TokenName::new("MRG")?)
                    .symbol("MRG".try_into()?)
                    .decimals(8)
                    .max_supply(AssetAmount::new(1_000_000)?)
                    .build()?,
            )
            .with_component(Authority::AuthControlled)
            .with_components(
                TokenPolicyManager::builder()
                    .active_mint_policy(MintPolicy::allow_all())
                    .active_burn_policy(BurnPolicy::allow_all())
                    .active_send_policy(SendPolicy::with_basic_blocklist(blocked_accounts))
                    .active_send_policy(CustomTransferPolicies::new(custom_policy_accepts)?.send)
                    .build()?,
            ),
        AccountState::Exists,
    )?;

    let asset = FungibleAsset::new(faucet.id(), TRANSFER_AMOUNT)?;
    let note =
        builder.add_p2id_note(faucet.id(), sender.id(), &[Asset::from(asset)], NoteType::Public)?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = execute_send(&mock_chain, sender.id(), &note, asset).await?;

    match expected_error {
        Some(expected_error) => assert_transaction_executor_error!(result, expected_error),
        None => assert_default_expiration_limit(&result?),
    }

    Ok(())
}

/// An asset is accepted only if all active receive policies accept it.
#[rstest::rstest]
#[case::all_accept(false, true, None)]
#[case::first_rejects(true, true, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[case::second_rejects(false, false, Some(ERR_CUSTOM_POLICY_REJECTED))]
#[case::both_reject_in_list_order(true, false, Some(ERR_ACCOUNT_IS_BLOCKED))]
#[tokio::test]
async fn all_active_receive_policies_must_accept(
    #[case] is_receiver_blocked: bool,
    #[case] custom_policy_accepts: bool,
    #[case] expected_error: Option<MasmError>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let receiver = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_multiple_transfer_policies(
        &mut builder,
        Vec::from_iter(is_receiver_blocked.then_some(receiver.id())),
        CustomTransferPolicies::new(custom_policy_accepts)?,
    )?;

    let asset = FungibleAsset::new(faucet.id(), TRANSFER_AMOUNT)?;
    let note = builder.add_p2id_note(
        faucet.id(),
        receiver.id(),
        &[Asset::from(asset)],
        NoteType::Public,
    )?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_transaction(receiver.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![mock_chain.get_foreign_account_inputs(faucet.id())?])
        .build()?
        .execute()
        .await;

    match expected_error {
        Some(expected_error) => assert_transaction_executor_error!(result, expected_error),
        None => assert_default_expiration_limit(&result?),
    }

    Ok(())
}

/// The getter returns the commitment to the active policy roots and inserts them into the advice
/// map, so its output can be passed to the setter.
#[rstest::rstest]
#[case::send("send")]
#[case::receive("receive")]
#[tokio::test]
async fn transfer_policy_getter_output_can_be_passed_to_setter(
    #[case] kind: &str,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let custom_policies = CustomTransferPolicies::new(true)?;
    let faucet = add_faucet_with_multiple_transfer_policies(
        &mut builder,
        vec![],
        CustomTransferPolicies::new(true)?,
    )?;
    let mock_chain = builder.build()?;

    let roots = match kind {
        "send" => [BasicBlocklist::send_root(), custom_policies.send.root()],
        _ => [BasicBlocklist::receive_root(), custom_policies.receive.root()],
    };
    let (commitment, elements) = policy_roots_preimage(&roots);
    let assert_roots_code = roots
        .iter()
        .map(|root| {
            format!(
                r#"padw adv_loadw push.{root}
                assert_eqw.err="advice map holds an unexpected policy root""#,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::standards::faucets::policies::policy_manager

        @transaction_script
        pub proc main
            padw padw padw padw
            call.policy_manager::get_{kind}_policy_roots_commitment
            # => [PROC_ROOTS_COMMITMENT, pad(12)]

            dupw push.{commitment} assert_eqw.err="getter returned an unexpected commitment"
            # => [PROC_ROOTS_COMMITMENT, pad(12)]

            adv.push_mapvaln
            adv_push push.{num_elements} assert_eq.err="advice map holds an unexpected length"
            {assert_roots_code}
            # => [PROC_ROOTS_COMMITMENT, pad(12)]

            call.policy_manager::set_{kind}_policy_roots_commitment
            dropw dropw dropw dropw
        end
        "#,
        num_elements = elements.len(),
    ))?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await?;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_patch(executed.account_patch())?;
    assert_eq!(active_transfer_policies(&updated_faucet)?, active_transfer_policies(&faucet)?);

    Ok(())
}

/// Setting a shorter list replaces the longer one and does not affect the list of the other kind.
#[rstest::rstest]
#[case::send("send")]
#[case::receive("receive")]
#[tokio::test]
async fn set_transfer_policy_roots_replaces_longer_list(#[case] kind: &str) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let custom_policies = CustomTransferPolicies::new(true)?;
    let custom_send_root = custom_policies.send.root();
    let custom_receive_root = custom_policies.receive.root();
    let faucet = add_faucet_with_multiple_transfer_policies(&mut builder, vec![], custom_policies)?;
    let mock_chain = builder.build()?;

    let (mut expected_send_roots, mut expected_receive_roots) = active_transfer_policies(&faucet)?;
    let new_root = match kind {
        "send" => {
            expected_send_roots = vec![custom_send_root.as_word()];
            custom_send_root
        },
        _ => {
            expected_receive_roots = vec![custom_receive_root.as_word()];
            custom_receive_root
        },
    };

    let (_, elements) = policy_roots_preimage(&[new_root]);
    let executed =
        execute_set_transfer_policy_roots(&mock_chain, faucet.id(), kind, elements).await??;

    let mut updated_faucet = faucet.clone();
    updated_faucet.apply_patch(executed.account_patch())?;
    assert_eq!(
        active_transfer_policies(&updated_faucet)?,
        (expected_send_roots, expected_receive_roots)
    );

    Ok(())
}

/// The setters and getters support a list of the maximum length.
#[rstest::rstest]
#[case::send("send", BasicBlocklist::send_root())]
#[case::receive("receive", BasicBlocklist::receive_root())]
#[tokio::test]
async fn transfer_policies_support_max_number_of_roots(
    #[case] kind: &str,
    #[case] root: AccountProcedureRoot,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_multiple_transfer_policies(
        &mut builder,
        vec![],
        CustomTransferPolicies::new(true)?,
    )?;
    let mock_chain = builder.build()?;

    let roots = [root; TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES];
    let (commitment, elements) = policy_roots_preimage(&roots);
    let tx_script = CodeBuilder::default().compile_tx_script(format!(
        r#"
        use miden::standards::faucets::policies::policy_manager

        @transaction_script
        pub proc main
            padw padw padw push.{commitment}
            call.policy_manager::set_{kind}_policy_roots_commitment
            # => [pad(16)]

            call.policy_manager::get_{kind}_policy_roots_commitment
            # => [PROC_ROOTS_COMMITMENT, pad(12)]

            push.{commitment} assert_eqw.err="getter returned an unexpected commitment"
            dropw dropw dropw
        end
        "#
    ))?;

    mock_chain
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .add_advice_map_entry(commitment, elements)
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// The setters reject lists that are malformed or contain a root that may not be activated. The
/// valid root at the start of most lists ensures that every root is validated.
#[rstest::rstest]
#[case::empty_list(|_| vec![], ERR_TRANSFER_POLICY_ROOTS_EMPTY)]
#[case::unaligned_list(
    |valid_root: Word| [valid_root.as_elements(), &[Felt::ONE]].concat(),
    ERR_TRANSFER_POLICY_ROOTS_NOT_WORD_ALIGNED
)]
#[case::too_many_roots(
    |valid_root: Word| {
        vec![valid_root; TokenPolicyManager::MAX_NUM_ACTIVE_TRANSFER_POLICIES + 1]
            .into_iter()
            .flatten()
            .collect()
    },
    ERR_TRANSFER_POLICY_ROOTS_TOO_MANY
)]
#[case::empty_word(
    |valid_root: Word| [valid_root, Word::empty()].map(Word::into_elements).concat(),
    ERR_TRANSFER_POLICY_ROOT_IS_ZERO
)]
#[case::not_in_account(
    |valid_root: Word| [valid_root, Word::from([1, 2, 3, 4u32])].map(Word::into_elements).concat(),
    ERR_TRANSFER_POLICY_ROOT_NOT_IN_ACCOUNT
)]
#[case::not_allowed(
    |valid_root: Word| {
        let not_allowed_root = TokenPolicyManager::set_mint_policy_root().as_word();
        [valid_root, not_allowed_root].map(Word::into_elements).concat()
    },
    ERR_TRANSFER_POLICY_ROOT_NOT_ALLOWED
)]
#[tokio::test]
async fn set_transfer_policy_roots_rejects_invalid_list(
    #[values("send", "receive")] kind: &str,
    #[case] build_elements: fn(Word) -> Vec<Felt>,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_multiple_transfer_policies(
        &mut builder,
        vec![],
        CustomTransferPolicies::new(true)?,
    )?;
    let mock_chain = builder.build()?;

    let valid_root = match kind {
        "send" => BasicBlocklist::send_root(),
        _ => BasicBlocklist::receive_root(),
    };
    let elements = build_elements(valid_root.as_word());
    let result =
        execute_set_transfer_policy_roots(&mock_chain, faucet.id(), kind, elements).await?;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}
