extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use miden_processor::ExecutionError;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentCode,
    AccountId,
    AccountIdVersion,
    AccountProcedureRoot,
    AccountType,
    AssetCallbackFlag,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{
    Asset,
    AssetAmount,
    AssetCallbacks,
    AssetComposition,
    AssetVault,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::crypto::rand::EidosRandomCoin;
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::{
    ERR_KERNEL_STATE_MUTATION_IN_ASSET_CALLBACK,
    ERR_OUTPUT_NOTE_ATTACHMENT_SCHEME_CANNOT_BE_ZERO,
    ERR_OUTPUT_NOTE_ATTACHMENT_SCHEME_MAX_EXCEEDED,
    ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_COMMITMENT_WITHOUT_ATTACHMENTS,
    ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_LENGTH_MISMATCH,
    ERR_OUTPUT_NOTE_CALLBACK_TOO_MANY_ATTACHMENTS,
    ERR_OUTPUT_NOTE_IS_SEALED,
    ERR_OUTPUT_NOTE_TOO_MANY_ATTACHMENTS,
    ERR_PROLOGUE_CALLBACK_SLOT_REQUIRES_ENABLED_ASSET_CALLBACK_FLAG,
};
use miden_protocol::note::{
    Note,
    NoteAttachment,
    NoteAttachmentScheme,
    NoteAttachments,
    NoteTag,
    NoteType,
};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Hasher, WORD_SIZE, Word};
use miden_standards::account::access::{Authority, Pausable};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::procedure_root;
use miden_standards::testing::account_component::MockFaucetComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::{LocalTransactionProver, TransactionExecutorError, TransactionKernelError};

use crate::{AccountState, Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};

// CONSTANTS
// ================================================================================================

/// MASM code for the BlockList callback component.
///
/// This procedure checks whether the native account (the one receiving the asset) is in a
/// block list stored in a storage map. If the account is blocked, the callback panics.
const BLOCK_LIST_MASM: &str = r#"
use miden::protocol::active_account
use miden::protocol::native_account
use miden::core::word

const BLOCK_LIST_MAP_SLOT = word("miden::testing::callbacks::block_list")
const ERR_ACCOUNT_BLOCKED = "the account is blocked and cannot receive this asset"

#! Asserts that the native account is not in the block list.
#!
#! Inputs:  []
#! Outputs: []
#!
#! Panics if the native account is in the block list.
#!
#! Invocation: exec
proc assert_native_account_not_blocked
    # Get the native account ID
    exec.native_account::get_id
    # => [native_acct_suffix, native_acct_prefix]

    # Build account ID map key: [0, 0, suffix, prefix]
    push.0.0
    # => [ACCOUNT_ID_KEY]

    # Look up in block list storage map
    push.BLOCK_LIST_MAP_SLOT[0..2]
    exec.active_account::get_map_item
    # => [IS_BLOCKED]

    # If IS_BLOCKED is non-zero, account is blocked.
    exec.word::eqz
    assert.err=ERR_ACCOUNT_BLOCKED
    # => []
end

#! Callback invoked when an asset with callbacks enabled is added to an account's vault.
#!
#! Checks whether the receiving account is in the block list. If so, panics.
#!
#! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
#! Outputs: [pad(16)]
#!
#! Invocation: call
@account_procedure
pub proc on_before_asset_added_to_account
    exec.assert_native_account_not_blocked
    # => [ASSET_ID, ASSET_VALUE, pad(8)]

    dropw dropw
    # => [pad(16)]
end

#! Callback invoked when an output note holding an asset with callbacks enabled is sealed.
#!
#! Checks whether the native account (the note creator) is in the block list. If so, panics.
#!
#! Inputs:  [note_idx, pad(15)]
#! Outputs: [0, EMPTY_WORD, pad(11)]
#!
#! Invocation: call
@account_procedure
pub proc on_before_note_sealed
    exec.assert_native_account_not_blocked
    # => [note_idx, pad(15)]

    drop
    # => [pad(16)]
end
"#;

/// The expected error when a blocked account tries to receive an asset with callbacks.
const ERR_ACCOUNT_BLOCKED: MasmError =
    MasmError::from_static_str("the account is blocked and cannot receive this asset");

/// The error raised by a note callback that observes an unexpected transaction expiration delta.
const ERR_UNEXPECTED_EXPIRATION_DELTA: MasmError =
    MasmError::from_static_str("note callback observed an unexpected expiration delta");

/// The error raised by the kernel if an attachment list does not hash to its commitment.
const ERR_ATTACHMENT_LIST_COMMITMENT_MISMATCH: MasmError =
    MasmError::from_static_str("pipe_double_words_preimage_to_memory: COMMITMENT does not match");

/// An advice map entry put into the advice map by a test callback: the key and its words.
type AdviceMapEntry = (Word, Vec<Word>);

// Initialize the block list component code only once.
static BLOCK_LIST_COMPONENT_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(BlockList::NAME, BLOCK_LIST_MASM)
        .expect("block list component code should be valid")
});

static BLOCK_LIST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::testing::callbacks::block_list")
        .expect("storage slot name should be valid")
});

procedure_root!(
    BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT,
    BlockList::NAME,
    BlockList::ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME,
    &BLOCK_LIST_COMPONENT_CODE
);

procedure_root!(
    BLOCK_LIST_ON_BEFORE_NOTE_SEALED,
    BlockList::NAME,
    BlockList::ON_BEFORE_NOTE_SEALED_PROC_NAME,
    &BLOCK_LIST_COMPONENT_CODE
);

// BLOCK LIST
// ================================================================================================

/// A test component that implements a block list for the `on_before_asset_added_to_account`
/// callback.
///
/// When a faucet distributes assets with callbacks enabled, this component checks whether the
/// receiving account is in the block list. If the account is blocked, the transaction fails.
struct BlockList {
    blocked_accounts: BTreeSet<AccountId>,
}

impl BlockList {
    const NAME: &str = "miden::testing::callbacks::block_list";

    const ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME: &str = "on_before_asset_added_to_account";

    const ON_BEFORE_NOTE_SEALED_PROC_NAME: &str = "on_before_note_sealed";

    /// Creates a new [`BlockList`] with the given set of blocked accounts.
    fn new(blocked_accounts: BTreeSet<AccountId>) -> Self {
        Self { blocked_accounts }
    }

    /// Returns the procedure root of the `on_before_asset_added_to_account` procedure.
    pub fn on_before_asset_added_to_account_root() -> AccountProcedureRoot {
        *BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT
    }

    /// Returns the procedure root of the `on_before_note_sealed` procedure.
    pub fn on_before_note_sealed_root() -> AccountProcedureRoot {
        *BLOCK_LIST_ON_BEFORE_NOTE_SEALED
    }
}

impl From<BlockList> for AccountComponent {
    fn from(block_list: BlockList) -> Self {
        // Build the storage map of blocked accounts
        let map_entries: Vec<(StorageMapKey, Word)> = block_list
            .blocked_accounts
            .iter()
            .map(|account_id| {
                let map_key = StorageMapKey::new(AccountIdKey::new(*account_id).as_word());
                // Non-zero value means the account is blocked
                let map_value = Word::new([Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
                (map_key, map_value)
            })
            .collect();

        let storage_map = StorageMap::with_entries(map_entries)
            .expect("btree set should guarantee no duplicates");

        // Build storage slots: block list map + asset callbacks value slot
        let mut storage_slots =
            vec![StorageSlot::with_map(BLOCK_LIST_SLOT_NAME.clone(), storage_map)];
        storage_slots.extend(
            AssetCallbacks::new()
                .on_before_asset_added_to_account(
                    BlockList::on_before_asset_added_to_account_root().as_word(),
                )
                .on_before_note_sealed(BlockList::on_before_note_sealed_root().as_word())
                .into_storage_slots(),
        );
        let metadata = AccountComponentMetadata::new(BlockList::NAME)
            .with_description("block list callback component for testing");

        AccountComponent::new(BLOCK_LIST_COMPONENT_CODE.clone(), storage_slots, metadata)
            .expect("block list should satisfy the requirements of a valid account component")
    }
}

// TESTS
// ================================================================================================

/// Tests that consuming a callbacks-enabled asset succeeds even when the issuing faucet does not
/// have the callback storage slot or when the callback storage slot contains the empty word.
#[rstest::rstest]
#[case::fungible_empty_storage(AssetComposition::Fungible, true)]
#[case::fungible_no_storage(AssetComposition::Fungible, false)]
#[case::non_fungible_empty_storage(AssetComposition::None, true)]
#[case::non_fungible_no_storage(AssetComposition::None, false)]
#[tokio::test]
async fn test_faucet_without_callback_slot_skips_callback(
    #[case] asset_composition: AssetComposition,
    #[case] has_empty_callback_proc_root: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Create a faucet whose ID enables callbacks, but WITHOUT a populated AssetCallbacks slot.
    // The flag has to be enabled explicitly here, since without a callback slot the builder would
    // otherwise derive it as disabled.
    let mut account_builder = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .enable_asset_callbacks()
        .with_component(MockFaucetComponent);

    // If callback proc roots should be empty, add the callback slots holding the empty word.
    // `AssetCallbacks` cannot express these, since it only emits slots for non-empty roots.
    if has_empty_callback_proc_root {
        let name = "miden::testing::callbacks";
        let slots = AssetCallbacks::slot_names()
            .into_iter()
            .map(|slot_name| StorageSlot::with_value(slot_name.clone(), Word::empty()))
            .collect();
        let component = AccountComponent::new(
            CodeBuilder::new().compile_component_code(name, "pub proc dummy nop end")?,
            slots,
            AccountComponentMetadata::mock(name),
        )?;
        account_builder = account_builder.with_component(component);
    }

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )?;

    // Create a P2ID note with an asset from this callbacks-enabled faucet.
    // The faucet's ID enables callbacks, but it does not have a populated callback slot.
    let asset = match asset_composition {
        AssetComposition::Fungible => Asset::from(FungibleAsset::new(faucet.id(), 100)?),
        AssetComposition::None => {
            Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(faucet.id(), vec![1])))
        },
        _ => unreachable!("test does not use custom composition"),
    };

    let note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Consuming the note should succeed: the callback is gracefully skipped because the
    // faucet does not define the callback storage slot.
    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that consuming a callbacks-enabled asset fails when the issuing faucet's callback slot
/// holds a procedure root that is not part of the faucet's account code.
#[tokio::test]
async fn test_faucet_with_invalid_callback_root_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Create a faucet whose ID enables callbacks and whose callback slot holds an arbitrary root
    // that does not correspond to any of the faucet's procedures.
    let arbitrary_root = Word::from([1u32, 2, 3, 4]);
    let name = "miden::testing::callbacks";
    let slots = AssetCallbacks::new()
        .on_before_asset_added_to_account(arbitrary_root)
        .into_storage_slots();
    let component = AccountComponent::new(
        CodeBuilder::new().compile_component_code(name, "pub proc dummy nop end")?,
        slots,
        AccountComponentMetadata::mock(name),
    )?;

    let account_builder = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockFaucetComponent)
        .with_component(component);

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )?;

    let asset = Asset::from(FungibleAsset::new(faucet.id(), 100)?);
    let note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::UnknownAccountProcedure(root)) if *root == arbitrary_root
            )
    );

    Ok(())
}

// ON_ASSET_ADDED_TO_ACCOUNT TESTS
// ================================================================================================

/// Tests that the `on_before_asset_added_to_account` callback receives the correct inputs.
#[tokio::test]
async fn test_on_before_asset_added_to_account_callback_receives_correct_inputs()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create wallet first so we know its ID before building the faucet.
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let wallet_id_suffix = target_account.id().suffix().as_canonical_u64();
    let wallet_id_prefix = target_account.id().prefix().as_u64();

    let amount: u64 = 100;

    // MASM callback that asserts the inputs match expected values.
    let account_callback_masm = format!(
        r#"
    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc on_before_asset_added_to_account
        # Assert native account ID can be retrieved via native_account::get_id
        exec.::miden::protocol::native_account::get_id
        # => [native_account_suffix, native_account_prefix, ASSET_ID, ASSET_VALUE, pad(8)]
        push.{wallet_id_suffix} assert_eq.err="callback received unexpected native account ID suffix"
        push.{wallet_id_prefix} assert_eq.err="callback received unexpected native account ID prefix"
        # => [ASSET_ID, ASSET_VALUE, pad(8)]

        # build the expected asset
        push.{amount}
        exec.::miden::protocol::active_account::get_id
        # => [active_account_id_suffix, active_account_id_prefix, amount, ASSET_ID, ASSET_VALUE, pad(8)]
        exec.::miden::standards::assets::fungible_asset::create
        # => [EXPECTED_ASSET_ID, EXPECTED_ASSET_VALUE, ASSET_ID, ASSET_VALUE, pad(8)]

        movupw.2
        assert_eqw.err="callback received unexpected asset ID"
        # => [EXPECTED_ASSET_VALUE, ASSET_VALUE, pad(8)]

        assert_eqw.err="callback received unexpected asset value"
        # => [pad(16)]
    end
    "#
    );

    let faucet =
        add_faucet_with_callbacks(&mut builder, [42; 32], Some(&account_callback_masm), None)?;

    // Create a P2ID note with a callbacks-enabled fungible asset.
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::from(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Execute the transaction - should succeed because all callback assertions pass.
    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that a blocked account cannot receive an asset with callbacks enabled.
#[rstest::rstest]
#[case::fungible(
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.into())
    }
)]
#[case::non_fungible(
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4]);
        Ok(NonFungibleAsset::new(&details).into())
    }
)]
#[tokio::test]
async fn test_blocked_account_cannot_receive_asset(
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_block_list(&mut builder, [target_account.id()])?;

    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[create_asset(faucet.id())?],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}

// ON_BEFORE_NOTE_SEALED TESTS
// ================================================================================================

/// Tests that a blocked account cannot seal an output note holding a callbacks-enabled asset.
#[rstest::rstest]
#[case::fungible(
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.into())
    }
)]
#[case::non_fungible(
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4]);
        Ok(NonFungibleAsset::new(&details).into())
    }
)]
#[tokio::test]
async fn test_blocked_account_cannot_seal_note_with_asset(
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Only `create_note` is needed here, so a `NoteCreator` account suffices instead of a full
    // basic wallet.
    let target_account = builder.add_existing_note_creator(Auth::IncrNonce)?;
    let faucet = add_faucet_with_block_list(&mut builder, [target_account.id()])?;
    let asset = create_asset(faucet.id())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Build a tx script that creates a private output note, adds the callbacks-enabled asset and
    // seals the note. We use a private note to avoid the public note details requirement in the
    // advice provider.
    let script_code = format!(
        r#"
        use miden::protocol::output_note

        @transaction_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::miden::standards::note::note_creator::create_note
            # => [note_idx, pad(15)]

            dup push.{asset_value} push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE, note_idx, note_idx, pad(15)]

            exec.output_note::add_asset
            # => [note_idx, pad(15)]

            exec.output_note::seal
            # => [pad(15)]

            exec.::miden::core::sys::truncate_stack
        end
        "#,
        recipient = Word::from([0u32, 1, 2, 3]),
        note_type = NoteType::Private as u8,
        tag = NoteTag::default(),
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}

/// Tests that adding a callbacks-enabled asset to a sealed note fails with the sealed-note error
/// without invoking the faucet's callback, which would reject the blocked account.
#[tokio::test]
async fn test_add_asset_to_sealed_note_does_not_invoke_callback() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_note_creator(Auth::IncrNonce)?;
    let faucet = add_faucet_with_block_list(&mut builder, [target_account.id()])?;
    let asset = Asset::from(FungibleAsset::new(faucet.id(), 100)?);

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let script_code = format!(
        r#"
        use miden::protocol::output_note

        @transaction_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.::miden::standards::note::note_creator::create_note
            # => [note_idx, pad(15)]

            # the note holds no assets, so sealing it invokes no callback
            dup exec.output_note::seal
            # => [note_idx, pad(15)]

            push.{asset_value} push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE, note_idx, pad(15)]

            exec.output_note::add_asset
            # => [pad(16)]

            exec.::miden::core::sys::truncate_stack
        end
        "#,
        recipient = Word::from([0u32, 1, 2, 3]),
        note_type = NoteType::Private as u8,
        tag = NoteTag::default(),
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_OUTPUT_NOTE_IS_SEALED);

    Ok(())
}

/// Tests that the `on_before_note_sealed` callback receives the correct inputs, runs before the
/// note is sealed and can read the note's assets.
///
/// Creates two output notes so that the asset is added to note at index 1, verifying that
/// `note_idx` is correctly passed to the callback (using 1 instead of the default element of 0).
#[tokio::test]
async fn test_on_before_note_sealed_callback_receives_correct_inputs() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create the account first so we know its ID before building the faucet.
    let target_account = builder.add_existing_mock_account(Auth::IncrNonce)?;
    let wallet_id_suffix = target_account.id().suffix().as_canonical_u64();
    let wallet_id_prefix = target_account.id().prefix().as_u64();

    let amount: u64 = 100;

    // MASM callback that asserts the inputs and the note's assets match expected values.
    let note_callback_masm = format!(
        r#"
    const ERR_WRONG_NOTE_IDX = "callback received unexpected note_idx"

    #! Inputs:  [note_idx, pad(15)]
    #! Outputs: [0, EMPTY_WORD, pad(11)]
    @locals(8)
    @account_procedure
    pub proc on_before_note_sealed
        # Assert native account ID can be retrieved via native_account::get_id
        exec.::miden::protocol::native_account::get_id
        # => [native_account_suffix, native_account_prefix, note_idx, pad(15)]
        push.{wallet_id_suffix} assert_eq.err="callback received unexpected native account ID suffix"
        push.{wallet_id_prefix} assert_eq.err="callback received unexpected native account ID prefix"
        # => [note_idx, pad(15)]

        # Assert note_idx == 1 (we create two notes, adding the asset to the second one)
        dup push.1 assert_eq.err=ERR_WRONG_NOTE_IDX
        # => [note_idx, pad(15)]

        dup exec.::miden::protocol::output_note::is_sealed
        assertz.err="callback ran after the note was sealed"
        # => [note_idx, pad(15)]

        locaddr.0 exec.::miden::protocol::output_note::get_assets
        # => [num_assets, pad(15)]

        push.1 assert_eq.err="callback read an unexpected number of note assets"
        # => [pad(16)]

        # build the expected asset
        push.{amount}
        exec.::miden::protocol::active_account::get_id
        # => [active_account_id_suffix, active_account_id_prefix, amount, pad(16)]
        exec.::miden::standards::assets::fungible_asset::create
        # => [EXPECTED_ASSET_ID, EXPECTED_ASSET_VALUE, pad(16)]

        locaddr.0 exec.::miden::protocol::asset::load
        # => [ASSET_ID, ASSET_VALUE, EXPECTED_ASSET_ID, EXPECTED_ASSET_VALUE, pad(16)]

        movupw.2
        assert_eqw.err="callback read an unexpected asset ID"
        # => [ASSET_VALUE, EXPECTED_ASSET_VALUE, pad(16)]

        assert_eqw.err="callback read an unexpected asset value"
        # => [pad(16)]
    end
    "#
    );

    let faucet =
        add_faucet_with_callbacks(&mut builder, [42; 32], None, Some(&note_callback_masm))?;

    // Create a P2ID note with a callbacks-enabled fungible asset.
    // Consuming this note adds the asset to the wallet's vault.
    let fungible_asset = FungibleAsset::new(faucet.id(), amount)?;
    let asset = Asset::from(fungible_asset);
    let note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Build a tx script that creates two output notes, moves the asset from vault to the
    // second note (note_idx=1) and seals it, so we can verify that the callback receives the
    // correct note_idx.
    let script_code = format!(
        r#"
        use miden::protocol::output_note
        use mock::util

        @transaction_script
        pub proc main
            # Create note 0 (just to consume index 0)
            exec.util::create_default_note exec.output_note::seal
            # => []

            # Create note 1
            push.{asset_value}
            push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE]
            exec.util::create_default_note_with_moved_asset
            # => []

            dropw dropw
        end
        "#,
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    );

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Execute the transaction: consume the P2ID note (asset enters vault), then move the asset
    // to output note 1 and seal it. Should succeed because all callback assertions pass.
    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that sealing a note runs the `on_before_note_sealed` callback once per distinct faucet,
/// in the order in which each faucet first occurs among the note's assets, and that sealing the
/// note again runs no callback.
///
/// The callbacks observe their order through the transaction's expiration delta, which starts
/// unset (0) and can only decrease: the callback of the faucet expected to run first asserts the
/// delta is unset and sets it to `FIRST_DELTA`, the other one asserts `FIRST_DELTA` and sets
/// `SECOND_DELTA`. A callback that runs out of order or more than once fails its assertion. The
/// note holds an asset of the first faucet after an asset of the second one, so a callback per
/// asset would also fail.
#[rstest::rstest]
#[case::first_occurrence_order(true)]
#[case::reversed_order(false)]
#[tokio::test]
async fn test_note_sealed_callback_runs_once_per_faucet_in_first_occurrence_order(
    #[case] first_faucet_occurs_first: bool,
) -> anyhow::Result<()> {
    const FIRST_DELTA: u16 = 200;
    const SECOND_DELTA: u16 = 100;

    let note_callback_masm = |expected_delta: u16, new_delta: u16| {
        format!(
            r#"
    #! Inputs:  [note_idx, pad(15)]
    #! Outputs: [0, EMPTY_WORD, pad(11)]
    @account_procedure
    pub proc on_before_note_sealed
        dup exec.::miden::protocol::output_note::is_sealed
        assertz.err="callback ran after the note was sealed"
        # => [note_idx, pad(15)]

        exec.::miden::protocol::tx::get_expiration_block_delta
        push.{expected_delta} assert_eq.err="{ERR_UNEXPECTED_EXPIRATION_DELTA}"
        # => [note_idx, pad(15)]

        push.{new_delta} exec.::miden::protocol::tx::update_expiration_block_delta
        # => [note_idx, pad(15)]

        drop
        # => [pad(16)]
    end
    "#,
            ERR_UNEXPECTED_EXPIRATION_DELTA = ERR_UNEXPECTED_EXPIRATION_DELTA.message(),
        )
    };

    let mut builder = MockChain::builder();
    let first_faucet = add_faucet_with_callbacks(
        &mut builder,
        [42; 32],
        None,
        Some(&note_callback_masm(0, FIRST_DELTA)),
    )?;
    let second_faucet = add_faucet_with_callbacks(
        &mut builder,
        [43; 32],
        None,
        Some(&note_callback_masm(FIRST_DELTA, SECOND_DELTA)),
    )?;

    let first_fungible = Asset::from(FungibleAsset::new(first_faucet.id(), 10)?);
    let second_fungible = Asset::from(FungibleAsset::new(second_faucet.id(), 20)?);
    let first_non_fungible = Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        first_faucet.id(),
        vec![1, 2, 3],
    )));
    let second_non_fungible = Asset::from(NonFungibleAsset::new(&NonFungibleAssetDetails::new(
        second_faucet.id(),
        vec![4, 5, 6],
    )));

    // Each faucet holds two separate assets in the note and the second faucet's asset sits
    // between them.
    let note_assets = if first_faucet_occurs_first {
        [first_fungible, second_fungible, first_non_fungible, second_non_fungible]
    } else {
        [second_fungible, first_fungible, second_non_fungible, first_non_fungible]
    };

    let sender = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, note_assets)?;
    let mock_chain = builder.build()?;

    let move_assets_code = note_assets
        .iter()
        .map(|asset| {
            format!(
                "push.{asset_value} push.{asset_id} dup.8
                # => [note_idx, ASSET_ID, ASSET_VALUE, note_idx]
                movdn.8 exec.util::move_asset_to_note
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
            exec.util::create_default_note
            # => [note_idx]

            {move_assets_code}

            # sealing again is a no-op that runs no callback
            dup exec.output_note::seal
            exec.output_note::seal
            # => []
        end
        "#
    ))?;

    let foreign_accounts = vec![
        mock_chain.get_foreign_account_inputs(first_faucet.id())?,
        mock_chain.get_foreign_account_inputs(second_faucet.id())?,
    ];

    let result = mock_chain
        .build_transaction(sender.id())
        .tx_script(tx_script)
        .foreign_accounts(foreign_accounts)
        .build()?
        .execute()
        .await;

    if first_faucet_occurs_first {
        let executed_tx = result?;
        assert_eq!(executed_tx.output_notes().get_note(0).assets().num_assets(), 4);
        assert_eq!(
            executed_tx.expiration_block_num(),
            executed_tx.block_header().block_num() + u32::from(SECOND_DELTA)
        );
    } else {
        assert_transaction_executor_error!(result, ERR_UNEXPECTED_EXPIRATION_DELTA);
    }

    Ok(())
}

/// Tests that the note callback of a native faucet can call kernel procedures that do not modify
/// account or note state.
///
/// The no-op case is a regression test for https://github.com/0xMiden/protocol/issues/2864.
#[rstest::rstest]
#[case::no_op("")]
#[case::update_expiration_block_delta(
    "push.10 exec.::miden::protocol::tx::update_expiration_block_delta"
)]
#[case::add_log("push.0.1.1.1 exec.::miden::protocol::tx::add_log_from_memory")]
#[tokio::test]
async fn test_native_faucet_callback_can_call_non_mutating_kernel_procedures(
    #[case] callback_body: &str,
) -> anyhow::Result<()> {
    mint_and_send_with_native_note_callback(callback_body).await??;

    Ok(())
}

/// Tests that the note callback of a native faucet cannot modify account or note state.
///
/// Each case calls the kernel procedure with the callback inputs as its arguments, because the
/// kernel rejects the call before it validates them.
#[rstest::rstest]
#[case::account_upgrade("exec.::miden::protocol::native_account::upgrade")]
#[case::account_incr_nonce("exec.::miden::protocol::native_account::incr_nonce")]
#[case::account_set_item("exec.::miden::protocol::native_account::set_item")]
#[case::account_set_map_item("exec.::miden::protocol::native_account::set_map_item")]
#[case::account_add_asset("exec.::miden::protocol::native_account::add_asset")]
#[case::account_remove_asset("exec.::miden::protocol::native_account::remove_asset")]
#[case::faucet_mint_asset("exec.::miden::protocol::faucet::mint")]
#[case::faucet_burn_asset("exec.::miden::protocol::faucet::burn")]
#[case::active_note_remove_asset("exec.::miden::protocol::active_note::remove_asset")]
#[case::input_note_remove_asset("exec.::miden::protocol::input_note::remove_asset")]
#[case::active_note_remove_all_assets(
    "push.0 exec.::miden::protocol::active_note::remove_all_assets"
)]
#[case::input_note_remove_all_assets(
    "push.0.0 exec.::miden::protocol::input_note::remove_all_assets"
)]
#[case::output_note_create("padw push.0.0 exec.::miden::protocol::output_note::create")]
#[case::output_note_add_asset("exec.::miden::protocol::output_note::add_asset")]
#[case::output_note_seal("dup exec.::miden::protocol::output_note::seal")]
#[case::output_note_add_attachment(
    "dup padw push.1 exec.::miden::protocol::output_note::add_word_attachment"
)]
#[tokio::test]
async fn test_native_faucet_callback_cannot_modify_state(
    #[case] callback_body: &str,
) -> anyhow::Result<()> {
    let result = mint_and_send_with_native_note_callback(callback_body).await?;

    assert_transaction_executor_error!(result, ERR_KERNEL_STATE_MUTATION_IN_ASSET_CALLBACK);

    Ok(())
}

/// Tests that the account callback of a foreign faucet cannot remove assets from the active note.
#[tokio::test]
async fn test_foreign_faucet_callback_cannot_remove_active_note_asset() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let account_callback_masm = r#"
    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc on_before_asset_added_to_account
        exec.::miden::protocol::active_note::remove_asset
        # => [REMAINING_ASSET_VALUE, pad(8)]

        dropw
        # => [pad(16)]
    end
    "#;

    let faucet =
        add_faucet_with_callbacks(&mut builder, [42; 32], Some(account_callback_masm), None)?;

    let fungible_asset = FungibleAsset::new(faucet.id(), 100)?;
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::from(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_KERNEL_STATE_MUTATION_IN_ASSET_CALLBACK);

    Ok(())
}

/// Tests that the attachments returned by the `on_before_note_sealed` callbacks are appended to the
/// note after the attachment the note's creator added, in the order in which each faucet first
/// occurs among the note's assets and, within one callback, in list order, and that a callback
/// returning 0 attachments appends no attachment.
///
/// Each case lists the faucets in the order of their assets in the note, each as the byte its seed
/// repeats and the attachments its callback returns. The transaction is also proven, so the prover
/// host must build the same output note.
#[rstest::rstest]
#[case::no_attachment(vec![(42, vec![])])]
#[case::one_attachment(vec![(42, vec![(20, Word::from([5, 6, 7, 8u32]))])])]
#[case::two_attachments(vec![(
    42,
    vec![(20, Word::from([5, 6, 7, 8u32])), (21, Word::from([9, 10, 11, 12u32]))],
)])]
#[case::first_faucet_occurs_first(vec![
    (42, vec![(21, Word::from([1, 1, 1, 1u32])), (22, Word::from([2, 2, 2, 2u32]))]),
    (43, vec![(23, Word::from([3, 3, 3, 3u32]))]),
])]
#[case::second_faucet_occurs_first(vec![
    (43, vec![(23, Word::from([3, 3, 3, 3u32]))]),
    (42, vec![(21, Word::from([1, 1, 1, 1u32])), (22, Word::from([2, 2, 2, 2u32]))]),
])]
#[tokio::test]
async fn test_note_sealed_callback_attachments_are_appended_to_note(
    #[case] faucets: Vec<(u8, Vec<(u16, Word)>)>,
) -> anyhow::Result<()> {
    let creator_attachment =
        NoteAttachment::with_word(NoteAttachmentScheme::new(10)?, Word::from([1, 2, 3, 4u32]));

    let note_callback_masms = faucets
        .iter()
        .map(|(_, attachments)| note_sealed_callback_masm(attachments))
        .collect::<Vec<_>>();
    let faucet_callbacks = faucets
        .iter()
        .zip(&note_callback_masms)
        .map(|((seed, _), note_callback_masm)| ([*seed; 32], note_callback_masm.as_str()))
        .collect::<Vec<_>>();
    let (note, result) =
        execute_note_sealing_tx(&faucet_callbacks, vec![creator_attachment.clone()]).await?;
    let executed_tx = result?;

    let mut expected_attachments = vec![creator_attachment];
    for (_, attachments) in &faucets {
        expected_attachments.extend(word_attachments(attachments)?);
    }
    let expected_note = Note::with_attachments(
        note.assets().clone(),
        *note.metadata().partial_metadata(),
        note.recipient().clone(),
        NoteAttachments::new(expected_attachments)?,
    );

    let output_note = executed_tx.output_notes().get_note(0);
    assert_eq!(output_note.attachments(), expected_note.attachments());
    assert_eq!(output_note.id(), expected_note.id());

    let proven_tx = LocalTransactionProver::default().prove(executed_tx)?;
    assert_eq!(proven_tx.output_notes().get_note(0).id(), expected_note.id());

    Ok(())
}

/// Tests that the attachments returned by an `on_before_note_sealed` callback are validated like
/// any other attachment and count toward the note's limit of attachments, and that a callback
/// cannot return more attachments than a note can hold.
#[rstest::rstest]
#[case::too_many_attachments(3, &[20, 21], ERR_OUTPUT_NOTE_TOO_MANY_ATTACHMENTS)]
#[case::too_many_listed_attachments(
    0,
    &[20, 21, 22, 23, 24],
    ERR_OUTPUT_NOTE_CALLBACK_TOO_MANY_ATTACHMENTS
)]
#[case::invalid_scheme(0, &[20, u16::MAX], ERR_OUTPUT_NOTE_ATTACHMENT_SCHEME_MAX_EXCEEDED)]
#[case::zero_scheme(0, &[0], ERR_OUTPUT_NOTE_ATTACHMENT_SCHEME_CANNOT_BE_ZERO)]
#[tokio::test]
async fn test_note_sealed_callback_attachments_are_validated(
    #[case] num_creator_attachments: u16,
    #[case] callback_attachment_schemes: &[u16],
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let scheme_word_attachment = |scheme: u16| (scheme, Word::from([u32::from(scheme); 4]));
    let creator_attachments =
        (1..=num_creator_attachments).map(scheme_word_attachment).collect::<Vec<_>>();
    let callback_attachments = callback_attachment_schemes
        .iter()
        .copied()
        .map(scheme_word_attachment)
        .collect::<Vec<_>>();
    let note_callback_masm = note_sealed_callback_masm(&callback_attachments);

    let (_, result) = execute_note_sealing_tx(
        &[([42; 32], &note_callback_masm)],
        word_attachments(&creator_attachments)?,
    )
    .await?;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that sealing fails if the number of attachments or the attachment list commitment returned
/// by an `on_before_note_sealed` callback does not match the attachment list in the advice map.
///
/// The callback puts a list of `num_listed_attachments` attachments into the advice map under
/// `attachment_list_commitment`, or under the list's commitment if it is `None`, and returns
/// `num_attachments` and that commitment.
#[rstest::rstest]
#[case::commitment_without_attachments(
    0,
    1,
    Some(Word::from([9, 9, 9, 9u32])),
    ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_COMMITMENT_WITHOUT_ATTACHMENTS
)]
#[case::list_not_matching_commitment(
    1,
    1,
    Some(Word::from([9, 9, 9, 9u32])),
    ERR_ATTACHMENT_LIST_COMMITMENT_MISMATCH
)]
#[case::fewer_attachments_than_listed(
    1,
    2,
    None,
    ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_LENGTH_MISMATCH
)]
#[case::more_attachments_than_listed(
    2,
    1,
    None,
    ERR_OUTPUT_NOTE_CALLBACK_ATTACHMENT_LIST_LENGTH_MISMATCH
)]
#[tokio::test]
async fn test_note_sealed_callback_attachment_list_is_verified(
    #[case] num_attachments: u64,
    #[case] num_listed_attachments: usize,
    #[case] attachment_list_commitment: Option<Word>,
    #[case] expected_error: MasmError,
) -> anyhow::Result<()> {
    let listed_attachments =
        [(20, Word::from([5, 6, 7, 8u32])), (21, Word::from([9, 10, 11, 12u32]))];
    let (list_commitment, list, mut advice_map_entries) =
        attachment_list(&listed_attachments[..num_listed_attachments]);
    let attachment_list_commitment = attachment_list_commitment.unwrap_or(list_commitment);
    advice_map_entries.push((attachment_list_commitment, list));
    let note_callback_masm = note_sealed_callback_masm_returning(
        num_attachments,
        attachment_list_commitment,
        &advice_map_entries,
    );

    let (_, result) =
        execute_note_sealing_tx(&[([42; 32], &note_callback_masm)], Vec::new()).await?;

    assert_transaction_executor_error!(result, expected_error);

    Ok(())
}

/// Tests that a new account whose storage contains an asset callback slot is rejected if its
/// account ID has the asset callback flag disabled.
#[tokio::test]
async fn test_new_account_with_callback_slot_and_disabled_flag_fails() -> anyhow::Result<()> {
    let mut mock_chain = MockChain::new();
    mock_chain.prove_next_block()?;

    // The block list component installs both callback slots, so the builder derives an enabled
    // flag for this account.
    let faucet = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(MockFaucetComponent)
        .with_component(BlockList::new(BTreeSet::new()))
        .build()?;
    assert_eq!(faucet.id().asset_callback_flag(), AssetCallbackFlag::Enabled);

    // Re-grind the ID of the very same code and storage, but with callbacks disabled.
    let seed = AccountId::compute_account_seed(
        [45; 32],
        AccountType::Public,
        AssetCallbackFlag::Disabled,
        AccountIdVersion::Version1,
        faucet.code().commitment(),
        faucet.storage().to_commitment(),
    )?;
    let account_id = AccountId::new(
        seed,
        AccountIdVersion::Version1,
        faucet.code().commitment(),
        faucet.storage().to_commitment(),
    )?;
    assert_eq!(account_id.asset_callback_flag(), AssetCallbackFlag::Disabled);

    let account = Account::new_unchecked(
        account_id,
        AssetVault::default(),
        faucet.storage().clone(),
        faucet.code().clone(),
        Felt::ZERO,
        Some(seed),
    );

    let mock_tx = mock_chain.build_transaction(account).build()?;

    let result = mock_tx.execute().await;

    assert_transaction_executor_error!(
        result,
        ERR_PROLOGUE_CALLBACK_SLOT_REQUIRES_ENABLED_ASSET_CALLBACK_FLAG
    );

    Ok(())
}

// HELPERS
// ================================================================================================

/// Builds a fungible faucet with the block list callback component and adds it to the builder.
///
/// The block list component registers both the account and note callbacks. When a
/// callbacks-enabled asset is added to an account or an output note holding one is sealed, the
/// callback checks whether the native account is in the block list and panics if so.
fn add_faucet_with_block_list(
    builder: &mut MockChainBuilder,
    blocked_accounts: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let block_list = BlockList::new(blocked_accounts.into_iter().collect());

    let account_builder = AccountBuilder::new([42u8; 32])
        .account_type(AccountType::Public)
        .with_component(MockFaucetComponent)
        .with_component(block_list);

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )
}

/// Mints a callbacks-enabled asset from a faucet and sends it in a new output note, in a
/// transaction against that faucet.
///
/// Sealing the note invokes the faucet's note callback in the native account context, which runs
/// `callback_body` on the callback inputs and then drops the note index.
async fn mint_and_send_with_native_note_callback(
    callback_body: &str,
) -> anyhow::Result<Result<ExecutedTransaction, TransactionExecutorError>> {
    let mut builder = MockChain::builder();

    let account_callback_masm = r#"
    #! Inputs:  [ASSET_ID, ASSET_VALUE, pad(8)]
    #! Outputs: [pad(16)]
    @account_procedure
    pub proc on_before_asset_added_to_account
        dropw dropw
        # => [pad(16)]
    end
    "#;

    let note_callback_masm = format!(
        r#"
    #! Inputs:  [note_idx, pad(15)]
    #! Outputs: [0, EMPTY_WORD, pad(11)]
    @account_procedure
    pub proc on_before_note_sealed
        {callback_body}
        # => [note_idx, pad(15)]

        drop
        # => [pad(16)]
    end
    "#
    );

    let faucet = add_faucet_with_callbacks(
        &mut builder,
        [42; 32],
        Some(account_callback_masm),
        Some(&note_callback_masm),
    )?;

    let recipient = Word::from([0, 1, 2, 3u32]);
    let tag = 0u32;
    let amount = 100u64;

    let tx_script_code = format!(
        "
        @transaction_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{amount}
            push.{faucet_id_prefix}
            push.{faucet_id_suffix}
            # => [faucet_id_suffix, faucet_id_prefix, amount, tag, note_type, RECIPIENT, pad(...)]

            exec.::miden::standards::assets::fungible_asset::create
            # => [ASSET_ID, ASSET_VALUE, tag, note_type, RECIPIENT, pad(...)]

            call.::miden::standards::faucets::fungible::mint_and_send
            # => [note_idx, pad(15)]

            exec.::miden::protocol::output_note::seal
            # => [pad(15)]

            # truncate the stack
            dropw dropw dropw drop drop drop
        end
        ",
        note_type = NoteType::Private as u8,
        faucet_id_suffix = faucet.id().suffix(),
        faucet_id_prefix = faucet.id().prefix().as_felt(),
    );

    let tx_script = CodeBuilder::default().compile_tx_script(tx_script_code)?;

    let mock_chain = builder.build()?;
    Ok(mock_chain
        .build_transaction(faucet.id())
        .tx_script(tx_script)
        .build()?
        .execute()
        .await)
}

/// Builds a fungible faucet from `seed` with custom callback MASM code and adds it to the builder.
///
/// `account_callback_masm` and `note_callback_masm` are optional MASM source for the
/// `on_before_asset_added_to_account` and `on_before_note_sealed` procedures. Each
/// string should contain a complete `pub proc ... end` block including any constants needed.
fn add_faucet_with_callbacks(
    builder: &mut MockChainBuilder,
    seed: [u8; 32],
    account_callback_masm: Option<&str>,
    note_callback_masm: Option<&str>,
) -> anyhow::Result<Account> {
    let component_name = "miden::testing::callbacks::input_validator";

    let masm_source =
        format!("{}\n{}", account_callback_masm.unwrap_or(""), note_callback_masm.unwrap_or(""),);

    let callback_code =
        CodeBuilder::default().compile_component_code(component_name, &masm_source)?;

    let mut callbacks = AssetCallbacks::new();

    if account_callback_masm.is_some() {
        let path = format!("{component_name}::on_before_asset_added_to_account");
        let proc_root = callback_code
            .as_package()
            .get_procedure_root_by_path(path.as_str())
            .expect("account callback procedure should exist");
        callbacks = callbacks.on_before_asset_added_to_account(proc_root);
    }

    if note_callback_masm.is_some() {
        let path = format!("{component_name}::on_before_note_sealed");
        let proc_root = callback_code
            .as_package()
            .get_procedure_root_by_path(path.as_str())
            .expect("note callback procedure should exist");
        callbacks = callbacks.on_before_note_sealed(proc_root);
    }

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("").expect("empty string is a valid token name"))
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::from(1_000_000u32))
        .build()?;

    let callback_storage_slots = callbacks.into_storage_slots();
    let callback_metadata = AccountComponentMetadata::new(component_name)
        .with_description("callback component for testing");
    let callback_component =
        AccountComponent::new(callback_code, callback_storage_slots, callback_metadata)?;

    let account_builder = AccountBuilder::new(seed)
        .account_type(AccountType::Public)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        )
        .with_component(Pausable::unpaused())
        .with_component(callback_component);

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )
}

/// Returns the MASM source of an `on_before_note_sealed` callback that returns the provided
/// single-word attachments, given as pairs of scheme and word, or no attachment if `attachments`
/// is empty.
///
/// The callback puts the attachment list and the elements of each attachment into the advice map.
fn note_sealed_callback_masm(attachments: &[(u16, Word)]) -> String {
    if attachments.is_empty() {
        return note_sealed_callback_masm_returning(0, Word::empty(), &[]);
    }

    let (list_commitment, list, mut advice_map_entries) = attachment_list(attachments);
    advice_map_entries.push((list_commitment, list));
    note_sealed_callback_masm_returning(
        attachments.len() as u64,
        list_commitment,
        &advice_map_entries,
    )
}

/// Returns the MASM source of an `on_before_note_sealed` callback that puts the provided entries
/// into the advice map and returns `[num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]`.
fn note_sealed_callback_masm_returning(
    num_attachments: u64,
    attachment_list_commitment: Word,
    advice_map_entries: &[AdviceMapEntry],
) -> String {
    let num_locals =
        advice_map_entries.iter().map(|(_, words)| words.len()).max().unwrap_or(1) * WORD_SIZE;
    let insert_entries_code = advice_map_entries
        .iter()
        .map(|(key, words)| {
            let store_words_code = words
                .iter()
                .enumerate()
                .map(|(word_idx, word)| {
                    format!("push.{word} loc_storew_le.{} dropw", word_idx * WORD_SIZE)
                })
                .collect::<Vec<_>>()
                .join("\n");

            format!(
                "{store_words_code}
                locaddr.0 dup add.{num_elements} swap push.{key}
                # => [KEY, start_ptr, end_ptr, pad(16)]

                adv.insert_mem dropw drop drop
                # => [pad(16)]",
                num_elements = words.len() * WORD_SIZE,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "
    #! Inputs:  [note_idx, pad(15)]
    #! Outputs: [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
    @locals({num_locals})
    @account_procedure
    pub proc on_before_note_sealed
        drop
        # => [pad(16)]

        {insert_entries_code}

        push.{attachment_list_commitment} push.{num_attachments}
        # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(16)]

        exec.::miden::core::sys::truncate_stack
        # => [num_attachments, ATTACHMENT_LIST_COMMITMENT, pad(11)]
    end
    "
    )
}

/// Returns the commitment to and the words of the attachment list of the provided single-word
/// attachments, given as pairs of scheme and word, and the advice map entries that hold the
/// elements of each attachment under its commitment.
///
/// The list holds, for each attachment, its scheme padded to a word followed by its commitment.
fn attachment_list(attachments: &[(u16, Word)]) -> (Word, Vec<Word>, Vec<AdviceMapEntry>) {
    let mut list = Vec::new();
    let mut attachment_entries = Vec::new();
    for &(attachment_scheme, attachment_word) in attachments {
        let attachment_commitment = Hasher::hash_elements(attachment_word.as_elements());
        list.extend([Word::from([u32::from(attachment_scheme), 0, 0, 0]), attachment_commitment]);
        attachment_entries.push((attachment_commitment, vec![attachment_word]));
    }

    (Hasher::hash_elements(Word::words_as_elements(&list)), list, attachment_entries)
}

/// Returns the single-word note attachments with the provided schemes and words.
fn word_attachments(attachments: &[(u16, Word)]) -> anyhow::Result<Vec<NoteAttachment>> {
    attachments
        .iter()
        .map(|&(attachment_scheme, attachment_word)| {
            Ok(NoteAttachment::with_word(
                NoteAttachmentScheme::new(attachment_scheme)?,
                attachment_word,
            ))
        })
        .collect()
}

/// Executes a transaction in which the native account creates a private output note, adds the
/// single-word `creator_attachments` to it, moves one asset of each of the `faucets` into it and
/// seals it.
///
/// Each entry of `faucets` is the seed of a faucet and the MASM source of its
/// `on_before_note_sealed` callback. The note holds the faucets' assets in the order of `faucets`.
///
/// Returns the note as the transaction script creates it, i.e. without the attachments returned by
/// the callbacks, and the execution result.
async fn execute_note_sealing_tx(
    faucets: &[([u8; 32], &str)],
    creator_attachments: Vec<NoteAttachment>,
) -> anyhow::Result<(Note, Result<ExecutedTransaction, TransactionExecutorError>)> {
    let mut builder = MockChain::builder();
    let faucets = faucets
        .iter()
        .map(|(seed, note_callback_masm)| {
            add_faucet_with_callbacks(&mut builder, *seed, None, Some(note_callback_masm))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let assets = faucets
        .iter()
        .map(|faucet| Ok(Asset::from(FungibleAsset::new(faucet.id(), 100)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let sender = builder.add_existing_mock_account_with_assets(Auth::IncrNonce, assets.clone())?;
    let mock_chain = builder.build()?;

    let mut note_builder = NoteBuilder::new(sender.id(), EidosRandomCoin::new(Word::empty()))
        .note_type(NoteType::Private)
        .add_assets(assets);
    for attachment in creator_attachments {
        note_builder = note_builder.attachment(attachment);
    }
    let note = note_builder.build()?;

    let move_assets_code = note
        .assets()
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

    let add_attachments_code = note
        .attachments()
        .iter()
        .map(|attachment| {
            format!(
                "dup push.{attachment_word} push.{attachment_scheme}
                # => [attachment_scheme, ATTACHMENT, note_idx, note_idx]

                exec.output_note::add_word_attachment
                # => [note_idx]",
                attachment_word = attachment.content().as_words()[0],
                attachment_scheme = attachment.attachment_scheme().as_u16(),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let tx_script = CodeBuilder::with_mock_packages().compile_tx_script(format!(
        "
        use miden::protocol::output_note
        use mock::util

        @transaction_script
        pub proc main
            push.{recipient} push.{note_type} push.{tag}
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            {move_assets_code}

            {add_attachments_code}

            exec.output_note::seal
            # => [pad(15)]

            exec.::miden::core::sys::truncate_stack
        end
        ",
        recipient = note.recipient().digest(),
        note_type = note.metadata().note_type() as u8,
        tag = note.metadata().tag(),
    ))?;

    let foreign_accounts = faucets
        .iter()
        .map(|faucet| mock_chain.get_foreign_account_inputs(faucet.id()))
        .collect::<Result<Vec<_>, _>>()?;

    let result = mock_chain
        .build_transaction(sender.id())
        .tx_script(tx_script)
        .foreign_accounts(foreign_accounts)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await;

    Ok((note, result))
}
