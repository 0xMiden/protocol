extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountComponentCode,
    AccountId,
    AccountStorageMode,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{
    Asset,
    AssetCallbackFlag,
    AssetCallbacks,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::metadata::{FungibleTokenMetadataBuilder, TokenName};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::procedure_digest;
use miden_standards::testing::account_component::MockFaucetComponent;

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
#! Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
#! Outputs: [ASSET_VALUE, pad(12)]
#!
#! Invocation: call
pub proc on_before_asset_added_to_account
    exec.assert_native_account_not_blocked
    # => [ASSET_KEY, ASSET_VALUE, pad(8)]

    # drop unused asset key
    dropw
    # => [ASSET_VALUE, pad(12)]
end

#! Callback invoked when an asset with callbacks enabled is added to an output note.
#!
#! Checks whether the native account (the note creator) is in the block list. If so, panics.
#!
#! Inputs:  [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]
#! Outputs: [ASSET_VALUE, pad(12)]
#!
#! Invocation: call
pub proc on_before_asset_added_to_note
    exec.assert_native_account_not_blocked
    # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]

    # drop unused asset key
    dropw
    # => [ASSET_VALUE, note_idx, pad(7)]
end
"#;

/// The expected error when a blocked account tries to receive an asset with callbacks.
const ERR_ACCOUNT_BLOCKED: MasmError =
    MasmError::from_static_str("the account is blocked and cannot receive this asset");

// Initialize the Basic Fungible Faucet library only once.
static BLOCK_LIST_COMPONENT_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(BlockList::NAME, BLOCK_LIST_MASM)
        .expect("block list library should be valid")
});

static BLOCK_LIST_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::testing::callbacks::block_list")
        .expect("storage slot name should be valid")
});

procedure_digest!(
    BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT,
    BlockList::NAME,
    BlockList::ON_BEFORE_ASSET_ADDED_TO_ACCOUNT_PROC_NAME,
    || { BLOCK_LIST_COMPONENT_CODE.as_library() }
);

procedure_digest!(
    BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_NOTE,
    BlockList::NAME,
    BlockList::ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME,
    || { BLOCK_LIST_COMPONENT_CODE.as_library() }
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

    const ON_BEFORE_ASSET_ADDED_TO_NOTE_PROC_NAME: &str = "on_before_asset_added_to_note";

    /// Creates a new [`BlockList`] with the given set of blocked accounts.
    fn new(blocked_accounts: BTreeSet<AccountId>) -> Self {
        Self { blocked_accounts }
    }

    /// Returns the digest of the `on_before_asset_added_to_account` procedure.
    pub fn on_before_asset_added_to_account_digest() -> Word {
        *BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT
    }

    /// Returns the digest of the `on_before_asset_added_to_note` procedure.
    pub fn on_before_asset_added_to_note_digest() -> Word {
        *BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_NOTE
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
                    BlockList::on_before_asset_added_to_account_digest(),
                )
                .on_before_asset_added_to_note(BlockList::on_before_asset_added_to_note_digest())
                .into_storage_slots(),
        );
        let metadata = AccountComponentMetadata::new(
            BlockList::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
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
#[case::fungible_empty_storage(AccountType::FungibleFaucet, true)]
#[case::fungible_no_storage(AccountType::FungibleFaucet, false)]
#[case::non_fungible_empty_storage(AccountType::NonFungibleFaucet, true)]
#[case::non_fungible_no_storage(AccountType::NonFungibleFaucet, false)]
#[tokio::test]
async fn test_faucet_without_callback_slot_skips_callback(
    #[case] account_type: AccountType,
    #[case] has_empty_callback_proc_root: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Create a faucet WITHOUT any AssetCallbacks component.
    let mut account_builder = AccountBuilder::new([45u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(account_type)
        .with_component(MockFaucetComponent);

    // If callback proc roots should be empty, add the empty storage slots.
    if has_empty_callback_proc_root {
        let name = "miden::testing::callbacks";
        let slots = AssetCallbacks::new().into_storage_slots();
        let component = AccountComponent::new(
            CodeBuilder::new().compile_component_code(name, "pub proc dummy nop end")?,
            slots,
            AccountComponentMetadata::mock(name),
        )?;
        account_builder = account_builder.with_component(component);
    }

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )?;

    // Create a P2ID note with a callbacks-enabled asset from this faucet.
    // The faucet does not have the callback slot, but the asset has callbacks enabled.
    let asset = match account_type {
        AccountType::FungibleFaucet => Asset::from(FungibleAsset::new(faucet.id(), 100)?),
        AccountType::NonFungibleFaucet => Asset::from(NonFungibleAsset::new(
            &NonFungibleAssetDetails::new(faucet.id(), vec![1])?,
        )?),
        _ => unreachable!("test only uses faucet account types"),
    }
    .with_callbacks(AssetCallbackFlag::Enabled);

    let note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Consuming the note should succeed: the callback is gracefully skipped because the
    // faucet does not define the callback storage slot.
    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

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
    #! Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
    #! Outputs: [ASSET_VALUE, pad(12)]
    pub proc on_before_asset_added_to_account
        # Assert native account ID can be retrieved via native_account::get_id
        exec.::miden::protocol::native_account::get_id
        # => [native_account_suffix, native_account_prefix, ASSET_KEY, ASSET_VALUE, pad(8)]
        push.{wallet_id_suffix} assert_eq.err="callback received unexpected native account ID suffix"
        push.{wallet_id_prefix} assert_eq.err="callback received unexpected native account ID prefix"
        # => [ASSET_KEY, ASSET_VALUE, pad(8)]

        # duplicate the asset value for returning
        dupw.1 swapw
        # => [ASSET_KEY, ASSET_VALUE, ASSET_VALUE, pad(8)]

        # build the expected asset
        push.{amount}
        exec.::miden::protocol::active_account::get_id
        push.1
        # => [enable_callbacks, active_account_id_suffix, active_account_id_prefix, amount, ASSET_KEY, ASSET_VALUE, ASSET_VALUE, pad(8)]
        exec.::miden::protocol::asset::create_fungible_asset
        # => [EXPECTED_ASSET_KEY, EXPECTED_ASSET_VALUE, ASSET_KEY, ASSET_VALUE, ASSET_VALUE, pad(8)]

        movupw.2
        assert_eqw.err="callback received unexpected asset key"
        # => [EXPECTED_ASSET_VALUE, ASSET_VALUE, ASSET_VALUE, pad(8)]

        assert_eqw.err="callback received unexpected asset value"
        # => [ASSET_VALUE, pad(12)]
    end
    "#
    );

    let faucet = add_faucet_with_callbacks(&mut builder, Some(&account_callback_masm), None)?;

    // Create a P2ID note with a callbacks-enabled fungible asset.
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Execute the transaction - should succeed because all callback assertions pass.
    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

/// Tests that a blocked account cannot receive an asset with callbacks enabled.
#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn test_blocked_account_cannot_receive_asset(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_block_list(&mut builder, account_type, [target_account.id()])?;

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
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}

// ON_ASSET_ADDED_TO_NOTE TESTS
// ================================================================================================

/// Tests that a blocked account cannot add a callbacks-enabled asset to an output note.
#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn test_blocked_account_cannot_add_asset_to_note(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_block_list(&mut builder, account_type, [target_account.id()])?;
    let asset = create_asset(faucet.id())?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Build a tx script that creates a private output note and adds the callbacks-enabled asset.
    // We use a private note to avoid the public note details requirement in the advice provider.
    let recipient = Word::from([0u32, 1, 2, 3]);
    let script_code = format!(
        r#"
        use miden::protocol::output_note

        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.output_note::create

            push.{asset_value}
            push.{asset_key}
            exec.output_note::add_asset
        end
        "#,
        recipient = recipient,
        note_type = NoteType::Private as u8,
        tag = NoteTag::default(),
        asset_value = asset.to_value_word(),
        asset_key = asset.to_key_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[], &[])?
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}

/// Tests that the `on_before_asset_added_to_note` callback receives the correct inputs.
///
/// Creates two output notes so that the asset is added to note at index 1, verifying that
/// `note_idx` is correctly passed to the callback (using 1 instead of the default element of 0).
#[tokio::test]
async fn test_on_before_asset_added_to_note_callback_receives_correct_inputs() -> anyhow::Result<()>
{
    let mut builder = MockChain::builder();

    // Create wallet first so we know its ID before building the faucet.
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let wallet_id_suffix = target_account.id().suffix().as_canonical_u64();
    let wallet_id_prefix = target_account.id().prefix().as_u64();

    let amount: u64 = 100;

    // MASM callback that asserts the inputs match expected values.
    let note_callback_masm = format!(
        r#"
    const ERR_WRONG_NOTE_IDX = "callback received unexpected note_idx"

    #! Inputs:  [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]
    #! Outputs: [ASSET_VALUE, pad(12)]
    pub proc on_before_asset_added_to_note
        # Assert native account ID can be retrieved via native_account::get_id
        exec.::miden::protocol::native_account::get_id
        # => [native_account_suffix, native_account_prefix, ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]
        push.{wallet_id_suffix} assert_eq.err="callback received unexpected native account ID suffix"
        push.{wallet_id_prefix} assert_eq.err="callback received unexpected native account ID prefix"
        # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]

        # Assert note_idx == 1 (we create two notes, adding the asset to the second one)
        dup.8 push.1 assert_eq.err=ERR_WRONG_NOTE_IDX
        # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]

        # duplicate the asset value for returning
        dupw.1 swapw
        # => [ASSET_KEY, ASSET_VALUE, ASSET_VALUE, note_idx, pad(7)]

        # build the expected asset
        push.{amount}
        exec.::miden::protocol::active_account::get_id
        push.1
        # => [enable_callbacks, active_account_id_suffix, active_account_id_prefix, amount, ASSET_KEY, ASSET_VALUE, ASSET_VALUE, note_idx, pad(7)]
        exec.::miden::protocol::asset::create_fungible_asset
        # => [EXPECTED_ASSET_KEY, EXPECTED_ASSET_VALUE, ASSET_KEY, ASSET_VALUE, ASSET_VALUE, note_idx, pad(7)]

        movupw.2
        assert_eqw.err="callback received unexpected asset key"
        # => [EXPECTED_ASSET_VALUE, ASSET_VALUE, ASSET_VALUE, note_idx, pad(7)]

        assert_eqw.err="callback received unexpected asset value"
        # => [ASSET_VALUE, note_idx, pad(7)]
    end
    "#
    );

    let faucet = add_faucet_with_callbacks(&mut builder, None, Some(&note_callback_masm))?;

    // Create a P2ID note with a callbacks-enabled fungible asset.
    // Consuming this note adds the asset to the wallet's vault.
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let asset = Asset::Fungible(fungible_asset);
    let note =
        builder.add_p2id_note(faucet.id(), target_account.id(), &[asset], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Build a tx script that creates two output notes and moves the asset from vault to the
    // second note (note_idx=1), so we can verify that the callback receives the correct
    // note_idx.
    let script_code = format!(
        r#"
        use mock::util

        begin
            # Create note 0 (just to consume index 0)
            exec.util::create_default_note drop
            # => []

            # Create note 1
            push.{asset_value}
            push.{asset_key}
            # => [ASSET_KEY, ASSET_VALUE]
            exec.util::create_default_note_with_moved_asset
            # => []

            dropw dropw
        end
        "#,
        asset_value = asset.to_value_word(),
        asset_key = asset.to_key_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Execute the transaction: consume the P2ID note (asset enters vault), then move the asset
    // to output note 1. Should succeed because all callback assertions pass.
    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

// HELPERS
// ================================================================================================

/// Builds a fungible faucet with the block list callback component and adds it to the builder.
///
/// The block list component registers both the account and note callbacks. When a
/// callbacks-enabled asset is added to an account or note, the callback checks whether the
/// native account is in the block list and panics if so.
fn add_faucet_with_block_list(
    builder: &mut MockChainBuilder,
    account_type: AccountType,
    blocked_accounts: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let block_list = BlockList::new(blocked_accounts.into_iter().collect());

    if !account_type.is_faucet() {
        anyhow::bail!("account type must be of type faucet")
    }

    let account_builder = AccountBuilder::new([42u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(account_type)
        .with_component(MockFaucetComponent)
        .with_component(block_list);

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}

/// Builds a fungible faucet with custom callback MASM code and adds it to the builder.
///
/// `account_callback_masm` and `note_callback_masm` are optional MASM source for the
/// `on_before_asset_added_to_account` and `on_before_asset_added_to_note` procedures. Each
/// string should contain a complete `pub proc ... end` block including any constants needed.
fn add_faucet_with_callbacks(
    builder: &mut MockChainBuilder,
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
            .as_library()
            .get_procedure_root_by_path(path.as_str())
            .expect("account callback procedure should exist");
        callbacks = callbacks.on_before_asset_added_to_account(proc_root);
    }

    if note_callback_masm.is_some() {
        let path = format!("{component_name}::on_before_asset_added_to_note");
        let proc_root = callback_code
            .as_library()
            .get_procedure_root_by_path(path.as_str())
            .expect("note callback procedure should exist");
        callbacks = callbacks.on_before_asset_added_to_note(proc_root);
    }

    let faucet_metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("").expect("empty string is a valid token name"),
        "SYM".try_into()?,
        8,
        1_000_000u64,
    )
    .build()?;

    let callback_storage_slots = callbacks.into_storage_slots();
    let callback_metadata =
        AccountComponentMetadata::new(component_name, [AccountType::FungibleFaucet])
            .with_description("callback component for testing");
    let callback_component =
        AccountComponent::new(callback_code, callback_storage_slots, callback_metadata)?;

    let account_builder = AccountBuilder::new([42; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet_metadata)
        .with_component(BasicFungibleFaucet)
        .with_component(callback_component);

    builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )
}
