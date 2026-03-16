extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
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
use miden_protocol::asset::{Asset, AssetCallbackFlag, AssetCallbacks, FungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::MasmError;
use miden_protocol::note::NoteType;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::procedure_digest;

use crate::{AccountState, Auth, assert_transaction_executor_error};

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

#! Callback invoked when an asset with callbacks enabled is added to an account's vault.
#!
#! Checks whether the receiving account is in the block list. If so, panics.
#!
#! Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
#! Outputs: [ASSET_VALUE, pad(12)]
#!
#! Invocation: call
pub proc on_before_asset_added_to_account
    # Get the native account ID (the account receiving the asset)
    exec.native_account::get_id
    # => [native_acct_suffix, native_acct_prefix, ASSET_KEY, ASSET_VALUE, pad(8)]

    # Build account ID map key: [0, 0, suffix, prefix]
    push.0.0
    # => [0, 0, native_acct_suffix, native_acct_prefix, ASSET_KEY, ASSET_VALUE, pad(8)]
    # => [ACCOUNT_ID_KEY, ASSET_KEY, ASSET_VALUE, pad(8)]

    # Look up in block list storage map
    push.BLOCK_LIST_MAP_SLOT[0..2]
    exec.active_account::get_map_item
    # => [IS_BLOCKED, ASSET_KEY, ASSET_VALUE, pad(8)]

    # If IS_BLOCKED is non-zero, account is blocked.
    exec.word::eqz
    assert.err=ERR_ACCOUNT_BLOCKED
    # => [ASSET_KEY, ASSET_VALUE, pad(10)]

    # drop unused asset key
    dropw
    # => [ASSET_VALUE, pad(12)]
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

    /// Creates a new [`BlockList`] with the given set of blocked accounts.
    fn new(blocked_accounts: BTreeSet<AccountId>) -> Self {
        Self { blocked_accounts }
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn on_before_asset_added_to_account_digest() -> Word {
        *BLOCK_LIST_ON_BEFORE_ASSET_ADDED_TO_ACCOUNT
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
                .into_storage_slots(),
        );
        let metadata =
            AccountComponentMetadata::new(BlockList::NAME, [AccountType::FungibleFaucet])
                .with_description("block list callback component for testing");

        AccountComponent::new(BLOCK_LIST_COMPONENT_CODE.clone(), storage_slots, metadata)
            .expect("block list should satisfy the requirements of a valid account component")
    }
}

// TESTS
// ================================================================================================

/// Tests that the `on_before_asset_added_to_account` callback receives the correct inputs.
#[tokio::test]
async fn test_on_before_asset_added_to_account_callback_receives_correct_inputs()
-> anyhow::Result<()> {
    let mut builder = crate::MockChain::builder();

    // Create wallet first so we know its ID before building the faucet.
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let wallet_id_suffix = target_account.id().suffix().as_canonical_u64();
    let wallet_id_prefix = target_account.id().prefix().as_u64();

    let amount: u64 = 100;

    // MASM callback that asserts the inputs match expected values.
    let component_name = "miden::testing::callbacks::input_validator";
    let proc_name = "on_before_asset_added_to_account";
    let callback_masm = format!(
        r#"
    const ERR_WRONG_VALUE = "callback received unexpected asset value element"

    #! Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
    #! Outputs: [ASSET_VALUE, pad(12)]
    pub proc {proc_name}
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

    // Compile the callback code and extract the procedure root.
    let callback_code =
        CodeBuilder::default().compile_component_code(component_name, callback_masm.as_str())?;

    let proc_root = callback_code
        .as_library()
        .get_procedure_root_by_path(format!("{component_name}::{proc_name}").as_str())
        .expect("callback should contain the procedure");

    // Build the faucet with BasicFungibleFaucet + callback component.
    let basic_faucet = BasicFungibleFaucet::new("CBK".try_into()?, 8, Felt::new(1_000_000))?;

    let callback_storage_slots = AssetCallbacks::new()
        .on_before_asset_added_to_account(proc_root)
        .into_storage_slots();

    let callback_metadata =
        AccountComponentMetadata::new(component_name, [AccountType::FungibleFaucet])
            .with_description("input validation callback component for testing");

    let callback_component =
        AccountComponent::new(callback_code, callback_storage_slots, callback_metadata)?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(basic_faucet)
        .with_component(callback_component);

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )?;

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

/// Tests that a blocked account cannot receive assets with callbacks enabled.
///
/// Flow:
/// 1. Create a faucet with BasicFungibleFaucet + BlockList components
/// 2. Create a wallet that is in the block list
/// 3. Create a P2ID note with a callbacks-enabled asset from the faucet to the wallet
/// 4. Attempt to consume the note on the blocked wallet
/// 5. Assert that the transaction fails with ERR_ACCOUNT_BLOCKED
#[tokio::test]
async fn test_blocked_account_cannot_receive_asset() -> anyhow::Result<()> {
    let mut builder = crate::MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let block_list = BlockList::new(BTreeSet::from_iter([target_account.id()]));
    let basic_faucet = BasicFungibleFaucet::new("BLK".try_into()?, 8, Felt::new(1_000_000))?;

    let account_builder = AccountBuilder::new([42u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(basic_faucet)
        .with_component(block_list);

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )?;

    // Create a P2ID note with a callbacks-enabled asset
    let fungible_asset =
        FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Get foreign account inputs for the faucet so the callback's foreign context can access it
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    // Try to consume the note on the blocked wallet - should fail because the callback
    // checks the block list and panics.
    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}

/// Tests that consuming a callbacks-enabled asset succeeds even when the issuing faucet does not
/// have the callback storage slot.
#[tokio::test]
async fn test_faucet_without_callback_slot_skips_callback() -> anyhow::Result<()> {
    let mut builder = crate::MockChain::builder();

    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let basic_faucet = BasicFungibleFaucet::new("NCB".try_into()?, 8, Felt::new(1_000_000))?;

    // Create a faucet WITHOUT any AssetCallbacks component.
    let account_builder = AccountBuilder::new([45u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(basic_faucet);

    let faucet = builder.add_account_from_builder(
        Auth::BasicAuth {
            auth_scheme: AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )?;

    // Create a P2ID note with a callbacks-enabled asset from this faucet.
    // The faucet does not have the callback slot, but the asset has callbacks enabled.
    let fungible_asset =
        FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

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
