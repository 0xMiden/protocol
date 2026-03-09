extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

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
use miden_protocol::asset::{Asset, AssetCallbacks, AssetCallbacksFlag, FungibleAsset};
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
use miden::core::word

const BLOCK_LIST_MAP_SLOT = word("miden::testing::callbacks::block_list")
const ERR_ACCOUNT_BLOCKED = "the account is blocked and cannot receive this asset"

#! Callback invoked when an asset with callbacks enabled is added to an account's vault.
#!
#! Checks whether the receiving account is in the block list. If so, panics.
#!
#! Inputs:  [native_acct_suffix, native_acct_prefix, ASSET_KEY, ASSET_VALUE, pad(6)]
#! Outputs: [ASSET_VALUE, pad(12)]
#!
#! Invocation: call
pub proc on_asset_added_to_account
    # Build account ID map key: [0, 0, suffix, prefix]
    push.0.0
    # => [0, 0, native_acct_suffix, native_acct_prefix, ASSET_KEY, ASSET_VALUE, pad(6)]
    # => [ACCOUNT_ID_KEY, ASSET_KEY, ASSET_VALUE, pad(6)]

    # Look up in block list storage map
    push.BLOCK_LIST_MAP_SLOT[0..2]
    exec.active_account::get_map_item
    # => [MAP_VALUE, ASSET_KEY, ASSET_VALUE, pad(6)]

    # If value is non-zero, account is blocked.
    # testz returns 1 if word is all zeros (not blocked), 0 otherwise (blocked).
    # assert fails if top is 0, so blocked accounts cause a panic.
    exec.word::testz
    assert.err=ERR_ACCOUNT_BLOCKED
    # => [ASSET_KEY, ASSET_VALUE, pad(6)]

    # Drop ASSET_KEY, keep ASSET_VALUE on top
    dropw
    # => [ASSET_VALUE, pad(6)]

    # Pad to 16 elements: need ASSET_VALUE(4) + pad(12), have pad(6), add 6 more
    repeat.6
        push.0
        movdn.4
    end
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
    BLOCK_LIST_ON_ASSET_ADDED_TO_ACCOUNT,
    BlockList::NAME,
    BlockList::ON_ASSET_ADDED_TO_ACCOUNT_PROC_NAME,
    || { BLOCK_LIST_COMPONENT_CODE.as_library() }
);

// BLOCK LIST
// ================================================================================================

/// A test component that implements a block list for the `on_asset_added_to_account` callback.
///
/// When a faucet distributes assets with callbacks enabled, this component checks whether the
/// receiving account is in the block list. If the account is blocked, the transaction fails.
struct BlockList {
    blocked_accounts: BTreeSet<AccountId>,
}

impl BlockList {
    const NAME: &str = "miden::testing::callbacks::block_list";

    const ON_ASSET_ADDED_TO_ACCOUNT_PROC_NAME: &str = "on_asset_added_to_account";

    /// Creates a new [`BlockList`] with the given set of blocked accounts.
    fn new(blocked_accounts: BTreeSet<AccountId>) -> Self {
        Self { blocked_accounts }
    }

    /// Returns the digest of the `distribute` account procedure.
    pub fn on_asset_added_to_account_digest() -> Word {
        *BLOCK_LIST_ON_ASSET_ADDED_TO_ACCOUNT
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
                .on_asset_added_to_account(BlockList::on_asset_added_to_account_digest())
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
            auth_scheme: miden_protocol::account::auth::AuthScheme::Falcon512Poseidon2,
        },
        account_builder,
        AccountState::Exists,
    )?;

    // Create a P2ID note with a callbacks-enabled asset
    let fungible_asset =
        FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbacksFlag::Enabled);
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
    let consume_tx_context = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?;
    let result = consume_tx_context.execute().await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_BLOCKED);

    Ok(())
}
