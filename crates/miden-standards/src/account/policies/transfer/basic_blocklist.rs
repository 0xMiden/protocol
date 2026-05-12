use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentMetadata, StorageSchema};
use miden_protocol::account::{AccountComponent, AccountType, StorageMap, StorageSlot};

use crate::account::components::basic_blocklist_transfer_policy_library;
use crate::account::policies::transfer::blocklist::Blocklist;
use crate::procedure_digest;

// BASIC BLOCKLIST TRANSFER POLICY
// ================================================================================================

procedure_digest!(
    BASIC_BLOCKLIST_POLICY_ROOT,
    BasicBlocklist::NAME,
    BasicBlocklist::PROC_NAME,
    basic_blocklist_transfer_policy_library
);

/// The basic blocklist transfer policy account component.
///
/// Installs the per-faucet `blocked_accounts` storage map (defined by [`Blocklist`]) plus the
/// `check_policy` predicate procedure. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send / receive policy maps include
/// [`BasicBlocklist::root`]. When active, transfers fail if the native account (asset
/// recipient or note creator) is currently blocked on the issuing faucet.
///
/// Block / unblock administration is intentionally not part of this component. The
/// `block_account` / `unblock_account` procedures live in the standards library and require an
/// auth-wrapped admin component (see [`super::OwnerManagedBlocklist`]) to be safely exposed on
/// a production faucet.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicBlocklist;

impl BasicBlocklist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::basic_blocklist";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the basic blocklist transfer policy procedure.
    pub fn root() -> Word {
        *BASIC_BLOCKLIST_POLICY_ROOT
    }
}

impl From<BasicBlocklist> for AccountComponent {
    fn from(_: BasicBlocklist) -> Self {
        let blocked_accounts_slot = StorageSlot::with_map(
            Blocklist::blocked_accounts_slot().clone(),
            StorageMap::default(),
        );

        let storage_schema = StorageSchema::new([Blocklist::blocked_accounts_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(
            BasicBlocklist::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Basic blocklist transfer policy: predicate procedure plus the `blocked_accounts` \
             storage map it reads",
        )
        .with_storage_schema(storage_schema);

        AccountComponent::new(
            basic_blocklist_transfer_policy_library(),
            vec![blocked_accounts_slot],
            metadata,
        )
        .expect(
            "basic blocklist transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
