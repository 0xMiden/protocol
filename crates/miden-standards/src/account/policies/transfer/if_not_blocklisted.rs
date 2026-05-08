use miden_protocol::Word;
use miden_protocol::account::component::{AccountComponentMetadata, StorageSchema};
use miden_protocol::account::{AccountComponent, AccountType, StorageMap, StorageSlot};

use crate::account::components::if_not_blocklisted_transfer_policy_library;
use crate::account::faucets::Restricted;
use crate::procedure_digest;

// IF-NOT-BLOCKLISTED TRANSFER POLICY
// ================================================================================================

procedure_digest!(
    IF_NOT_BLOCKLISTED_POLICY_ROOT,
    TransferIfNotBlocklisted::NAME,
    TransferIfNotBlocklisted::PROC_NAME,
    if_not_blocklisted_transfer_policy_library
);

/// The `if_not_blocklisted` transfer policy account component.
///
/// Installs the per-faucet `blocked_accounts` storage map (see [`Restricted`]) plus the
/// `check_policy` predicate procedure. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send / receive policy maps include
/// [`TransferIfNotBlocklisted::root`]. When active, transfers fail if the native account (asset
/// recipient or note creator) is currently blocked on the issuing faucet.
///
/// Block / unblock administration is intentionally not part of this component. The
/// `block` / `unblock` procedures live in the standards library and require an auth-wrapped
/// admin component (e.g. an Ownable2Step- or RBAC-gated wrapper) to be safely exposed on a
/// production faucet. Tests may invoke them via `exec.` directly when the test transaction
/// runs with the faucet as the native account.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferIfNotBlocklisted;

impl TransferIfNotBlocklisted {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::if_not_blocklisted";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the MAST root of the `if_not_blocklisted` transfer policy procedure.
    pub fn root() -> Word {
        *IF_NOT_BLOCKLISTED_POLICY_ROOT
    }
}

impl From<TransferIfNotBlocklisted> for AccountComponent {
    fn from(_: TransferIfNotBlocklisted) -> Self {
        let blocked_accounts_slot = StorageSlot::with_map(
            Restricted::blocked_accounts_slot().clone(),
            StorageMap::default(),
        );

        let storage_schema = StorageSchema::new([Restricted::blocked_accounts_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(
            TransferIfNotBlocklisted::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "`if_not_blocklisted` transfer policy: predicate procedure plus the \
             `blocked_accounts` storage map it reads",
        )
        .with_storage_schema(storage_schema);

        AccountComponent::new(
            if_not_blocklisted_transfer_policy_library(),
            vec![blocked_accounts_slot],
            metadata,
        )
        .expect(
            "`if_not_blocklisted` transfer policy component should satisfy the requirements of a valid account component",
        )
    }
}
