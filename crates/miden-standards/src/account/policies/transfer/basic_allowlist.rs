use alloc::collections::BTreeSet;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::account::policies::transfer::allowlist::AllowlistStorage;
use crate::procedure_root;

// BASIC ALLOWLIST TRANSFER POLICY
// ================================================================================================

account_component_code!(
    BASIC_ALLOWLIST_TRANSFER_POLICY_CODE,
    "faucets/policies/transfer/basic_allowlist.masl"
);

procedure_root!(
    BASIC_ALLOWLIST_TRANSFER_POLICY_ROOT,
    BasicAllowlist::NAME,
    BasicAllowlist::PROC_NAME,
    BasicAllowlist::code()
);

/// The basic allowlist transfer policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose send and receive
/// policy  maps include [`BasicAllowlist::root`]. When active, transfers fail if the
/// native account (asset recipient or note creator) is not currently allowed on the
/// issuing faucet.
///
/// Allow / disallow administration is intentionally not part of this component. The
/// `allow_account` / `disallow_account` procedures live in the standards library and require
/// an auth-wrapped admin component (see [`super::AllowlistOwnerControlled`]) to be safely
/// exposed on a production faucet.
#[derive(Debug, Clone, Default)]
pub struct BasicAllowlist(AllowlistStorage);

impl BasicAllowlist {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::transfer::basic_allowlist";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Creates a basic allowlist with the given initial allowed accounts.
    pub fn with_allowed_accounts<I>(allowed_accounts: I) -> Self
    where
        I: IntoIterator<Item = AccountId>,
    {
        Self(AllowlistStorage::with_allowed_accounts(allowed_accounts))
    }

    /// Returns the initial allowed accounts captured in this component.
    pub fn allowed_accounts(&self) -> &BTreeSet<AccountId> {
        self.0.allowed_accounts()
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &BASIC_ALLOWLIST_TRANSFER_POLICY_CODE
    }

    /// Returns the MAST root of the basic allowlist transfer policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *BASIC_ALLOWLIST_TRANSFER_POLICY_ROOT
    }
}

impl From<AllowlistStorage> for BasicAllowlist {
    fn from(storage: AllowlistStorage) -> Self {
        Self(storage)
    }
}

impl From<BasicAllowlist> for AccountComponent {
    fn from(allowlist: BasicAllowlist) -> Self {
        let storage_schema = StorageSchema::new([AllowlistStorage::allowed_accounts_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(BasicAllowlist::NAME)
            .with_description(
                "Basic allowlist transfer policy: predicate procedure plus the `allowed_accounts` \
                 storage map it reads",
            )
            .with_storage_schema(storage_schema);

        AccountComponent::new(BasicAllowlist::code().clone(), vec![allowlist.0.into_slot()], metadata)
            .expect(
                "basic allowlist transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
