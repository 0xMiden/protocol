use alloc::collections::BTreeSet;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot, AccountType};

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
/// Installs the per-faucet `allowed_accounts` storage map (defined by [`AllowlistStorage`])
/// plus the `check_policy` predicate procedure. Pair with a
/// [`crate::account::policies::TokenPolicyManager`] whose send / receive policy maps include
/// [`BasicAllowlist::root`]. When active, transfers fail if the native account (asset
/// recipient or note creator) is not currently allowed on the issuing faucet.
///
/// The wrapped [`BTreeSet<AccountId>`] captures the initial allowlist contents. Unlike the
/// blocklist, an empty allowlist rejects every transfer — a production faucet should seed
/// the allowlist with at least the accounts that need to receive or send tokens (including
/// the faucet itself if it participates in transfer callbacks). Use [`Default`] for an empty
/// allowlist or [`Self::with_allowed_accounts`] to seed the storage map at component
/// construction time.
///
/// Allow / disallow administration is intentionally not part of this component. The
/// `allow_account` / `disallow_account` procedures live in the standards library and require
/// an auth-wrapped admin component (see [`super::AllowlistOwnerControlled`]) to be safely
/// exposed on a production faucet.
#[derive(Debug, Clone, Default)]
pub struct BasicAllowlist(BTreeSet<AccountId>);

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
        Self(allowed_accounts.into_iter().collect())
    }

    /// Returns the initial allowed accounts captured in this component.
    pub fn allowed_accounts(&self) -> &BTreeSet<AccountId> {
        &self.0
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

impl From<BasicAllowlist> for AccountComponent {
    fn from(allowlist: BasicAllowlist) -> Self {
        let storage = AllowlistStorage::with_allowed_accounts(allowlist.0);
        let storage_schema = StorageSchema::new([AllowlistStorage::allowed_accounts_slot_schema()])
            .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(
            BasicAllowlist::NAME,
            [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
        )
        .with_description(
            "Basic allowlist transfer policy: predicate procedure plus the `allowed_accounts` \
             storage map it reads",
        )
        .with_storage_schema(storage_schema);

        AccountComponent::new(BasicAllowlist::code().clone(), vec![storage.into_slot()], metadata)
            .expect(
                "basic allowlist transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
