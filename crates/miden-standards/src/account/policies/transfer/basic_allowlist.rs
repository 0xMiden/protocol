use alloc::collections::BTreeSet;

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountId, AccountProcedureRoot};

use crate::account::policies::transfer::allowlist::AllowlistStorage;
use crate::account::{account_component_code, package_metadata};
use crate::procedure_root;

// BASIC ALLOWLIST TRANSFER POLICY
// ================================================================================================

account_component_code!(
    BASIC_ALLOWLIST_TRANSFER_POLICY_CODE,
    "miden-standards-faucets-policies-transfer-basic-allowlist.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`BasicAllowlist::NAME`],
/// which mirrors the standards-side MASM module path.
const BASIC_ALLOWLIST_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::basic_allowlist";

procedure_root!(
    BASIC_ALLOWLIST_TRANSFER_POLICY_ROOT,
    BASIC_ALLOWLIST_LIBRARY_PATH,
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
/// The issuing faucet is exempt from its own allowlist.
///
/// Allow / disallow administration is intentionally not part of this component. The
/// `allow_account` / `disallow_account` procedures live in the standards library and require
/// an auth-wrapped admin component (see [`super::AllowlistManager`]) to be safely
/// exposed on a production faucet.
#[derive(Debug, Clone, Default)]
pub struct BasicAllowlist(AllowlistStorage);

impl BasicAllowlist {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::faucets::policies::transfer::basic_allowlist";

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

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<AllowlistStorage> for BasicAllowlist {
    fn from(storage: AllowlistStorage) -> Self {
        Self(storage)
    }
}

impl From<BasicAllowlist> for AccountComponent {
    fn from(allowlist: BasicAllowlist) -> Self {
        let metadata = BasicAllowlist::component_metadata();

        AccountComponent::new(BasicAllowlist::code().clone(), vec![allowlist.0.into_slot()], metadata)
            .expect(
                "basic allowlist transfer policy component should satisfy the requirements of a valid account component",
            )
    }
}
