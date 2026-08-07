use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// OWNER-ONLY MINT POLICY
// ================================================================================================

account_component_code!(
    OWNER_ONLY_MINT_POLICY_CODE,
    "miden-standards-faucets-policies-mint-owner-controlled-owner-only.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`MintOwnerOnly::NAME`],
/// which mirrors the standards-side MASM module path.
const MINT_OWNER_ONLY_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::mint::owner_controlled::owner_only";

procedure_root!(
    OWNER_ONLY_POLICY_ROOT,
    MINT_OWNER_ONLY_LIBRARY_PATH,
    MintOwnerOnly::PROC_NAME,
    MintOwnerOnly::code()
);

/// The storage-free `owner_only` mint policy account component (owner-controlled family).
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed mint-policies
/// map includes [`MintOwnerOnly::root`]. When active, only the account owner (as recorded by
/// the `Ownable2Step` component) may trigger mint operations.
///
/// Companion components required:
/// - [`crate::account::access::Ownable2Step`] — provides the owner storage slot the auth check
///   reads. The slot is declared as a required slot of
///   [`MintPolicy::owner_only`][crate::account::policies::MintPolicy::owner_only], so the faucet
///   factories reject an account that does not install it; an account assembled by hand should run
///   the same check via
///   [`verify_policy_dependencies`][crate::account::policies::verify_policy_dependencies],
///   otherwise it builds successfully and every mint reverts.
#[derive(Debug, Clone, Copy, Default)]
pub struct MintOwnerOnly;

impl MintOwnerOnly {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::faucets::policies::mint::owner_controlled::owner_only";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &OWNER_ONLY_MINT_POLICY_CODE
    }

    /// Returns the procedure root of the `owner_only` mint policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<MintOwnerOnly> for AccountComponent {
    fn from(_: MintOwnerOnly) -> Self {
        let metadata = AccountComponentMetadata::new(MintOwnerOnly::NAME).with_description(
            "`owner_only` mint policy (owner-controlled family) for fungible faucets",
        );

        AccountComponent::new(MintOwnerOnly::code().clone(), vec![], metadata).expect(
            "`owner_only` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
