use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    AccountType,
};

use crate::account::account_component_code;
use crate::procedure_root;

// OWNER-ONLY BURN POLICY
// ================================================================================================

account_component_code!(
    OWNER_ONLY_BURN_POLICY_CODE,
    "faucets/policies/burn/owner_controlled/owner_only.masl"
);

procedure_root!(
    OWNER_ONLY_POLICY_ROOT,
    BurnOwnerOnly::NAME,
    BurnOwnerOnly::PROC_NAME,
    BurnOwnerOnly::code()
);

/// The storage-free `owner_only` burn policy account component (owner-controlled family).
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed burn-policies
/// map includes [`BurnOwnerOnly::root`]. When active, only the account owner (as recorded by
/// the `Ownable2Step` component) may trigger burn operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct BurnOwnerOnly;

impl BurnOwnerOnly {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::burn::owner_controlled::owner_only";

    pub(crate) const PROC_NAME: &str = "check_policy";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &OWNER_ONLY_BURN_POLICY_CODE
    }

    /// Returns the procedure root of the `owner_only` burn policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *OWNER_ONLY_POLICY_ROOT
    }
}

impl From<BurnOwnerOnly> for AccountComponent {
    fn from(_: BurnOwnerOnly) -> Self {
        let metadata =
            AccountComponentMetadata::new(BurnOwnerOnly::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "`owner_only` burn policy (owner-controlled family) for fungible faucets",
                );

        AccountComponent::new(BurnOwnerOnly::code().clone(), vec![], metadata).expect(
            "`owner_only` burn policy component should satisfy the requirements of a valid account component",
        )
    }
}
