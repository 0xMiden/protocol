use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot, AccountType};
use miden_protocol::assembly::Library;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::utils::sync::LazyLock;

use crate::procedure_digest;

// OWNER-ONLY MINT POLICY
// ================================================================================================

// Initialize the `owner_only` Mint Policy component code only once.
static OWNER_ONLY_MINT_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/policies/mint/owner_controlled/owner_only.masl"
    ));
    let library = Library::read_from_bytes(bytes)
        .expect("Shipped `owner_only` Mint Policy library is well-formed");
    AccountComponentCode::from(library)
});

procedure_digest!(
    OWNER_ONLY_POLICY_ROOT,
    MintOwnerOnly::NAME,
    MintOwnerOnly::PROC_NAME,
    MintOwnerOnly::code()
);

/// The storage-free `owner_only` mint policy account component (owner-controlled family).
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose allowed mint-policies
/// map includes [`MintOwnerOnly::root`]. When active, only the account owner (as recorded by
/// the `Ownable2Step` component) may trigger mint operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MintOwnerOnly;

impl MintOwnerOnly {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::components::faucets::policies::mint::owner_controlled::owner_only";

    pub(crate) const PROC_NAME: &str = "check_policy";

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
        let metadata =
            AccountComponentMetadata::new(MintOwnerOnly::NAME, [AccountType::FungibleFaucet])
                .with_description(
                    "`owner_only` mint policy (owner-controlled family) for fungible faucets",
                );

        AccountComponent::new(MintOwnerOnly::code().clone(), vec![], metadata).expect(
            "`owner_only` mint policy component should satisfy the requirements of a valid account component",
        )
    }
}
