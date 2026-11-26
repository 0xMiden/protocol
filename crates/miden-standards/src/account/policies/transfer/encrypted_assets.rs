use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountProcedureRoot};

use crate::account::account_component_package;
use crate::procedure_root;

// ENCRYPTED ASSETS SEND POLICY
// ================================================================================================

account_component_package!(
    ENCRYPTED_ASSETS_SEND_POLICY_PACKAGE,
    "miden-standards-faucets-policies-transfer-encrypted-assets.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`EncryptedAssetsSendPolicy::NAME`], which mirrors the standards-side MASM module path.
const ENCRYPTED_ASSETS_SEND_POLICY_LIBRARY_PATH: &str =
    "miden::standards::components::faucets::policies::transfer::encrypted_assets";

procedure_root!(
    ENCRYPTED_ASSETS_SEND_POLICY_ROOT,
    ENCRYPTED_ASSETS_SEND_POLICY_LIBRARY_PATH,
    EncryptedAssetsSendPolicy::SEND_PROC_NAME,
    EncryptedAssetsSendPolicy::code()
);

/// The storage-free encrypted assets send policy account component.
///
/// Pair with a [`crate::account::policies::TokenPolicyManager`] whose send policy map includes
/// [`EncryptedAssetsSendPolicy::send_root`], e.g. through
/// [`SendPolicy::with_encrypted_assets`](super::SendPolicy::with_encrypted_assets), which also
/// installs the [`EncryptedAssetsIssuerKey`](crate::note::EncryptedAssetsIssuerKey). When active,
/// the policy returns the [`EncryptedAssetsAttachment`](crate::note::EncryptedAssetsAttachment) of
/// every private output note holding the faucet's assets, encrypted to that key, and rejects a
/// private note that holds more than one asset. Public notes get no attachment.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncryptedAssetsSendPolicy;

impl EncryptedAssetsSendPolicy {
    /// The name of the component.
    pub const NAME: &'static str =
        "miden::standards::faucets::policies::transfer::encrypted_assets";

    pub(crate) const SEND_PROC_NAME: &str = "check_send_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ENCRYPTED_ASSETS_SEND_POLICY_PACKAGE.code
    }

    /// Returns the procedure root of the send policy procedure.
    pub fn send_root() -> AccountProcedureRoot {
        *ENCRYPTED_ASSETS_SEND_POLICY_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        ENCRYPTED_ASSETS_SEND_POLICY_PACKAGE.metadata.clone()
    }
}

impl From<EncryptedAssetsSendPolicy> for AccountComponent {
    fn from(_: EncryptedAssetsSendPolicy) -> Self {
        let metadata = EncryptedAssetsSendPolicy::component_metadata();

        AccountComponent::new(EncryptedAssetsSendPolicy::code().clone(), vec![], metadata).expect(
            "encrypted assets send policy component should satisfy the requirements of a valid account component",
        )
    }
}
