use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// ZERO FEE POLICY
// ================================================================================================

account_component_code!(ZERO_FEE_POLICY_CODE, "miden-standards-fees-policies-zero-fee.masp");

procedure_root!(
    ZERO_FEE_POLICY_ROOT,
    ZeroFeePolicy::NAME,
    ZeroFeePolicy::PROC_NAME,
    ZeroFeePolicy::code()
);

/// The storage-free `zero_fee` fee policy account component.
///
/// Pair with a [`crate::account::fees::FeeManager`] whose allowed fee-policies map includes
/// [`ZeroFeePolicy::root`]. When active, every note is estimated at zero fee: `compute_note_fee`
/// returns the zero word for both the fee asset ID and the fee asset value.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroFeePolicy;

impl ZeroFeePolicy {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::fees::policies::zero_fee";

    pub(crate) const PROC_NAME: &str = "compute_note_fee";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &ZERO_FEE_POLICY_CODE
    }

    /// Returns the procedure root of the `compute_note_fee` fee policy procedure.
    pub fn root() -> AccountProcedureRoot {
        *ZERO_FEE_POLICY_ROOT
    }
}

impl From<ZeroFeePolicy> for AccountComponent {
    fn from(_: ZeroFeePolicy) -> Self {
        let metadata = AccountComponentMetadata::new(ZeroFeePolicy::NAME)
            .with_description("`zero_fee` fee policy estimating every note at zero fee");

        AccountComponent::new(ZeroFeePolicy::code().clone(), vec![], metadata).expect(
            "`zero_fee` fee policy component should satisfy the requirements of a valid account component",
        )
    }
}
