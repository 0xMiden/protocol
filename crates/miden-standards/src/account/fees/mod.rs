use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountType};

use crate::account::components::native_fee_library;

/// Default fee component that pays transaction fees in the native asset.
///
/// This component provides a `@fee_script` procedure that converts computation units
/// into the native fungible asset at a 1:1 rate. FEE_ARGS are ignored.
///
/// Accounts using this component pay fees exactly as they do today: in the native asset,
/// proportional to computation cost. For accounts that want to pay in a different asset,
/// a custom fee component can be provided instead.
pub struct NativeFee;

impl NativeFee {
    pub const NAME: &'static str = "miden::standards::components::fees::native_fee";

    pub fn new() -> Self {
        Self
    }

    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description("Default fee component paying in the native asset")
    }
}

impl Default for NativeFee {
    fn default() -> Self {
        Self::new()
    }
}

impl From<NativeFee> for AccountComponent {
    fn from(_: NativeFee) -> Self {
        let metadata = NativeFee::component_metadata();

        AccountComponent::new(native_fee_library(), vec![], metadata).expect(
            "NativeFee component should satisfy the requirements of a valid account component",
        )
    }
}
