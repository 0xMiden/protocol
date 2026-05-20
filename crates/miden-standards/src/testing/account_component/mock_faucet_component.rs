use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountCode, AccountComponent};

use crate::testing::mock_account_code::MockAccountCodeExt;

// MOCK FAUCET COMPONENT
// ================================================================================================

/// A mock faucet account component for use in tests.
///
/// It uses the [`MockAccountCodeExt::mock_faucet_library`][faucet_lib] and contains no storage
/// slots.
///
/// [faucet_lib]: crate::testing::mock_account_code::MockAccountCodeExt::mock_faucet_library
pub struct MockFaucetComponent;

impl From<MockFaucetComponent> for AccountComponent {
    fn from(_: MockFaucetComponent) -> Self {
        let metadata = AccountComponentMetadata::new("miden::testing::mock_faucet")
            .with_description("Mock faucet component for testing");

        AccountComponent::new(AccountCode::mock_faucet_library(), vec![], metadata).expect(
            "mock faucet component should satisfy the requirements of a valid account component",
        )
    }
}
