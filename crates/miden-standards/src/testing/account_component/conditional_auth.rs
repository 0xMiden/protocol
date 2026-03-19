use alloc::string::String;

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountComponentCode, AccountType};
use miden_protocol::utils::sync::LazyLock;

use crate::code_builder::CodeBuilder;

pub const ERR_WRONG_ARGS_MSG: &str = "auth procedure args are incorrect";

static CONDITIONAL_AUTH_CODE: LazyLock<String> = LazyLock::new(|| {
    format!(
        r#"
        use miden::protocol::native_account

        const WRONG_ARGS="{ERR_WRONG_ARGS_MSG}"

        @auth_script
        pub proc auth_conditional
            # => [AUTH_ARGS]

            # If [97, 98, 99] is passed as an argument, all good.
            # Otherwise we error out.
            push.97 assert_eq.err=WRONG_ARGS
            push.98 assert_eq.err=WRONG_ARGS
            push.99 assert_eq.err=WRONG_ARGS

            # Last element is the incr_nonce_flag.
            if.true
                exec.native_account::incr_nonce drop
            end
            dropw dropw dropw dropw
        end
"#
    )
});

static CONDITIONAL_AUTH_LIBRARY: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code("mock::conditional_auth", CONDITIONAL_AUTH_CODE.as_str())
        .expect("conditional auth code should be valid")
});

/// Creates a mock authentication [`AccountComponent`] for testing purposes.
///
/// The component defines an `auth_conditional` procedure that conditionally succeeds and
/// conditionally increments the nonce based on the authentication arguments.
///
/// The auth procedure expects the first three arguments as [99, 98, 97] to succeed.
/// In case it succeeds, it conditionally increments the nonce based on the fourth argument.
pub struct ConditionalAuthComponent;

impl From<ConditionalAuthComponent> for AccountComponent {
    fn from(_: ConditionalAuthComponent) -> Self {
        let metadata =
            AccountComponentMetadata::new("miden::testing::conditional_auth", AccountType::all())
                .with_description("Testing auth component with conditional behavior");

        AccountComponent::new(CONDITIONAL_AUTH_LIBRARY.clone(), vec![], metadata)
            .expect("component should be valid")
    }
}
