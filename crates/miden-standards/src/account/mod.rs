use super::auth_method::AuthMethod;

pub mod access;
pub mod auth;
pub mod components;
pub mod faucets;
pub mod interface;
pub mod metadata;
pub mod policies;
pub mod wallets;

pub use metadata::AccountBuilderSchemaCommitmentExt;

/// Macro to simplify the creation of static procedure root constants.
///
/// This macro generates a `LazyLock<AccountProcedureRoot>` static variable that lazily initializes
/// the procedure root of a procedure from an [`AccountComponentCode`].
///
/// The full procedure path is constructed by concatenating `$component_name` and `$proc_name`
/// with `::` as separator (i.e. `"{component_name}::{proc_name}"`).
///
/// Note: This macro references exported types from `miden_protocol`, so your crate must
/// include `miden_protocol` as a dependency.
///
/// # Arguments
/// * `$name` - The name of the static variable to create
/// * `$component_name` - The name of the component (e.g. `BasicWallet::NAME`)
/// * `$proc_name` - The short name of the procedure (e.g. `"receive_asset"`)
/// * `$component_code` - An expression evaluating to `&AccountComponentCode` (typically the
///   component's `code()` accessor)
///
/// [`AccountComponentCode`]: miden_protocol::account::AccountComponentCode
///
/// # Example
/// ```ignore
/// procedure_digest!(
///     BASIC_WALLET_RECEIVE_ASSET,
///     BasicWallet::NAME,
///     BasicWallet::RECEIVE_ASSET_PROC_NAME,
///     BasicWallet::code()
/// );
/// ```
#[macro_export]
macro_rules! procedure_digest {
    ($name:ident, $component_name:expr, $proc_name:expr, $component_code:expr) => {
        static $name: miden_protocol::utils::sync::LazyLock<
            miden_protocol::account::AccountProcedureRoot,
        > = miden_protocol::utils::sync::LazyLock::new(|| {
            let full_path = alloc::format!("{}::{}", $component_name, $proc_name);
            let code: &miden_protocol::account::AccountComponentCode = $component_code;
            code.get_procedure_root_by_path(full_path.as_str()).unwrap_or_else(|| {
                panic!("component '{}' should contain procedure '{}'", $component_name, full_path)
            })
        });
    };
}
