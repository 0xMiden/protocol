pub mod access;
pub mod auth;
pub mod components;
pub mod faucets;
pub mod fees;
pub mod inspection;
pub mod interface;
pub mod note_creator;
pub mod oracle;
pub mod policies;
pub mod upgrade;
pub mod wallets;

pub use inspection::AccountBuilderSchemaCommitmentExt;

/// Macro to simplify the creation of static procedure root constants.
///
/// This macro generates a `LazyLock<AccountProcedureRoot>` static variable that lazily initializes
/// the procedure root of a procedure from an [`AccountComponentCode`].
///
/// The full procedure path is constructed by concatenating `$component_name` and `$proc_name`
/// with `::` as separator (i.e. `"{component_name}::{proc_name}"`).
///
/// Note: This macro references exported types from `miden_protocol`, so your crate must
/// include `miden_protocol` as a dependency. The expanded code uses `::alloc::format!`, so
/// downstream callers must also have `extern crate alloc;` (or otherwise expose `alloc` at the
/// crate root) - this is automatic in `std`-linked binaries.
///
/// # Arguments
/// * `$name` - The name of the static variable to create
/// * `$component_name` - The name of the component (e.g. `BasicWallet::NAME`)
/// * `$proc_name` - The short name of the procedure (e.g. `"receive_asset"`)
/// * `$component_code` - An expression evaluating to `&AccountComponentCode` (or any type coercible
///   via `Deref` such as `&LazyLock<AccountComponentCode>`).
///
/// [`AccountComponentCode`]: miden_protocol::account::AccountComponentCode
///
/// # Example
/// ```ignore
/// procedure_root!(
///     BASIC_WALLET_RECEIVE_ASSET,
///     BasicWallet::NAME,
///     BasicWallet::RECEIVE_ASSET_PROC_NAME,
///     BasicWallet::code()
/// );
/// ```
#[macro_export]
macro_rules! procedure_root {
    ($name:ident, $component_name:expr, $proc_name:expr, $component_code:expr) => {
        static $name: miden_protocol::utils::sync::LazyLock<
            miden_protocol::account::AccountProcedureRoot,
        > = miden_protocol::utils::sync::LazyLock::new(|| {
            let full_path = ::alloc::format!("{}::{}", $component_name, $proc_name);
            let code: &miden_protocol::account::AccountComponentCode = $component_code;
            code.get_procedure_root_by_path(full_path.as_str())
                .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
        });
    };
}

/// Macro to declare a static `LazyLock<AccountComponentCode>` initialized from a `.masp` asset
/// shipped by the `miden-standards` build script.
///
/// `$relative_path` is appended to `concat!(env!("OUT_DIR"), "/assets/components/")` and the
/// resulting bytes are deserialized into a [`Package`], which is then wrapped into an
/// [`AccountComponentCode`].
///
/// This macro is intended for use **inside the `miden-standards` crate only**: it relies on
/// `env!("OUT_DIR")` resolving against `miden-standards`'s build script, which is where the
/// `components` assets are written.
///
/// [`Package`]: miden_protocol::vm::Package
/// [`AccountComponentCode`]: miden_protocol::account::component::AccountComponentCode
///
/// # Example
/// ```ignore
/// account_component_code!(BASIC_WALLET_CODE, "miden-standards-wallets-basic-wallet.masp");
/// ```
macro_rules! account_component_code {
    ($name:ident, $relative_path:expr) => {
        static $name: miden_protocol::utils::sync::LazyLock<
            miden_protocol::account::component::AccountComponentCode,
        > = miden_protocol::utils::sync::LazyLock::new(|| {
            let bytes =
                include_bytes!(concat!(env!("OUT_DIR"), "/assets/components/", $relative_path));
            // These bytes are produced by this crate's build script and embedded in the binary.
            let package = miden_protocol::vm::Package::read_from_bytes_trusted(bytes)
                .expect("shipped account-component package failed to deserialize");
            miden_protocol::account::component::AccountComponentCode::from(package)
        });
    };
}

pub(crate) use account_component_code;
