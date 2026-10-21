use miden_protocol::account::StorageSlotName;
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
};
use miden_protocol::vm::Package;

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

/// The code and metadata of an account component shipped by this crate.
pub(crate) struct ComponentPackage {
    pub(crate) code: AccountComponentCode,
    pub(crate) metadata: AccountComponentMetadata,
}

impl ComponentPackage {
    /// Deserializes a component package produced by this crate's build script and splits it into
    /// its [`AccountComponentMetadata`] and its [`AccountComponentCode`].
    ///
    /// The metadata is declared in the component's `miden-project.toml` manifest and embedded into
    /// the package by the build script. Converting the package into [`AccountComponentCode`]
    /// removes the metadata section, so the metadata is only reachable through this struct.
    pub(crate) fn from_package_bytes(bytes: &[u8]) -> Self {
        // These bytes are produced by this crate's build script and embedded in the binary.
        let package = Package::read_from_bytes_trusted(bytes)
            .expect("shipped account-component package failed to deserialize");
        let metadata = AccountComponentMetadata::try_from(&package)
            .expect("shipped component package should declare account component metadata");

        Self {
            code: AccountComponentCode::from(package),
            metadata,
        }
    }
}

/// Macro to declare a static `LazyLock<ComponentPackage>` initialized from a `.masp` asset
/// shipped by the `miden-standards` build script.
///
/// `$relative_path` is appended to `concat!(env!("OUT_DIR"), "/assets/components/")` and the
/// resulting bytes are split into the component's [`AccountComponentCode`] and
/// [`AccountComponentMetadata`] by [`ComponentPackage::from_package_bytes`].
///
/// This macro is intended for use **inside the `miden-standards` crate only**: it relies on
/// `env!("OUT_DIR")` resolving against `miden-standards`'s build script, which is where the
/// `components` assets are written.
///
/// # Example
/// ```ignore
/// account_component_package!(BASIC_WALLET_PACKAGE, "miden-standards-wallets-basic-wallet.masp");
/// ```
macro_rules! account_component_package {
    ($name:ident, $relative_path:expr) => {
        static $name: miden_protocol::utils::sync::LazyLock<crate::account::ComponentPackage> =
            miden_protocol::utils::sync::LazyLock::new(|| {
                crate::account::ComponentPackage::from_package_bytes(include_bytes!(concat!(
                    env!("OUT_DIR"),
                    "/assets/components/",
                    $relative_path
                )))
            });
    };
}

pub(crate) use account_component_package;

/// Returns `metadata` with the given slots removed from its storage schema.
///
/// Used by components whose manifest declares the superset of all possible slots while a
/// particular configuration installs only a subset.
pub(crate) fn metadata_without_slots(
    metadata: AccountComponentMetadata,
    excluded: &[&StorageSlotName],
) -> AccountComponentMetadata {
    let slots = metadata
        .storage_schema()
        .iter()
        .filter(|(slot_name, _)| !excluded.contains(slot_name))
        .map(|(slot_name, schema)| (slot_name.clone(), schema.clone()));
    let storage_schema = StorageSchema::new(slots).expect("a subset of a valid schema is valid");

    metadata.with_storage_schema(storage_schema)
}
