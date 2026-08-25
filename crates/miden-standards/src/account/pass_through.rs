use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// PASS THROUGH
// ================================================================================================

account_component_code!(PASS_THROUGH_CODE, "miden-standards-pass-through.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from [`PassThrough::NAME`],
/// which mirrors the standards-side MASM module path.
const PASS_THROUGH_LIBRARY_PATH: &str = "miden::standards::components::pass_through";

// Initialize the procedure root of the `sweep_asset_to_note` procedure only once.
procedure_root!(
    PASS_THROUGH_SWEEP_ASSET_TO_NOTE,
    PASS_THROUGH_LIBRARY_PATH,
    PassThrough::SWEEP_ASSET_TO_NOTE_PROC_NAME,
    PassThrough::code()
);

// Initialize the procedure root of the `assert_vault_unchanged` procedure only once.
procedure_root!(
    PASS_THROUGH_ASSERT_VAULT_UNCHANGED,
    PASS_THROUGH_LIBRARY_PATH,
    PassThrough::ASSERT_VAULT_UNCHANGED_PROC_NAME,
    PassThrough::code()
);

/// An [`AccountComponent`] providing the account procedures a pass-through transaction needs.
///
/// A transaction script has no account context, so it cannot read the account's vault. This
/// component exposes the two steps that need it, for the pass-through transaction scripts (e.g.
/// [`PassThroughSingleP2idTransactionScript`][single]) to `call`:
/// - `sweep_asset_to_note`, which moves the account's entire balance of an asset into an output
///   note.
/// - `assert_vault_unchanged`, which asserts the vault is the one the transaction started with.
///
/// Both require authentication. Thus, this component must be combined with a component providing
/// authentication, and with one exposing `receive_asset` (e.g.
/// [`BasicWallet`](crate::account::wallets::BasicWallet)) so that input notes can deposit into the
/// account in the first place.
///
/// [single]: crate::tx_script::PassThroughSingleP2idTransactionScript
pub struct PassThrough;

impl PassThrough {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::pass_through";

    const SWEEP_ASSET_TO_NOTE_PROC_NAME: &str = "sweep_asset_to_note";
    const ASSERT_VAULT_UNCHANGED_PROC_NAME: &str = "assert_vault_unchanged";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PASS_THROUGH_CODE
    }

    /// Returns the procedure root of the `sweep_asset_to_note` procedure.
    pub fn sweep_asset_to_note_root() -> AccountProcedureRoot {
        *PASS_THROUGH_SWEEP_ASSET_TO_NOTE
    }

    /// Returns the procedure root of the `assert_vault_unchanged` procedure.
    pub fn assert_vault_unchanged_root() -> AccountProcedureRoot {
        *PASS_THROUGH_ASSERT_VAULT_UNCHANGED
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME).with_description(
            "Pass-through component exposing the account procedures a pass-through transaction \
             needs",
        )
    }
}

impl From<PassThrough> for AccountComponent {
    fn from(_: PassThrough) -> Self {
        let metadata = PassThrough::component_metadata();

        AccountComponent::new(PassThrough::code().clone(), vec![], metadata).expect(
            "pass through component should satisfy the requirements of a valid account component",
        )
    }
}
