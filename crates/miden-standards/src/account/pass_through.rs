use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// PASS THROUGH SWEEP
// ================================================================================================

account_component_code!(PASS_THROUGH_SWEEP_CODE, "miden-standards-pass-through-sweep.masp");

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`PassThroughSweep::NAME`], which mirrors the standards-side MASM module path.
const PASS_THROUGH_SWEEP_LIBRARY_PATH: &str = "miden::standards::components::pass_through::sweep";

// Initialize the procedure root of the `sweep_asset_to_note` procedure only once.
procedure_root!(
    PASS_THROUGH_SWEEP_ASSET_TO_NOTE,
    PASS_THROUGH_SWEEP_LIBRARY_PATH,
    PassThroughSweep::SWEEP_ASSET_TO_NOTE_PROC_NAME,
    PassThroughSweep::code()
);

/// An [`AccountComponent`] moving whole account balances into an output note.
///
/// It exposes `sweep_asset_to_note` for the pass-through transaction scripts that forward whole
/// balances (e.g. [`PassThroughSingleP2idTransactionScript`][single]) to `call`.
///
/// # Security
///
/// `sweep_asset_to_note` reads the balance itself, unlike
/// [`BasicWallet`](crate::account::wallets::BasicWallet)'s `move_asset_to_note`, which makes the
/// caller name the amount, so it needs no prior knowledge of what the vault holds. It asserts the
/// account did not hold the asset when the transaction started, which bounds it to what the
/// transaction deposited, but nothing bounds who moves that: any note script the account consumes
/// can call it and redirect what earlier notes deposited, and on an account whose auth procedure
/// authenticates nobody - which is what keeps a pass-through account's commitment unchanged - any
/// third party can execute a transaction as the account and name themselves as the destination.
///
/// Assets passing through are therefore only safe if the input note's own script constrains where
/// they go, or if they were already unrestricted before they arrived.
/// [`TxFeeNote`](crate::note::TxFeeNote)s are the latter: any account may consume one, so routing
/// them through a pass-through account takes nothing away. Routing a destination-restricted note
/// such as [`P2idNote`](crate::note::P2idNote) through one instead destroys that restriction,
/// since the assets become claimable by whoever executes the next transaction as the account.
///
/// It is an account procedure, so the component must be combined with an authentication component
/// - for a pass-through account [`AuthPassThrough`](crate::account::auth::AuthPassThrough), which
/// asserts the account's state is unchanged and so catches an asset the script fails to move out -
/// and with one exposing `receive_asset` (e.g.
/// [`BasicWallet`](crate::account::wallets::BasicWallet)) so that input notes can deposit into the
/// account in the first place.
///
/// [single]: crate::tx_script::PassThroughSingleP2idTransactionScript
pub struct PassThroughSweep;

impl PassThroughSweep {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::pass_through::sweep";

    const SWEEP_ASSET_TO_NOTE_PROC_NAME: &str = "sweep_asset_to_note";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &PASS_THROUGH_SWEEP_CODE
    }

    /// Returns the procedure root of the `sweep_asset_to_note` procedure.
    pub fn sweep_asset_to_note_root() -> AccountProcedureRoot {
        *PASS_THROUGH_SWEEP_ASSET_TO_NOTE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Pass-through component moving whole account balances into a note")
    }
}

impl From<PassThroughSweep> for AccountComponent {
    fn from(_: PassThroughSweep) -> Self {
        let metadata = PassThroughSweep::component_metadata();

        AccountComponent::new(PassThroughSweep::code().clone(), vec![], metadata).expect(
            "pass through sweep component should satisfy the requirements of a valid account \
             component",
        )
    }
}
