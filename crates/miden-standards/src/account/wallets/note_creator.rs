use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// NOTE CREATOR
// ================================================================================================

account_component_code!(NOTE_CREATOR_CODE, "miden-standards-wallets-note-creator.masp");

// Initialize the procedure root of the `create_note` procedure of the Note Creator only once.
procedure_root!(
    NOTE_CREATOR_CREATE_NOTE,
    NoteCreator::NAME,
    NoteCreator::CREATE_NOTE_PROC_NAME,
    NoteCreator::code()
);

/// An [`AccountComponent`] exposing only the `create_note` procedure.
///
/// When linking against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder].
///
/// `create_note` requires authentication. Thus, this component must be combined with a component
/// providing authentication.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct NoteCreator;

impl NoteCreator {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::note::note_creator";

    const CREATE_NOTE_PROC_NAME: &str = "create_note";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NOTE_CREATOR_CODE
    }

    /// Returns the procedure root of the `create_note` procedure.
    pub fn create_note_root() -> AccountProcedureRoot {
        *NOTE_CREATOR_CREATE_NOTE
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Note creator component exposing only the create_note procedure")
    }
}

impl From<NoteCreator> for AccountComponent {
    fn from(_: NoteCreator) -> Self {
        let metadata = NoteCreator::component_metadata();

        AccountComponent::new(NoteCreator::code().clone(), vec![], metadata).expect(
            "note creator component should satisfy the requirements of a valid account component",
        )
    }
}
