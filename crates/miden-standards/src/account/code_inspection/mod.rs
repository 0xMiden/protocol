use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{AccountComponent, AccountComponentName, AccountProcedureRoot};

use crate::account::account_component_code;
use crate::procedure_root;

// CODE INSPECTION
// ================================================================================================

account_component_code!(CODE_INSPECTION_CODE, "code_inspection.masl");

// Initialize the procedure root of the `has_procedure` procedure only once.
procedure_root!(
    CODE_INSPECTION_HAS_PROCEDURE,
    CodeInspection::NAME,
    CodeInspection::HAS_PROCEDURE_PROC_NAME,
    CodeInspection::code()
);

// Initialize the procedure root of the `get_code_commitment` procedure only once.
procedure_root!(
    CODE_INSPECTION_GET_CODE_COMMITMENT,
    CodeInspection::NAME,
    CodeInspection::GET_CODE_COMMITMENT_PROC_NAME,
    CodeInspection::code()
);

// Initialize the procedure root of the `get_num_procedures` procedure only once.
procedure_root!(
    CODE_INSPECTION_GET_NUM_PROCEDURES,
    CodeInspection::NAME,
    CodeInspection::GET_NUM_PROCEDURES_PROC_NAME,
    CodeInspection::code()
);

// Initialize the procedure root of the `get_procedure_root` procedure only once.
procedure_root!(
    CODE_INSPECTION_GET_PROCEDURE_ROOT,
    CodeInspection::NAME,
    CodeInspection::GET_PROCEDURE_ROOT_PROC_NAME,
    CodeInspection::code()
);

/// An [`AccountComponent`] exposing read-only introspection over the account's own code.
///
/// It reexports the procedures from `miden::standards::code_inspection`, which wrap the
/// account-related kernel procedures. When linking against this component, the `miden` library
/// (i.e. [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is
/// the case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `has_procedure`, which returns whether a procedure with the given root is available on the
///   account.
/// - `get_code_commitment`, which returns the commitment to the account's code.
/// - `get_num_procedures`, which returns the number of procedures in the account.
/// - `get_procedure_root`, which returns the procedure root at the given index.
///
/// Exposing these procedures lets external callers (note scripts, transaction scripts, or foreign
/// accounts via FPI) verify what an account can do without being granted access to its storage or
/// vault. The component carries no storage of its own.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct CodeInspection;

impl CodeInspection {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::code_inspection";

    const HAS_PROCEDURE_PROC_NAME: &str = "has_procedure";
    const GET_CODE_COMMITMENT_PROC_NAME: &str = "get_code_commitment";
    const GET_NUM_PROCEDURES_PROC_NAME: &str = "get_num_procedures";
    const GET_PROCEDURE_ROOT_PROC_NAME: &str = "get_procedure_root";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &CODE_INSPECTION_CODE
    }

    /// Returns the procedure root of the `has_procedure` procedure.
    pub fn has_procedure_root() -> AccountProcedureRoot {
        *CODE_INSPECTION_HAS_PROCEDURE
    }

    /// Returns the procedure root of the `get_code_commitment` procedure.
    pub fn get_code_commitment_root() -> AccountProcedureRoot {
        *CODE_INSPECTION_GET_CODE_COMMITMENT
    }

    /// Returns the procedure root of the `get_num_procedures` procedure.
    pub fn get_num_procedures_root() -> AccountProcedureRoot {
        *CODE_INSPECTION_GET_NUM_PROCEDURES
    }

    /// Returns the procedure root of the `get_procedure_root` procedure.
    pub fn get_procedure_root_root() -> AccountProcedureRoot {
        *CODE_INSPECTION_GET_PROCEDURE_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME)
            .with_description("Read-only introspection over the account's own code")
    }
}

impl From<CodeInspection> for AccountComponent {
    fn from(_: CodeInspection) -> Self {
        let metadata = CodeInspection::component_metadata();

        AccountComponent::new(CodeInspection::code().clone(), vec![], metadata).expect(
            "code inspection component should satisfy the requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, AccountType};

    use super::CodeInspection;
    use crate::account::auth::NoAuth;

    /// Check that obtaining the code inspection procedure roots does not panic.
    #[test]
    fn get_code_inspection_procedures() {
        let _has_procedure_root = CodeInspection::has_procedure_root();
        let _get_code_commitment_root = CodeInspection::get_code_commitment_root();
        let _get_num_procedures_root = CodeInspection::get_num_procedures_root();
        let _get_procedure_root_root = CodeInspection::get_procedure_root_root();
    }

    /// Check that the component can be added to an account and that the resulting account exposes
    /// the code inspection procedures.
    #[test]
    fn account_exposes_code_inspection_procedures() -> anyhow::Result<()> {
        let account = AccountBuilder::new([1; 32])
            .account_type(AccountType::Public)
            .with_auth_component(NoAuth)
            .with_component(CodeInspection)
            .build_existing()?;

        let code = account.code();
        assert!(code.has_procedure(*CodeInspection::has_procedure_root().mast_root()));
        assert!(code.has_procedure(*CodeInspection::get_code_commitment_root().mast_root()));
        assert!(code.has_procedure(*CodeInspection::get_num_procedures_root().mast_root()));
        assert!(code.has_procedure(*CodeInspection::get_procedure_root_root().mast_root()));

        Ok(())
    }
}
