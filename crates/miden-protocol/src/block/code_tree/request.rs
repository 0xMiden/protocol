use alloc::collections::BTreeSet;

use crate::code::ProcedureRoot;

// CODE WITNESS REQUEST
// ================================================================================================

/// A request for the [`CodeWitness`](super::CodeWitness)es of a top-level procedure root and of the
/// procedures that its code references.
///
/// The witnesses of the referenced procedures are only needed if the top-level procedure root is
/// absent, because the code of a present procedure root is already registered. Grouping the
/// procedures by their top-level root lets the provider of the witnesses skip them otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeWitnessRequest {
    procedure_root: ProcedureRoot,
    referenced_procedures: BTreeSet<ProcedureRoot>,
}

impl CodeWitnessRequest {
    /// Creates a new [`CodeWitnessRequest`] from a top-level procedure root and the procedures that
    /// its code references, directly or indirectly.
    pub fn new(
        procedure_root: ProcedureRoot,
        referenced_procedures: BTreeSet<ProcedureRoot>,
    ) -> Self {
        Self { procedure_root, referenced_procedures }
    }

    /// Returns the top-level procedure root.
    pub fn procedure_root(&self) -> ProcedureRoot {
        self.procedure_root
    }

    /// Returns the procedures that the code of the top-level procedure root references.
    pub fn referenced_procedures(&self) -> &BTreeSet<ProcedureRoot> {
        &self.referenced_procedures
    }
}
