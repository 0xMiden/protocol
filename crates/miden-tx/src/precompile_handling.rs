/// Selects how the transaction epilogue handles its precompile obligations.
///
/// Execution and proving may choose different modes when re-executing a transaction. This choice
/// controls proof production; it does not change which proof states a verifier accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PrecompileHandling {
    /// Leaves the accumulator unchanged and carries any outstanding work in a deferred witness.
    ///
    /// The resulting VM proof alone does not recursively attest to that work. An execution with
    /// no precompile obligations still produces a complete proof.
    Deferred = 0,

    /// Recursively verifies a precompile proof under the authenticated protocol security policy,
    /// then clears the verified obligation. The resulting transaction proof has no external
    /// precompile work.
    ///
    /// Execution fails if the proof does not meet the minimum security. Raising precompile work
    /// limits can exceed the security supported by the VM's fixed proof parameters.
    #[default]
    Recursive = 1,
}
