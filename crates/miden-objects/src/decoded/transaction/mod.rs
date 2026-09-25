//! Domain construction for decoded transaction messages.

#[cfg(test)]
pub(crate) mod test_utils;

mod core;
pub use core::{
    ProvenTransaction,
    TransactionHeader,
    TransactionHeaderBuildError,
    TransactionId,
    TxAccountUpdate,
};

mod effects;
pub use effects::{TransactionEffects, TransactionEffectsV1};

mod args;
pub use args::{NoteArgument, TransactionArgs, TransactionArgsError, TransactionScript};

mod notes;
pub use notes::{
    AuthenticatedInputNote,
    InputNote,
    InputNoteCommitment,
    InputNoteError,
    InputNotes,
    OutputNote,
    PrivateOutputNote,
    PublicOutputNote,
    RawOutputNote,
    RawOutputNotes,
};

mod inputs;
pub use inputs::{
    ForeignAccountSlotName,
    ForeignAccountSlotNameError,
    TransactionInputs,
    TransactionInputsError,
    TransactionInputsV1,
};

mod batch;
pub use batch::{
    BatchAccountUpdate,
    ProposedBatch,
    ProposedBatchError,
    ProvenBatch,
    ProvenBatchError,
};
