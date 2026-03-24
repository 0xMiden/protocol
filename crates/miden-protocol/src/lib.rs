#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod account;
pub mod address;
pub mod asset;
pub mod batch;
pub mod block;
pub mod errors;
pub mod note;
mod protocol;
pub mod transaction;

#[cfg(any(feature = "testing", test))]
pub mod testing;

mod constants;

// RE-EXPORTS
// ================================================================================================

pub use constants::*;
pub use miden_core::mast::{MastForest, MastNodeId};
pub use miden_core::prettier::PrettyPrint;
pub use miden_core::{EMPTY_WORD, Felt, ONE, WORD_SIZE, ZERO, field};
pub use miden_core_lib::CoreLibrary;
pub use miden_crypto::hash::poseidon2::Poseidon2 as Hasher;
pub use miden_crypto::word;
pub use miden_crypto::word::{Word, WordError};
pub use protocol::ProtocolLib;

pub mod assembly {
    pub use miden_assembly::ast::{Module, ModuleKind, ProcedureName, QualifiedProcedureName};
    pub use miden_assembly::debuginfo::SourceManagerSync;
    pub use miden_assembly::library::LibraryExport;
    pub use miden_assembly::{
        Assembler,
        DefaultSourceManager,
        KernelLibrary,
        Library,
        Parse,
        ParseOptions,
        Path,
        SourceFile,
        SourceId,
        SourceManager,
        SourceSpan,
        debuginfo,
        diagnostics,
        mast,
    };
}

pub mod crypto {
    pub use miden_crypto::{SequentialCommit, dsa, hash, ies, merkle, rand, utils};
}

pub mod utils {
    pub use miden_core::utils::*;
    pub use miden_crypto::utils::{HexParseError, bytes_to_hex_string, hex_to_bytes};
    pub use miden_utils_sync as sync;

    pub mod serde {
        pub use miden_crypto::utils::{
            BudgetedReader,
            ByteReader,
            ByteWriter,
            Deserializable,
            DeserializationError,
            Serializable,
            SliceReader,
        };
    }
}

pub mod vm {
    pub use miden_assembly_syntax::ast::{AttributeSet, QualifiedProcedureName};
    pub use miden_core::advice::{AdviceInputs, AdviceMap};
    pub use miden_core::events::{EventId, EventName, SystemEvent};
    pub use miden_core::program::{Program, ProgramInfo};
    pub use miden_mast_package::{
        MastArtifact,
        Package,
        PackageExport,
        PackageKind,
        PackageManifest,
        ProcedureExport,
        Section,
        SectionId,
    };
    pub use miden_processor::trace::RowIndex;
    pub use miden_processor::{FutureMaybeSend, StackInputs, StackOutputs};
    pub use miden_verifier::ExecutionProof;
}
