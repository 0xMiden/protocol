use core::fmt;

pub mod trace_capture;
pub mod utils;

/// Indicates the type of the transaction execution benchmark
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBenchmark {
    ConsumeSingleP2IDFalcon,
    ConsumeSingleP2IDEcdsa,
    ConsumeTwoP2IDFalcon,
    ConsumeTwoP2IDEcdsa,
    CreateSingleP2IDFalcon,
    CreateSingleP2IDEcdsa,
    ConsumeClaimNoteL1ToMiden,
    ConsumeClaimNoteL2ToMiden,
    ConsumeB2AggNote,
    ConsumeB2AggNotePopulated2p31,
    ConsumeB2AggNotePopulated2p31m1,
}

impl ExecutionBenchmark {
    /// All benchmark scenarios, in the order their results appear in `bench-tx.json`.
    pub const fn all() -> &'static [ExecutionBenchmark] {
        &[
            ExecutionBenchmark::ConsumeSingleP2IDFalcon,
            ExecutionBenchmark::ConsumeSingleP2IDEcdsa,
            ExecutionBenchmark::ConsumeTwoP2IDFalcon,
            ExecutionBenchmark::ConsumeTwoP2IDEcdsa,
            ExecutionBenchmark::CreateSingleP2IDFalcon,
            ExecutionBenchmark::CreateSingleP2IDEcdsa,
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden,
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden,
            ExecutionBenchmark::ConsumeB2AggNote,
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31,
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31m1,
        ]
    }
}

impl fmt::Display for ExecutionBenchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionBenchmark::ConsumeSingleP2IDFalcon => {
                write!(f, "consume single P2ID note with Falcon signing")
            },
            ExecutionBenchmark::ConsumeSingleP2IDEcdsa => {
                write!(f, "consume single P2ID note with ECDSA signing")
            },
            ExecutionBenchmark::ConsumeTwoP2IDFalcon => {
                write!(f, "consume two P2ID notes with Falcon signing")
            },
            ExecutionBenchmark::ConsumeTwoP2IDEcdsa => {
                write!(f, "consume two P2ID notes with ECDSA signing")
            },
            ExecutionBenchmark::CreateSingleP2IDFalcon => {
                write!(f, "create single P2ID note with Falcon signing")
            },
            ExecutionBenchmark::CreateSingleP2IDEcdsa => {
                write!(f, "create single P2ID note with ECDSA signing")
            },
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden => {
                write!(f, "consume CLAIM note (L1 to Miden)")
            },
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden => {
                write!(f, "consume CLAIM note (L2 to Miden)")
            },
            ExecutionBenchmark::ConsumeB2AggNote => {
                write!(f, "consume B2AGG note (bridge-out)")
            },
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31 => {
                write!(f, "consume B2AGG note (bridge-out, 2^31 leaves)")
            },
            ExecutionBenchmark::ConsumeB2AggNotePopulated2p31m1 => {
                write!(f, "consume B2AGG note (bridge-out, 2^31-1 leaves)")
            },
        }
    }
}
