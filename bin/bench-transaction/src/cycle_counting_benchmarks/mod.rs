use core::fmt;

pub mod utils;

/// Indicates the type of the transaction execution benchmark
pub enum ExecutionBenchmark {
    ConsumeSingleP2ID,
    ConsumeTwoP2ID,
    CreateSingleP2ID,
    ConsumeClaimNoteL1ToMiden,
    ConsumeClaimNoteL2ToMiden,
    ConsumeB2AggNote,
}

impl fmt::Display for ExecutionBenchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionBenchmark::ConsumeSingleP2ID => write!(f, "consume single P2ID note"),
            ExecutionBenchmark::ConsumeTwoP2ID => write!(f, "consume two P2ID notes"),
            ExecutionBenchmark::CreateSingleP2ID => write!(f, "create single P2ID note"),
            ExecutionBenchmark::ConsumeClaimNoteL1ToMiden => {
                write!(f, "consume CLAIM note (L1 to Miden)")
            },
            ExecutionBenchmark::ConsumeClaimNoteL2ToMiden => {
                write!(f, "consume CLAIM note (L2 to Miden)")
            },
            ExecutionBenchmark::ConsumeB2AggNote => {
                write!(f, "consume B2AGG note (bridge-out)")
            },
        }
    }
}
