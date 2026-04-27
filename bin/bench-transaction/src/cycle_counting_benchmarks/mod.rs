use core::fmt;

pub mod trace_capture;
pub mod utils;

/// Indicates the type of the transaction execution benchmark
#[derive(Clone, Copy)]
pub enum ExecutionBenchmark {
    ConsumeSingleP2ID,
    ConsumeTwoP2ID,
    CreateSingleP2ID,
}

impl fmt::Display for ExecutionBenchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionBenchmark::ConsumeSingleP2ID => write!(f, "consume single P2ID note"),
            ExecutionBenchmark::ConsumeTwoP2ID => write!(f, "consume two P2ID notes"),
            ExecutionBenchmark::CreateSingleP2ID => write!(f, "create single P2ID note"),
        }
    }
}
