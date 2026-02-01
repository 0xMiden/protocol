//! VM execution profile types for synthetic benchmark generation

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Versioned VM profile exported from transaction kernel benchmarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmProfile {
    pub profile_version: String,
    pub source: String,
    pub timestamp: String,
    pub miden_vm_version: String,
    pub transaction_kernel: TransactionKernelProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionKernelProfile {
    pub total_cycles: u64,
    pub phases: HashMap<String, PhaseProfile>,
    pub instruction_mix: InstructionMix,
    pub key_procedures: Vec<ProcedureProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseProfile {
    pub cycles: u64,
    pub operations: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionMix {
    pub arithmetic: f64,
    pub hashing: f64,
    pub memory: f64,
    pub control_flow: f64,
    pub signature_verify: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureProfile {
    pub name: String,
    pub cycles: u64,
    pub invocations: u64,
}
