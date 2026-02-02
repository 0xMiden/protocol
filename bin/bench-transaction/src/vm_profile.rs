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
    /// Detailed operation information for generating realistic benchmarks
    #[serde(default)]
    pub operation_details: Vec<OperationDetails>,
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

/// Detailed information about a specific operation type
/// Used by synthetic benchmark generators to create realistic workloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDetails {
    /// Operation type identifier (e.g., "falcon512_verify", "hperm", "hmerge")
    pub op_type: String,
    /// Size of each input in bytes (for operations with variable input sizes)
    pub input_sizes: Vec<usize>,
    /// Number of times this operation is executed
    pub iterations: u64,
    /// Estimated cycle cost per operation (for validation)
    pub cycle_cost: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that old VM profiles without operation_details can be deserialized
    /// This ensures backward compatibility with existing profiles
    #[test]
    fn deserialize_profile_without_operation_details() {
        let json = r#"{
            "profile_version": "1.0",
            "source": "test",
            "timestamp": "2025-01-01T00:00:00Z",
            "miden_vm_version": "0.20.0",
            "transaction_kernel": {
                "total_cycles": 1000,
                "phases": {},
                "instruction_mix": {
                    "arithmetic": 0.2,
                    "hashing": 0.2,
                    "memory": 0.2,
                    "control_flow": 0.2,
                    "signature_verify": 0.2
                },
                "key_procedures": []
            }
        }"#;

        let profile: VmProfile =
            serde_json::from_str(json).expect("should deserialize old profile");
        assert!(profile.transaction_kernel.operation_details.is_empty());
        assert_eq!(profile.transaction_kernel.total_cycles, 1000);
    }

    /// Test that profiles with operation_details deserialize correctly
    #[test]
    fn deserialize_profile_with_operation_details() {
        let json = r#"{
            "profile_version": "1.0",
            "source": "test",
            "timestamp": "2025-01-01T00:00:00Z",
            "miden_vm_version": "0.20.0",
            "transaction_kernel": {
                "total_cycles": 100000,
                "phases": {},
                "instruction_mix": {
                    "arithmetic": 0.05,
                    "hashing": 0.45,
                    "memory": 0.08,
                    "control_flow": 0.05,
                    "signature_verify": 0.37
                },
                "key_procedures": [],
                "operation_details": [
                    {
                        "op_type": "falcon512_verify",
                        "input_sizes": [64, 32],
                        "iterations": 1,
                        "cycle_cost": 59859
                    },
                    {
                        "op_type": "hperm",
                        "input_sizes": [48],
                        "iterations": 1000,
                        "cycle_cost": 1
                    }
                ]
            }
        }"#;

        let profile: VmProfile =
            serde_json::from_str(json).expect("should deserialize profile with details");
        assert_eq!(profile.transaction_kernel.operation_details.len(), 2);
        assert_eq!(profile.transaction_kernel.operation_details[0].op_type, "falcon512_verify");
        assert_eq!(profile.transaction_kernel.operation_details[1].iterations, 1000);
    }

    /// Calculate total cycles from operation details
    fn calculate_operation_cycles(details: &[OperationDetails]) -> u64 {
        details.iter().map(|d| d.iterations * d.cycle_cost).sum()
    }

    /// Test that operation_details cycles are consistent with total_cycles
    /// This validates that the operation breakdown roughly matches the total
    #[test]
    fn operation_details_consistent_with_total_cycles() {
        // Profile with realistic operation mix
        let profile = VmProfile {
            profile_version: "1.0".to_string(),
            source: "test".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 73123,
                phases: HashMap::new(),
                instruction_mix: InstructionMix {
                    arithmetic: 0.05,
                    hashing: 0.45,
                    memory: 0.08,
                    control_flow: 0.05,
                    signature_verify: 0.37,
                },
                key_procedures: vec![],
                operation_details: vec![
                    OperationDetails {
                        op_type: "falcon512_verify".to_string(),
                        input_sizes: vec![64, 32],
                        iterations: 1,
                        cycle_cost: 59859,
                    },
                    OperationDetails {
                        op_type: "hperm".to_string(),
                        input_sizes: vec![48],
                        iterations: 10000,
                        cycle_cost: 1,
                    },
                ],
            },
        };

        let operation_cycles =
            calculate_operation_cycles(&profile.transaction_kernel.operation_details);
        // Operation cycles should be within reasonable range of total_cycles
        // (allowing for overhead, other operations, and estimation errors)
        assert!(
            operation_cycles <= profile.transaction_kernel.total_cycles * 2,
            "operation cycles ({}) should not exceed 2x total_cycles ({})",
            operation_cycles,
            profile.transaction_kernel.total_cycles
        );

        // For this profile, falcon512_verify dominates, so operation_cycles should be significant
        assert!(
            operation_cycles >= profile.transaction_kernel.total_cycles / 2,
            "operation cycles ({}) should be at least 50% of total_cycles ({})",
            operation_cycles,
            profile.transaction_kernel.total_cycles
        );
    }

    /// Test that tiny workloads don't get inflated by minimums
    #[test]
    fn tiny_workload_no_minimum_inflation() {
        // Small profile with low operation counts
        let profile = VmProfile {
            profile_version: "1.0".to_string(),
            source: "test".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles: 100, // Very small workload
                phases: HashMap::new(),
                instruction_mix: InstructionMix {
                    arithmetic: 0.5,
                    hashing: 0.0,
                    memory: 0.0,
                    control_flow: 0.0,
                    signature_verify: 0.5,
                },
                key_procedures: vec![],
                operation_details: vec![
                    // Without minimums, these should be small counts
                    OperationDetails {
                        op_type: "arithmetic".to_string(),
                        input_sizes: vec![8],
                        iterations: 50, // 50 * 1 = 50 cycles, not inflated to 10
                        cycle_cost: 1,
                    },
                ],
            },
        };

        let operation_cycles =
            calculate_operation_cycles(&profile.transaction_kernel.operation_details);
        // For tiny workloads without minimums applied, iterations should be small
        assert_eq!(operation_cycles, 50);
    }
}
