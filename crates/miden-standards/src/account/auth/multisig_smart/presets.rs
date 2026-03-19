use alloc::vec::Vec;

use miden_protocol::Word;

use super::{
    AuthMultisigSmart,
    ProcedurePolicy,
    ProcedurePolicyConstraints,
};
use crate::account::components::multisig_smart_library;
use crate::procedure_digest;

procedure_digest!(
    MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD,
    AuthMultisigSmart::NAME,
    "update_signers_and_threshold",
    multisig_smart_library
);

procedure_digest!(
    MULTISIG_SMART_UPDATE_THRESHOLD_CONFIG,
    AuthMultisigSmart::NAME,
    "update_threshold_config",
    multisig_smart_library
);

procedure_digest!(
    MULTISIG_SMART_UPDATE_SPENDING_LIMITS,
    AuthMultisigSmart::NAME,
    "update_spending_limits",
    multisig_smart_library
);

procedure_digest!(
    MULTISIG_SMART_UPDATE_ORACLE_CONFIG,
    AuthMultisigSmart::NAME,
    "update_oracle_config_and_proc_root",
    multisig_smart_library
);

procedure_digest!(
    MULTISIG_SMART_UPDATE_TIMELOCK_CONTROLLER,
    AuthMultisigSmart::NAME,
    "update_timelock_controller",
    multisig_smart_library
);

/// Opinionated smart-multisig policy presets.
pub struct AuthMultisigSmartPresets;

impl AuthMultisigSmartPresets {
    pub fn single_user_1_of_2() -> Vec<(Word, ProcedurePolicy)> {
        vec![
            (
                Self::update_signers_and_threshold(),
                ProcedurePolicy::with_delay_threshold(1)
                    .with_constraints(ProcedurePolicyConstraints::isolated_no_input_output_notes()),
            ),
            (
                Self::update_threshold_config(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1),
            ),
            (
                Self::update_spending_limits(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1),
            ),
            (
                Self::update_oracle_config_and_proc_root(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1),
            ),
            (
                Self::update_timelock_controller(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .with_constraints(ProcedurePolicyConstraints::isolated_tx()),
            ),
        ]
    }

    pub fn treasury_3_of_5() -> Vec<(Word, ProcedurePolicy)> {
        vec![
            (
                Self::update_signers_and_threshold(),
                ProcedurePolicy::with_delay_threshold(3)
                    .with_constraints(ProcedurePolicyConstraints::isolated_no_input_output_notes()),
            ),
            (
                Self::update_threshold_config(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3),
            ),
            (
                Self::update_spending_limits(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3),
            ),
            (
                Self::update_oracle_config_and_proc_root(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3),
            ),
            (
                Self::update_timelock_controller(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(5, 4)
                    .with_constraints(ProcedurePolicyConstraints::isolated_tx()),
            ),
        ]
    }

    pub fn update_signers_and_threshold() -> Word {
        *MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD
    }

    pub fn update_threshold_config() -> Word {
        *MULTISIG_SMART_UPDATE_THRESHOLD_CONFIG
    }

    pub fn update_spending_limits() -> Word {
        *MULTISIG_SMART_UPDATE_SPENDING_LIMITS
    }

    pub fn update_oracle_config_and_proc_root() -> Word {
        *MULTISIG_SMART_UPDATE_ORACLE_CONFIG
    }

    pub fn update_timelock_controller() -> Word {
        *MULTISIG_SMART_UPDATE_TIMELOCK_CONTROLLER
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::auth::AuthSecretKey;

    use super::AuthMultisigSmartPresets;
    use crate::account::auth::{
        AmountLimits,
        AuthMultisigSmart,
        AuthMultisigSmartConfig,
        SpendingPolicyConfig,
        TierThresholds,
        TimelockControllerConfig,
    };

    #[test]
    fn single_user_preset_contains_expected_policy_count() {
        assert_eq!(AuthMultisigSmartPresets::single_user_1_of_2().len(), 5);
    }

    #[test]
    fn treasury_preset_contains_expected_policy_count() {
        assert_eq!(AuthMultisigSmartPresets::treasury_3_of_5().len(), 5);
    }

    #[test]
    fn presets_smoke_test_with_component_configs() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_3 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_4 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_5 = AuthSecretKey::new_ecdsa_k256_keccak();

        let one_of_two_approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];
        let three_of_five_approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
            (sec_key_3.public_key().to_commitment(), sec_key_3.auth_scheme()),
            (sec_key_4.public_key().to_commitment(), sec_key_4.auth_scheme()),
            (sec_key_5.public_key().to_commitment(), sec_key_5.auth_scheme()),
        ];

        let one_of_two = AuthMultisigSmartConfig::new(one_of_two_approvers, 1)
            .expect("config should be valid")
            .with_proc_policies(AuthMultisigSmartPresets::single_user_1_of_2())
            .expect("preset policies should validate")
            .with_spending(SpendingPolicyConfig::new(
                100,
                AmountLimits::new(500, 1000, 2000, 1500),
                TierThresholds::new(1, 1, 1, 1),
            ))
            .with_timelock_controller_config(TimelockControllerConfig::new(30, 3));
        AuthMultisigSmart::new(one_of_two).expect("preset component should build");

        let three_of_five = AuthMultisigSmartConfig::new(three_of_five_approvers, 3)
            .expect("config should be valid")
            .with_proc_policies(AuthMultisigSmartPresets::treasury_3_of_5())
            .expect("preset policies should validate")
            .with_spending(SpendingPolicyConfig::new(
                100,
                AmountLimits::new(500, 1000, 2000, 1500),
                TierThresholds::new(1, 2, 3, 5),
            ))
            .with_timelock_controller_config(TimelockControllerConfig::new(30, 3));
        AuthMultisigSmart::new(three_of_five).expect("preset component should build");
    }
}
