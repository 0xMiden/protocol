use alloc::vec::Vec;

use miden_protocol::Word;

use super::{AuthMultisigSmart, ProcedurePolicy, ProcedurePolicyNoteRestriction};
use crate::procedure_root;

procedure_root!(
    MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_SIGNERS_AND_THRESHOLD_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_THRESHOLD_CONFIG,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_THRESHOLD_CONFIG_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_SPENDING_LIMITS,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_SPENDING_LIMITS_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_ORACLE_CONFIG,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_ORACLE_CONFIG_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_GET_PRICE_UNTRACKED_POLICY,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_GET_PRICE_UNTRACKED_POLICY_PROC_NAME,
    AuthMultisigSmart::code()
);

procedure_root!(
    MULTISIG_SMART_UPDATE_TIMELOCK_CONTROLLER,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_TIMELOCK_CONTROLLER_PROC_NAME,
    AuthMultisigSmart::code()
);

/// Opinionated smart-multisig policy presets.
pub struct AuthMultisigSmartPresets;

impl AuthMultisigSmartPresets {
    pub fn single_user_1_of_2() -> Vec<(Word, ProcedurePolicy)> {
        vec![
            (
                Self::update_signers_and_threshold(),
                ProcedurePolicy::with_delay_threshold(1)
                    .expect("preset policy should be valid")
                    .with_note_restriction(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes),
            ),
            (
                Self::update_threshold_config(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_spending_limits(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_oracle_config_and_proc_root(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_get_price_untracked_policy(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_timelock_controller(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(2, 1)
                    .expect("preset policy should be valid"),
            ),
        ]
    }

    pub fn multisig_3_of_5() -> Vec<(Word, ProcedurePolicy)> {
        vec![
            (
                Self::update_signers_and_threshold(),
                ProcedurePolicy::with_delay_threshold(3)
                    .expect("preset policy should be valid")
                    .with_note_restriction(ProcedurePolicyNoteRestriction::NoInputOrOutputNotes),
            ),
            (
                Self::update_threshold_config(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_spending_limits(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_oracle_config_and_proc_root(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_get_price_untracked_policy(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(4, 3)
                    .expect("preset policy should be valid"),
            ),
            (
                Self::update_timelock_controller(),
                ProcedurePolicy::with_immediate_and_delay_thresholds(5, 4)
                    .expect("preset policy should be valid"),
            ),
        ]
    }

    pub fn update_signers_and_threshold() -> Word {
        MULTISIG_SMART_UPDATE_SIGNERS_AND_THRESHOLD.as_word()
    }

    pub fn update_threshold_config() -> Word {
        MULTISIG_SMART_UPDATE_THRESHOLD_CONFIG.as_word()
    }

    pub fn update_spending_limits() -> Word {
        MULTISIG_SMART_UPDATE_SPENDING_LIMITS.as_word()
    }

    pub fn update_oracle_config_and_proc_root() -> Word {
        MULTISIG_SMART_UPDATE_ORACLE_CONFIG.as_word()
    }

    pub fn update_get_price_untracked_policy() -> Word {
        MULTISIG_SMART_UPDATE_GET_PRICE_UNTRACKED_POLICY.as_word()
    }

    pub fn update_timelock_controller() -> Word {
        MULTISIG_SMART_UPDATE_TIMELOCK_CONTROLLER.as_word()
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::account::auth::AuthSecretKey;

    use super::AuthMultisigSmartPresets;
    use crate::account::auth::multisig_smart::{
        AmountLimits,
        AuthMultisigSmart,
        AuthMultisigSmartConfig,
        SpendingPolicyConfig,
        TierThresholds,
        TimelockControllerConfig,
    };

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
            .with_proc_policies(AuthMultisigSmartPresets::multisig_3_of_5())
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
