use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use super::ProcedurePolicy;
use super::config::{OracleReaderConfig, SpendingPolicyConfig, TimelockControllerConfig};
use super::types::{AmountLimits, OracleId, TierThresholds};
use crate::account::account_component_code;

account_component_code!(MULTISIG_SMART_CODE, "auth/multisig_smart.masl");

// CONSTANTS
// ================================================================================================

static THRESHOLD_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::threshold_config")
        .expect("storage slot name should be valid")
});

static APPROVER_PUBKEYS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::approver_public_keys")
        .expect("storage slot name should be valid")
});

static APPROVER_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::approver_schemes")
        .expect("storage slot name should be valid")
});

static EXECUTED_TRANSACTIONS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::executed_transactions")
        .expect("storage slot name should be valid")
});

static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::procedure_policies")
        .expect("storage slot name should be valid")
});

static TIMELOCK_CONTROLLER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::timelock_controller")
        .expect("storage slot name should be valid")
});

static SPENDING_WINDOW_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_window")
        .expect("storage slot name should be valid")
});

static AMOUNT_LIMITS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::amount_limits")
        .expect("storage slot name should be valid")
});

static SPENDING_TRACKER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::spending_tracker")
        .expect("storage slot name should be valid")
});

static TIER_THRESHOLD_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::tier_threshold_config")
        .expect("storage slot name should be valid")
});

static ORACLE_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::oracle_config")
        .expect("storage slot name should be valid")
});

static GET_PRICE_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::get_price_proc_root")
        .expect("storage slot name should be valid")
});

static GET_PRICE_UNTRACKED_POLICY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::get_price_untracked_policy")
        .expect("storage slot name should be valid")
});

static TX_PROPOSALS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::tx_proposals")
        .expect("storage slot name should be valid")
});

static PENDING_PROPOSE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::pending_propose")
        .expect("storage slot name should be valid")
});

static PENDING_CANCEL_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::pending_cancel")
        .expect("storage slot name should be valid")
});

static PENDING_EXECUTE_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::pending_execute")
        .expect("storage slot name should be valid")
});

// MULTISIG SMART AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisigSmart`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigSmartConfig {
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    default_threshold: u32,
    procedure_policies: Vec<(Word, ProcedurePolicy)>,
    spending_policy: SpendingPolicyConfig,
    timelock_controller: TimelockControllerConfig,
    oracle_reader: OracleReaderConfig,
}

impl AuthMultisigSmartConfig {
    /// Creates a new configuration with the given approvers and a default threshold.
    ///
    /// The `default_threshold` must be at least 1 and at most the number of approvers.
    pub fn new(
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        default_threshold: u32,
    ) -> Result<Self, AccountError> {
        if default_threshold == 0 {
            return Err(AccountError::other("threshold must be at least 1"));
        }
        if default_threshold > approvers.len() as u32 {
            return Err(AccountError::other(
                "threshold cannot be greater than number of approvers",
            ));
        }

        let unique_approvers: alloc::collections::BTreeSet<_> =
            approvers.iter().map(|(pk, _)| pk).collect();
        if unique_approvers.len() != approvers.len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        Ok(Self {
            approvers,
            default_threshold,
            procedure_policies: vec![],
            spending_policy: SpendingPolicyConfig::default(),
            timelock_controller: TimelockControllerConfig::default(),
            oracle_reader: OracleReaderConfig::default(),
        })
    }

    /// Attaches a per-procedure smart policy map.
    pub fn with_proc_policies(
        mut self,
        proc_policies: Vec<(Word, ProcedurePolicy)>,
    ) -> Result<Self, AccountError> {
        validate_proc_policies(self.approvers.len() as u32, &proc_policies)?;
        self.procedure_policies = proc_policies;
        Ok(self)
    }

    pub fn with_spending(mut self, spending_policy: SpendingPolicyConfig) -> Self {
        self.spending_policy = spending_policy;
        self
    }

    pub fn with_timelock_controller_config(
        mut self,
        timelock_controller: TimelockControllerConfig,
    ) -> Self {
        self.timelock_controller = timelock_controller;
        self
    }

    pub fn with_oracle_reader(mut self, oracle_reader: OracleReaderConfig) -> Self {
        self.oracle_reader = oracle_reader;
        self
    }

    pub fn approvers(&self) -> &[(PublicKeyCommitment, AuthScheme)] {
        &self.approvers
    }

    pub fn default_threshold(&self) -> u32 {
        self.default_threshold
    }

    pub fn procedure_policies(&self) -> &[(Word, ProcedurePolicy)] {
        &self.procedure_policies
    }

    pub fn spending_policy(&self) -> SpendingPolicyConfig {
        self.spending_policy
    }

    pub fn timelock_controller(&self) -> TimelockControllerConfig {
        self.timelock_controller
    }

    pub fn oracle_reader(&self) -> OracleReaderConfig {
        self.oracle_reader
    }

    pub fn spending_window(&self) -> u32 {
        self.spending_policy.spending_window()
    }

    pub fn min_delay(&self) -> u32 {
        self.timelock_controller.min_delay()
    }

    pub fn propose_expiration_delta(&self) -> u16 {
        self.timelock_controller.propose_expiration_delta()
    }

    pub fn amount_limits(&self) -> AmountLimits {
        self.spending_policy.amount_limits()
    }

    pub fn tier_thresholds(&self) -> TierThresholds {
        self.spending_policy.tier_thresholds()
    }

    pub fn oracle_id(&self) -> OracleId {
        self.oracle_reader.oracle_id()
    }

    pub fn get_price_proc_root(&self) -> Word {
        self.oracle_reader.get_price_proc_root()
    }
}

fn validate_tier_thresholds(
    num_approvers: u32,
    tier_thresholds: TierThresholds,
) -> Result<(), AccountError> {
    let [tier_0, tier_1, tier_2, tier_3] = tier_thresholds.as_array();

    if tier_0 == 0 {
        return Err(AccountError::other("tier_0 must be > 0"));
    }
    if tier_0 > tier_1 || tier_1 > tier_2 || tier_2 > tier_3 {
        return Err(AccountError::other("tier config is invalid"));
    }
    if tier_3 > num_approvers {
        return Err(AccountError::other("tier_3 must be <= num_approvers"));
    }

    Ok(())
}

fn validate_proc_policies(
    num_approvers: u32,
    proc_policies: &[(Word, ProcedurePolicy)],
) -> Result<(), AccountError> {
    for (_, policy) in proc_policies {
        if let Some(immediate_threshold) = policy.immediate_threshold()
            && immediate_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy immediate threshold cannot exceed number of approvers",
            ));
        }
        if let Some(delay_threshold) = policy.delay_threshold()
            && delay_threshold > num_approvers
        {
            return Err(AccountError::other(
                "procedure policy delay threshold cannot exceed number of approvers",
            ));
        }
    }

    Ok(())
}

/// An [`AccountComponent`] implementing a multisig auth component with smart-policy slots.
#[derive(Debug)]
pub struct AuthMultisigSmart {
    config: AuthMultisigSmartConfig,
}

impl AuthMultisigSmart {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::multisig_smart";

    pub const UPDATE_SIGNERS_AND_THRESHOLD_PROC_NAME: &'static str = "update_signers_and_threshold";
    pub const UPDATE_THRESHOLD_CONFIG_PROC_NAME: &'static str = "update_threshold_config";
    pub const UPDATE_SPENDING_LIMITS_PROC_NAME: &'static str = "update_spending_limits";
    pub const UPDATE_ORACLE_CONFIG_PROC_NAME: &'static str = "update_oracle_config_and_proc_root";
    pub const UPDATE_GET_PRICE_UNTRACKED_POLICY_PROC_NAME: &'static str =
        "update_get_price_untracked_policy";
    pub const UPDATE_TIMELOCK_CONTROLLER_PROC_NAME: &'static str = "update_timelock_controller";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_SMART_CODE
    }

    /// Creates a new [`AuthMultisigSmart`] component from the provided configuration.
    pub fn new(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
        if config
            .spending_policy()
            .amount_limits()
            .as_array()
            .iter()
            .any(|v| *v > u32::MAX as u64)
        {
            return Err(AccountError::other("amount limits must fit into u32"));
        }
        if config.spending_policy().spending_window() == 0 {
            return Err(AccountError::other("spending window must be non-zero"));
        }
        if config.timelock_controller().min_delay() == 0 {
            return Err(AccountError::other("min delay must be non-zero"));
        }
        if config.timelock_controller().propose_expiration_delta() == 0 {
            return Err(AccountError::other("propose expiration delta must be non-zero"));
        }
        if config.oracle_reader().untracked_price_policy() > 1 {
            return Err(AccountError::other(
                "oracle untracked price policy must be 0 (omit) or 1 (reject)",
            ));
        }
        validate_tier_thresholds(
            config.approvers().len() as u32,
            config.spending_policy().tier_thresholds(),
        )?;
        validate_proc_policies(config.approvers().len() as u32, config.procedure_policies())?;
        Ok(Self { config })
    }

    pub fn threshold_config_slot() -> &'static StorageSlotName {
        &THRESHOLD_CONFIG_SLOT_NAME
    }

    pub fn approver_public_keys_slot() -> &'static StorageSlotName {
        &APPROVER_PUBKEYS_SLOT_NAME
    }

    pub fn approver_scheme_ids_slot() -> &'static StorageSlotName {
        &APPROVER_SCHEME_ID_SLOT_NAME
    }

    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        &EXECUTED_TRANSACTIONS_SLOT_NAME
    }

    pub fn procedure_policies_slot() -> &'static StorageSlotName {
        &PROCEDURE_POLICIES_SLOT_NAME
    }

    pub fn timelock_controller_slot() -> &'static StorageSlotName {
        &TIMELOCK_CONTROLLER_SLOT_NAME
    }

    pub fn spending_window_slot() -> &'static StorageSlotName {
        &SPENDING_WINDOW_SLOT_NAME
    }

    pub fn amount_limits_slot() -> &'static StorageSlotName {
        &AMOUNT_LIMITS_SLOT_NAME
    }

    pub fn spending_tracker_slot() -> &'static StorageSlotName {
        &SPENDING_TRACKER_SLOT_NAME
    }

    pub fn tier_threshold_config_slot() -> &'static StorageSlotName {
        &TIER_THRESHOLD_CONFIG_SLOT_NAME
    }

    pub fn oracle_config_slot() -> &'static StorageSlotName {
        &ORACLE_CONFIG_SLOT_NAME
    }

    pub fn get_price_proc_root_slot() -> &'static StorageSlotName {
        &GET_PRICE_PROC_ROOT_SLOT_NAME
    }

    pub fn get_price_untracked_policy_slot() -> &'static StorageSlotName {
        &GET_PRICE_UNTRACKED_POLICY_SLOT_NAME
    }

    pub fn tx_proposals_slot() -> &'static StorageSlotName {
        &TX_PROPOSALS_SLOT_NAME
    }

    pub fn pending_propose_slot() -> &'static StorageSlotName {
        &PENDING_PROPOSE_SLOT_NAME
    }

    pub fn pending_cancel_slot() -> &'static StorageSlotName {
        &PENDING_CANCEL_SLOT_NAME
    }

    pub fn pending_execute_slot() -> &'static StorageSlotName {
        &PENDING_EXECUTE_SLOT_NAME
    }

    pub fn threshold_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::threshold_config_slot().clone(),
            StorageSlotSchema::value(
                "Threshold configuration",
                [
                    FeltSchema::u32("threshold"),
                    FeltSchema::u32("num_approvers"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn approver_public_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::approver_public_keys_slot().clone(),
            StorageSlotSchema::map(
                "Approver public keys",
                SchemaType::u32(),
                SchemaType::pub_key(),
            ),
        )
    }

    pub fn approver_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::approver_scheme_ids_slot().clone(),
            StorageSlotSchema::map(
                "Approver scheme IDs",
                SchemaType::u32(),
                SchemaType::auth_scheme(),
            ),
        )
    }

    pub fn executed_transactions_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::executed_transactions_slot().clone(),
            StorageSlotSchema::map(
                "Executed transactions",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn procedure_policies_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::procedure_policies_slot().clone(),
            StorageSlotSchema::map(
                "Procedure policies",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn timelock_controller_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::timelock_controller_slot().clone(),
            StorageSlotSchema::value(
                "Timelock controller",
                [
                    FeltSchema::u32("min_delay"),
                    FeltSchema::u16("propose_expiration_delta"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn spending_window_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::spending_window_slot().clone(),
            StorageSlotSchema::value(
                "Spending window policy",
                [
                    FeltSchema::u32("spending_window"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn amount_limits_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::amount_limits_slot().clone(),
            StorageSlotSchema::value(
                "Amount limits",
                [
                    FeltSchema::u32("limit_0"),
                    FeltSchema::u32("limit_1"),
                    FeltSchema::u32("limit_2"),
                    FeltSchema::u32("delay_trigger_amount"),
                ],
            ),
        )
    }

    pub fn spending_tracker_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::spending_tracker_slot().clone(),
            StorageSlotSchema::value(
                "Spending tracker",
                [
                    FeltSchema::u32("amount_spent_in_window"),
                    FeltSchema::u32("window_start_timestamp"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn tier_threshold_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::tier_threshold_config_slot().clone(),
            StorageSlotSchema::value(
                "Tier threshold configuration",
                [
                    FeltSchema::u32("tier_0"),
                    FeltSchema::u32("tier_1"),
                    FeltSchema::u32("tier_2"),
                    FeltSchema::u32("tier_3"),
                ],
            ),
        )
    }

    pub fn oracle_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::oracle_config_slot().clone(),
            StorageSlotSchema::value(
                "Oracle configuration",
                [
                    FeltSchema::felt("oracle_id_prefix"),
                    FeltSchema::felt("oracle_id_suffix"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn get_price_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::get_price_proc_root_slot().clone(),
            StorageSlotSchema::value("Price procedure root", SchemaType::native_word()),
        )
    }

    pub fn get_price_untracked_policy_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::get_price_untracked_policy_slot().clone(),
            StorageSlotSchema::value(
                "get_price untracked policy",
                [
                    FeltSchema::u32("policy_mode"),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    pub fn tx_proposals_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::tx_proposals_slot().clone(),
            StorageSlotSchema::map(
                "Transaction proposals",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn pending_propose_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_propose_slot().clone(),
            StorageSlotSchema::value("Pending propose", SchemaType::native_word()),
        )
    }

    pub fn pending_cancel_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_cancel_slot().clone(),
            StorageSlotSchema::value("Pending cancel", SchemaType::native_word()),
        )
    }

    pub fn pending_execute_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_execute_slot().clone(),
            StorageSlotSchema::value("Pending execute", SchemaType::native_word()),
        )
    }
}

impl From<AuthMultisigSmart> for AccountComponent {
    fn from(multisig: AuthMultisigSmart) -> Self {
        let mut storage_slots = Vec::with_capacity(16);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, (pub_key, _))| {
                (StorageMapKey::from_index(i as u32), Word::from(*pub_key))
            });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot
        let scheme_id_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, (_, auth_scheme))| {
                (StorageMapKey::from_index(i as u32), Word::from([*auth_scheme as u32, 0, 0, 0]))
            });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::approver_scheme_ids_slot().clone(),
            StorageMap::with_entries(scheme_id_entries).unwrap(),
        ));

        // Executed transactions slot (map)
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::executed_transactions_slot().clone(),
            StorageMap::default(),
        ));

        // Procedure policies slot (map)
        let procedure_policies =
            StorageMap::with_entries(multisig.config.procedure_policies().iter().map(
                |(proc_root, policy)| (StorageMapKey::from_raw(*proc_root), policy.to_word()),
            ))
            .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::procedure_policies_slot().clone(),
            procedure_policies,
        ));

        // Smart policy slots
        let timelock_controller = multisig.config.timelock_controller();
        let spending_policy = multisig.config.spending_policy();
        let amount_limits = spending_policy.amount_limits();
        let tier_thresholds = spending_policy.tier_thresholds();
        let oracle_reader = multisig.config.oracle_reader();
        let oracle_id = oracle_reader.oracle_id();

        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::timelock_controller_slot().clone(),
            Word::from([
                timelock_controller.min_delay(),
                timelock_controller.propose_expiration_delta() as u32,
                0u32,
                0u32,
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_window_slot().clone(),
            Word::from([spending_policy.spending_window(), 0u32, 0u32, 0u32]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_tracker_slot().clone(),
            Word::empty(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::amount_limits_slot().clone(),
            Word::from([
                amount_limits.limit_0() as u32,
                amount_limits.limit_1() as u32,
                amount_limits.limit_2() as u32,
                amount_limits.delay_trigger_amount() as u32,
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::tier_threshold_config_slot().clone(),
            Word::from([
                tier_thresholds.tier_0(),
                tier_thresholds.tier_1(),
                tier_thresholds.tier_2(),
                tier_thresholds.tier_3(),
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::oracle_config_slot().clone(),
            Word::from([oracle_id.prefix(), oracle_id.suffix(), Felt::ZERO, Felt::ZERO]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::get_price_proc_root_slot().clone(),
            oracle_reader.get_price_proc_root(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::get_price_untracked_policy_slot().clone(),
            Word::from([oracle_reader.untracked_price_policy(), 0u32, 0u32, 0u32]),
        ));
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::tx_proposals_slot().clone(),
            StorageMap::default(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::pending_propose_slot().clone(),
            Word::empty(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::pending_cancel_slot().clone(),
            Word::empty(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::pending_execute_slot().clone(),
            Word::empty(),
        ));

        let storage_schema = StorageSchema::new(vec![
            AuthMultisigSmart::threshold_config_slot_schema(),
            AuthMultisigSmart::approver_public_keys_slot_schema(),
            AuthMultisigSmart::approver_auth_scheme_slot_schema(),
            AuthMultisigSmart::executed_transactions_slot_schema(),
            AuthMultisigSmart::procedure_policies_slot_schema(),
            AuthMultisigSmart::timelock_controller_slot_schema(),
            AuthMultisigSmart::spending_window_slot_schema(),
            AuthMultisigSmart::spending_tracker_slot_schema(),
            AuthMultisigSmart::amount_limits_slot_schema(),
            AuthMultisigSmart::tier_threshold_config_slot_schema(),
            AuthMultisigSmart::oracle_config_slot_schema(),
            AuthMultisigSmart::get_price_proc_root_slot_schema(),
            AuthMultisigSmart::get_price_untracked_policy_slot_schema(),
            AuthMultisigSmart::tx_proposals_slot_schema(),
            AuthMultisigSmart::pending_propose_slot_schema(),
            AuthMultisigSmart::pending_cancel_slot_schema(),
            AuthMultisigSmart::pending_execute_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthMultisigSmart::NAME)
            .with_description("Multisig smart authentication component")
            .with_storage_schema(storage_schema);

        AccountComponent::new(AuthMultisigSmart::code().clone(), storage_slots, metadata).expect(
            "multisig smart component should satisfy the requirements of a valid account component",
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;
    use crate::account::auth::multisig_smart::{
        AmountLimits,
        OracleId,
        OracleReaderConfig,
        ProcedurePolicyNoteRestriction,
        SpendingPolicyConfig,
        TierThresholds,
        TimelockControllerConfig,
    };
    use crate::account::wallets::BasicWallet;

    #[test]
    fn test_multisig_smart_component_setup() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let config = AuthMultisigSmartConfig::new(approvers.clone(), 2)
            .expect("invalid multisig smart config")
            .with_proc_policies(vec![(
                BasicWallet::receive_asset_root().as_word(),
                ProcedurePolicy::with_immediate_threshold(1)
                    .expect("procedure policy should be valid"),
            )])
            .expect("procedure policy config should be valid")
            .with_spending(SpendingPolicyConfig::new(
                100,
                AmountLimits::new(500, 1000, 2000, 1500),
                TierThresholds::new(1, 2, 2, 2),
            ))
            .with_timelock_controller_config(TimelockControllerConfig::new(30, 3))
            .with_oracle_reader(OracleReaderConfig::new(
                OracleId::new(Felt::from(1u32), Felt::from(2u32)),
                Word::from([7u32, 8, 9, 10]),
            ));

        let component =
            AuthMultisigSmart::new(config).expect("multisig smart component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        let threshold_config = account
            .storage()
            .get_item(AuthMultisigSmart::threshold_config_slot())
            .expect("threshold config should be present");
        assert_eq!(threshold_config, Word::from([2u32, 2u32, 0, 0]));

        let timelock_controller = account
            .storage()
            .get_item(AuthMultisigSmart::timelock_controller_slot())
            .expect("timelock controller should be present");
        assert_eq!(timelock_controller, Word::from([30u32, 3u32, 0u32, 0u32]));

        let spending_window = account
            .storage()
            .get_item(AuthMultisigSmart::spending_window_slot())
            .expect("spending window should be present");
        assert_eq!(spending_window, Word::from([100u32, 0u32, 0u32, 0u32]));

        let amount_limits = account
            .storage()
            .get_item(AuthMultisigSmart::amount_limits_slot())
            .expect("amount limits should be present");
        assert_eq!(amount_limits, Word::from([500u32, 1000, 2000, 1500]));

        let receive_asset_policy = account
            .storage()
            .get_map_item(
                AuthMultisigSmart::procedure_policies_slot(),
                BasicWallet::receive_asset_root().as_word(),
            )
            .expect("receive_asset policy should be present");
        assert_eq!(receive_asset_policy, Word::from([1u32, 0u32, 0u32, 0u32]));

        let untracked_policy = account
            .storage()
            .get_item(AuthMultisigSmart::get_price_untracked_policy_slot())
            .expect("get_price untracked policy slot should be present");
        assert_eq!(untracked_policy, Word::from([0u32, 0u32, 0u32, 0u32]));
    }

    #[test]
    fn test_multisig_smart_component_error_cases() {
        let sec_key = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![(sec_key.public_key().to_commitment(), sec_key.auth_scheme())];

        let result = AuthMultisigSmartConfig::new(approvers.clone(), 0);
        assert!(result.unwrap_err().to_string().contains("threshold must be at least 1"));

        let result = AuthMultisigSmartConfig::new(approvers.clone(), 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("threshold cannot be greater than number of approvers")
        );

        let config = AuthMultisigSmartConfig::new(approvers, 1)
            .expect("config should be valid")
            .with_spending(SpendingPolicyConfig::new(
                100,
                AmountLimits::new(u32::MAX as u64 + 1, 0, 0, 0),
                TierThresholds::new(1, 2, 2, 2),
            ))
            .with_timelock_controller_config(TimelockControllerConfig::new(30, 3));
        let result = AuthMultisigSmart::new(config);
        assert!(result.unwrap_err().to_string().contains("amount limits must fit into u32"));

        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            (sec_key.public_key().to_commitment(), sec_key.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigSmartConfig::new(approvers.clone(), 2).and_then(|cfg| {
            let policy = ProcedurePolicy::with_immediate_and_delay_thresholds(1, 2)?;
            cfg.with_proc_policies(vec![(Word::from([1u32, 2, 3, 4]), policy)])
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("delay threshold cannot exceed immediate threshold")
        );

        let result = AuthMultisigSmartConfig::new(approvers, 2).and_then(|cfg| {
            let policy = ProcedurePolicy::with_immediate_threshold(0)?
                .with_note_restriction(ProcedurePolicyNoteRestriction::NoInputNotes);
            cfg.with_proc_policies(vec![(Word::from([4u32, 3, 2, 1]), policy)])
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("procedure policy immediate threshold must be at least 1")
        );
    }

    #[test]
    fn test_multisig_smart_component_rejects_invalid_tier_thresholds() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigSmart::new(
            AuthMultisigSmartConfig::new(approvers.clone(), 2)
                .expect("config should be valid")
                .with_spending(SpendingPolicyConfig::new(
                    100,
                    AmountLimits::new(500, 1000, 2000, 1500),
                    TierThresholds::new(0, 2, 2, 2),
                ))
                .with_timelock_controller_config(TimelockControllerConfig::new(30, 3)),
        );
        assert!(result.unwrap_err().to_string().contains("tier_0 must be > 0"));

        let result = AuthMultisigSmart::new(
            AuthMultisigSmartConfig::new(approvers.clone(), 2)
                .expect("config should be valid")
                .with_spending(SpendingPolicyConfig::new(
                    100,
                    AmountLimits::new(500, 1000, 2000, 1500),
                    TierThresholds::new(1, 2, 1, 2),
                ))
                .with_timelock_controller_config(TimelockControllerConfig::new(30, 3)),
        );
        assert!(result.unwrap_err().to_string().contains("tier config is invalid"));

        let result = AuthMultisigSmart::new(
            AuthMultisigSmartConfig::new(approvers, 2)
                .expect("config should be valid")
                .with_spending(SpendingPolicyConfig::new(
                    100,
                    AmountLimits::new(500, 1000, 2000, 1500),
                    TierThresholds::new(1, 2, 2, 3),
                ))
                .with_timelock_controller_config(TimelockControllerConfig::new(30, 3)),
        );
        assert!(result.unwrap_err().to_string().contains("tier_3 must be <= num_approvers"));
    }

    #[test]
    fn test_multisig_smart_component_duplicate_approvers() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigSmartConfig::new(approvers, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }
}
