use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountType,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::multisig_smart_library;

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

static PROCEDURE_THRESHOLDS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::procedure_thresholds")
        .expect("storage slot name should be valid")
});

static TIMELOCK_CONTROLLER_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::timelock_controller")
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
    proc_thresholds: Vec<(Word, u32)>,
    spending_window: u32,
    min_delay: u32,
    propose_expiration_delta: u16,
    execute_expiration_delta: u16,
    amount_limits: [u64; 4],
    tier_thresholds: [u32; 4],
    oracle_id: [Felt; 2],
    get_price_proc_root: Word,
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

        // Check for duplicate approvers
        let unique_approvers: BTreeSet<_> = approvers.iter().map(|(pk, _)| pk).collect();
        if approvers.len() != unique_approvers.len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        Ok(Self {
            approvers,
            default_threshold,
            proc_thresholds: Vec::new(),
            spending_window: 0,
            min_delay: 0,
            propose_expiration_delta: 0,
            execute_expiration_delta: 0,
            amount_limits: [0; 4],
            tier_thresholds: [0; 4],
            oracle_id: [Felt::new(0), Felt::new(0)],
            get_price_proc_root: Word::empty(),
        })
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(Word, u32)>,
    ) -> Result<Self, AccountError> {
        for (_, threshold) in &proc_thresholds {
            if *threshold == 0 {
                return Err(AccountError::other("procedure threshold must be at least 1"));
            }
            if *threshold > self.approvers.len() as u32 {
                return Err(AccountError::other(
                    "procedure threshold cannot be greater than number of approvers",
                ));
            }
        }
        self.proc_thresholds = proc_thresholds;
        Ok(self)
    }

    pub fn with_timelock_controller(
        mut self,
        spending_window: u32,
        min_delay: u32,
        propose_expiration_delta: u16,
        execute_expiration_delta: u16,
    ) -> Self {
        self.spending_window = spending_window;
        self.min_delay = min_delay;
        self.propose_expiration_delta = propose_expiration_delta;
        self.execute_expiration_delta = execute_expiration_delta;
        self
    }

    pub fn with_amount_limits(mut self, amount_limits: [u64; 4]) -> Self {
        self.amount_limits = amount_limits;
        self
    }

    pub fn with_tier_thresholds(mut self, tier_thresholds: [u32; 4]) -> Self {
        self.tier_thresholds = tier_thresholds;
        self
    }

    pub fn with_oracle_config(mut self, oracle_id: [Felt; 2]) -> Self {
        self.oracle_id = oracle_id;
        self
    }

    pub fn with_get_price_proc_root(mut self, get_price_proc_root: Word) -> Self {
        self.get_price_proc_root = get_price_proc_root;
        self
    }

    pub fn approvers(&self) -> &[(PublicKeyCommitment, AuthScheme)] {
        &self.approvers
    }

    pub fn default_threshold(&self) -> u32 {
        self.default_threshold
    }

    pub fn proc_thresholds(&self) -> &[(Word, u32)] {
        &self.proc_thresholds
    }

    pub fn spending_window(&self) -> u32 {
        self.spending_window
    }

    pub fn min_delay(&self) -> u32 {
        self.min_delay
    }

    pub fn propose_expiration_delta(&self) -> u16 {
        self.propose_expiration_delta
    }

    pub fn execute_expiration_delta(&self) -> u16 {
        self.execute_expiration_delta
    }

    pub fn amount_limits(&self) -> &[u64; 4] {
        &self.amount_limits
    }

    pub fn tier_thresholds(&self) -> &[u32; 4] {
        &self.tier_thresholds
    }

    pub fn oracle_id(&self) -> &[Felt; 2] {
        &self.oracle_id
    }

    pub fn get_price_proc_root(&self) -> &Word {
        &self.get_price_proc_root
    }
}

/// An [`AccountComponent`] implementing a multisig auth component with smart-policy slots.
#[derive(Debug)]
pub struct AuthMultisigSmart {
    config: AuthMultisigSmartConfig,
}

impl AuthMultisigSmart {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::multisig_smart";

    /// Creates a new [`AuthMultisigSmart`] component from the provided configuration.
    pub fn new(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
        if config.amount_limits.iter().any(|v| *v > u32::MAX as u64) {
            return Err(AccountError::other("amount limits must fit into u32"));
        }
        if config.spending_window() == 0 {
            return Err(AccountError::other("spending window must be non-zero"));
        }
        if config.min_delay() == 0 {
            return Err(AccountError::other("min delay must be non-zero"));
        }
        if config.propose_expiration_delta() == 0 {
            return Err(AccountError::other("propose expiration delta must be non-zero"));
        }
        if config.execute_expiration_delta() == 0 {
            return Err(AccountError::other("execute expiration delta must be non-zero"));
        }

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

    pub fn procedure_thresholds_slot() -> &'static StorageSlotName {
        &PROCEDURE_THRESHOLDS_SLOT_NAME
    }

    pub fn timelock_controller_slot() -> &'static StorageSlotName {
        &TIMELOCK_CONTROLLER_SLOT_NAME
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

    pub fn procedure_thresholds_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::procedure_thresholds_slot().clone(),
            StorageSlotSchema::map(
                "Procedure thresholds",
                SchemaType::native_word(),
                SchemaType::u32(),
            ),
        )
    }

    pub fn timelock_controller_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::timelock_controller_slot().clone(),
            StorageSlotSchema::value(
                "Timelock controller",
                [
                    FeltSchema::u32("spending_window"),
                    FeltSchema::u32("min_delay"),
                    FeltSchema::u16("propose_expiration_delta"),
                    FeltSchema::u16("execute_expiration_delta"),
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
        let mut storage_slots = Vec::with_capacity(15);

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

        // Procedure thresholds slot (map)
        let proc_threshold_roots = StorageMap::with_entries(
            multisig.config.proc_thresholds().iter().map(|(proc_root, threshold)| {
                (StorageMapKey::from_raw(*proc_root), Word::from([*threshold, 0, 0, 0]))
            }),
        )
        .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::procedure_thresholds_slot().clone(),
            proc_threshold_roots,
        ));

        // Smart policy slots
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::timelock_controller_slot().clone(),
            Word::from([
                multisig.config.spending_window(),
                multisig.config.min_delay(),
                multisig.config.propose_expiration_delta() as u32,
                multisig.config.execute_expiration_delta() as u32,
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::spending_tracker_slot().clone(),
            Word::empty(),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::amount_limits_slot().clone(),
            Word::from([
                multisig.config.amount_limits()[0] as u32,
                multisig.config.amount_limits()[1] as u32,
                multisig.config.amount_limits()[2] as u32,
                multisig.config.amount_limits()[3] as u32,
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::tier_threshold_config_slot().clone(),
            Word::from([
                multisig.config.tier_thresholds()[0],
                multisig.config.tier_thresholds()[1],
                multisig.config.tier_thresholds()[2],
                multisig.config.tier_thresholds()[3],
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::oracle_config_slot().clone(),
            Word::from([
                multisig.config.oracle_id()[0],
                multisig.config.oracle_id()[1],
                Felt::new(0),
                Felt::new(0),
            ]),
        ));
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::get_price_proc_root_slot().clone(),
            *multisig.config.get_price_proc_root(),
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
            AuthMultisigSmart::procedure_thresholds_slot_schema(),
            AuthMultisigSmart::timelock_controller_slot_schema(),
            AuthMultisigSmart::spending_tracker_slot_schema(),
            AuthMultisigSmart::amount_limits_slot_schema(),
            AuthMultisigSmart::tier_threshold_config_slot_schema(),
            AuthMultisigSmart::oracle_config_slot_schema(),
            AuthMultisigSmart::get_price_proc_root_slot_schema(),
            AuthMultisigSmart::tx_proposals_slot_schema(),
            AuthMultisigSmart::pending_propose_slot_schema(),
            AuthMultisigSmart::pending_cancel_slot_schema(),
            AuthMultisigSmart::pending_execute_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthMultisigSmart::NAME, AccountType::all())
            .with_description("Multisig smart authentication component")
            .with_storage_schema(storage_schema);

        AccountComponent::new(multisig_smart_library(), storage_slots, metadata).expect(
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
            .with_timelock_controller(100, 30, 3, 5)
            .with_amount_limits([500, 1000, 2000, 1500])
            .with_tier_thresholds([1, 2, 2, 2])
            .with_oracle_config([Felt::new(1), Felt::new(2)])
            .with_get_price_proc_root(Word::from([7u32, 8, 9, 10]));

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
        assert_eq!(timelock_controller, Word::from([100u32, 30u32, 3u32, 5u32]));

        let amount_limits = account
            .storage()
            .get_item(AuthMultisigSmart::amount_limits_slot())
            .expect("amount limits should be present");
        assert_eq!(amount_limits, Word::from([500u32, 1000, 2000, 1500]));
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
            .with_timelock_controller(100, 30, 3, 3)
            .with_amount_limits([u32::MAX as u64 + 1, 0, 0, 0]);
        let result = AuthMultisigSmart::new(config);
        assert!(result.unwrap_err().to_string().contains("amount limits must fit into u32"));
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
