use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    SchemaType,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

// Slots and schemas reused from `AuthMultisig` to keep the storage layout in sync. The statics
// are exposed as `pub(super)` in the sibling `multisig` module; we reference them directly so
// the sharing is visible at the use site rather than hidden behind delegating methods.
use super::super::multisig::{
    APPROVER_PUBKEYS_SLOT_NAME,
    APPROVER_SCHEME_ID_SLOT_NAME,
    EXECUTED_TRANSACTIONS_SLOT_NAME,
    THRESHOLD_CONFIG_SLOT_NAME,
};
use super::ProcedurePolicy;
use super::config::DelayedExecutionPolicy;
use crate::account::account_component_code;
use crate::account::auth::AuthMultisig;
use crate::procedure_root;

account_component_code!(MULTISIG_SMART_CODE, "auth/multisig_smart.masl");

// Procedure-root statics for the delayed-execution control-plane procedures. Tests and callers
// can use these to look up the on-chain procedure roots without re-deriving them from the
// component code.
procedure_root!(
    MULTISIG_SMART_UPDATE_DELAYED_EXECUTION_POLICY,
    AuthMultisigSmart::NAME,
    AuthMultisigSmart::UPDATE_DELAYED_EXECUTION_POLICY_PROC_NAME,
    AuthMultisigSmart::code()
);

// CONSTANTS
// ================================================================================================

// Only the smart-specific slots need their own constants here. The four slots reused from
// `AuthMultisig` (threshold config, approver public keys, approver scheme ids, executed
// transactions) are imported from that sibling module above.
static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::procedure_policies")
        .expect("storage slot name should be valid")
});

static DELAYED_EXECUTION_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::delayed_execution")
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
    delayed_execution: DelayedExecutionPolicy,
}

impl AuthMultisigSmartConfig {
    /// Creates a new configuration with the given approvers, default threshold, and delayed
    /// execution policy.
    ///
    /// The `default_threshold` must be at least 1 and at most the number of approvers.
    /// `delayed_execution` is required — `AuthMultisigSmart` always runs with a configured
    /// timelock policy; see [`DelayedExecutionPolicy::new`] for its validation rules.
    pub fn new(
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        default_threshold: u32,
        delayed_execution: DelayedExecutionPolicy,
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
            delayed_execution,
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

    pub fn approvers(&self) -> &[(PublicKeyCommitment, AuthScheme)] {
        &self.approvers
    }

    pub fn default_threshold(&self) -> u32 {
        self.default_threshold
    }

    pub fn procedure_policies(&self) -> &[(Word, ProcedurePolicy)] {
        &self.procedure_policies
    }

    pub fn delayed_execution(&self) -> DelayedExecutionPolicy {
        self.delayed_execution
    }
}

fn validate_proc_policies(
    num_approvers: u32,
    proc_policies: &[(Word, ProcedurePolicy)],
) -> Result<(), AccountError> {
    // Reject duplicate procedure roots. Catching it here turns the failure into a regular
    // `AccountError` returned from `with_proc_policies` / `AuthMultisigSmart::new`.
    let mut policy_roots = alloc::collections::BTreeSet::new();
    for (proc_root, _) in proc_policies {
        if !policy_roots.insert(*proc_root) {
            return Err(AccountError::other(
                "duplicate procedure roots are not allowed in the procedure policy map",
            ));
        }
    }

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

    pub const UPDATE_DELAYED_EXECUTION_POLICY_PROC_NAME: &'static str =
        "update_delayed_execution_policy";

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_SMART_CODE
    }

    /// Creates a new [`AuthMultisigSmart`] component from the provided configuration.
    pub fn new(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
        validate_proc_policies(config.approvers().len() as u32, config.procedure_policies())?;
        Ok(Self { config })
    }

    /// Returns the approver list configured for this component.
    pub fn approvers(&self) -> &[(PublicKeyCommitment, AuthScheme)] {
        self.config.approvers()
    }

    /// Returns the default approver threshold.
    pub fn default_threshold(&self) -> u32 {
        self.config.default_threshold()
    }

    /// Returns the per-procedure smart policy map.
    pub fn procedure_policies(&self) -> &[(Word, ProcedurePolicy)] {
        self.config.procedure_policies()
    }

    /// Returns the configured delayed-execution policy.
    pub fn delayed_execution(&self) -> DelayedExecutionPolicy {
        self.config.delayed_execution()
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

    pub fn delayed_execution_slot() -> &'static StorageSlotName {
        &DELAYED_EXECUTION_SLOT_NAME
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

    /// Returns the [`AccountProcedureRoot`] of the `update_delayed_execution_policy` procedure.
    pub fn update_delayed_execution_policy_root() -> AccountProcedureRoot {
        *MULTISIG_SMART_UPDATE_DELAYED_EXECUTION_POLICY
    }

    pub fn threshold_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::threshold_config_slot_schema()
    }

    pub fn approver_public_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::approver_public_keys_slot_schema()
    }

    pub fn approver_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::approver_auth_scheme_slot_schema()
    }

    pub fn executed_transactions_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::executed_transactions_slot_schema()
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

    pub fn delayed_execution_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::delayed_execution_slot().clone(),
            StorageSlotSchema::value(
                "Delayed-execution policy: [min_delay, propose_expiration_delta, 0, 0]",
                SchemaType::native_word(),
            ),
        )
    }

    pub fn tx_proposals_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::tx_proposals_slot().clone(),
            StorageSlotSchema::map(
                "Active tx proposals: tx_summary_commitment => [unlock_timestamp, expiration_height, 0, 0]",
                SchemaType::native_word(),
                SchemaType::native_word(),
            ),
        )
    }

    pub fn pending_propose_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_propose_slot().clone(),
            StorageSlotSchema::value(
                "Pending propose: TX_SUMMARY_COMMITMENT",
                SchemaType::native_word(),
            ),
        )
    }

    pub fn pending_cancel_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_cancel_slot().clone(),
            StorageSlotSchema::value(
                "Pending cancel: TX_SUMMARY_COMMITMENT",
                SchemaType::native_word(),
            ),
        )
    }

    pub fn pending_execute_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::pending_execute_slot().clone(),
            StorageSlotSchema::value(
                "Pending execute marker (any non-zero word)",
                SchemaType::native_word(),
            ),
        )
    }
}

impl From<AuthMultisigSmart> for AccountComponent {
    fn from(multisig: AuthMultisigSmart) -> Self {
        let mut storage_slots = Vec::with_capacity(10);

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

        // Delayed-execution policy slot (value: [min_delay, propose_expiration_delta, 0, 0]).
        let delayed_execution = multisig.config.delayed_execution();
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::delayed_execution_slot().clone(),
            Word::from([
                delayed_execution.min_delay(),
                delayed_execution.propose_expiration_delta() as u32,
                0u32,
                0u32,
            ]),
        ));

        // Tx-proposals map slot (TX_SUMMARY_COMMITMENT => [unlock_timestamp, expiration_height, 0,
        // 0])
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::tx_proposals_slot().clone(),
            StorageMap::default(),
        ));

        // Pending propose / cancel / execute scratch slots — empty by default.
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
            AuthMultisigSmart::delayed_execution_slot_schema(),
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
    use crate::account::wallets::BasicWallet;

    fn default_delayed_execution_policy() -> DelayedExecutionPolicy {
        DelayedExecutionPolicy::new(30, 2).expect("default test policy must be valid")
    }

    #[test]
    fn test_multisig_smart_component_setup() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];
        let num_approvers = approvers.len() as u32;
        let default_threshold = 2u32;
        let receive_asset_immediate_threshold = 1u32;

        let config = AuthMultisigSmartConfig::new(
            approvers.clone(),
            default_threshold,
            default_delayed_execution_policy(),
        )
        .expect("invalid multisig smart config")
        .with_proc_policies(vec![(
            BasicWallet::receive_asset_root().as_word(),
            ProcedurePolicy::with_immediate_threshold(receive_asset_immediate_threshold)
                .expect("procedure policy should be valid"),
        )])
        .expect("procedure policy config should be valid");

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
        assert_eq!(threshold_config, Word::from([default_threshold, num_approvers, 0, 0]));

        let receive_asset_policy = account
            .storage()
            .get_map_item(
                AuthMultisigSmart::procedure_policies_slot(),
                BasicWallet::receive_asset_root().as_word(),
            )
            .expect("receive_asset policy should be present");
        assert_eq!(
            receive_asset_policy,
            Word::from([receive_asset_immediate_threshold, 0u32, 0u32, 0u32])
        );
    }

    #[test]
    fn test_multisig_smart_component_error_cases() {
        let sec_key = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![(sec_key.public_key().to_commitment(), sec_key.auth_scheme())];

        let policy = default_delayed_execution_policy();
        let result = AuthMultisigSmartConfig::new(approvers.clone(), 0, policy);
        assert!(result.unwrap_err().to_string().contains("threshold must be at least 1"));

        let result = AuthMultisigSmartConfig::new(approvers, 2, policy);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("threshold cannot be greater than number of approvers")
        );
    }

    #[test]
    fn test_multisig_smart_component_rejects_duplicate_procedure_roots() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let receive_asset_root = BasicWallet::receive_asset_root().as_word();
        let policy_one =
            ProcedurePolicy::with_immediate_threshold(1).expect("procedure policy should be valid");
        let policy_two =
            ProcedurePolicy::with_immediate_threshold(2).expect("procedure policy should be valid");

        let result = AuthMultisigSmartConfig::new(approvers, 2, default_delayed_execution_policy())
            .expect("base config should be valid")
            .with_proc_policies(vec![
                (receive_asset_root, policy_one),
                (receive_asset_root, policy_two),
            ]);

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate procedure roots are not allowed in the procedure policy map")
        );
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

        let result = AuthMultisigSmartConfig::new(approvers, 2, default_delayed_execution_policy());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }
}
