use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
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
use crate::account::account_component_code;
use crate::account::auth::{Approver, ApproverSet, AuthMultisig};

account_component_code!(MULTISIG_SMART_CODE, "auth/multisig_smart.masl");

// CONSTANTS
// ================================================================================================

// Only the smart-specific procedure_policies slot needs its own constant here. The other four
// slots (threshold config, approver public keys, approver scheme ids, executed transactions) are
// reused from `AuthMultisig` via the imports above.
static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::procedure_policies")
        .expect("storage slot name should be valid")
});

// MULTISIG SMART AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisigSmart`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigSmartConfig {
    approver_set: ApproverSet,
    procedure_policies: Vec<(Word, ProcedurePolicy)>,
}

impl AuthMultisigSmartConfig {
    /// Creates a new configuration from the given approver set.
    pub fn new(approver_set: ApproverSet) -> Self {
        Self {
            approver_set,
            procedure_policies: Vec::new(),
        }
    }

    /// Attaches a per-procedure smart policy map.
    pub fn with_proc_policies(
        mut self,
        proc_policies: Vec<(Word, ProcedurePolicy)>,
    ) -> Result<Self, AccountError> {
        validate_proc_policies(self.approver_set.approvers().len() as u32, &proc_policies)?;
        self.procedure_policies = proc_policies;
        Ok(self)
    }

    pub fn approver_set(&self) -> &ApproverSet {
        &self.approver_set
    }

    pub fn approvers(&self) -> &[Approver] {
        self.approver_set.approvers()
    }

    pub fn default_threshold(&self) -> u32 {
        self.approver_set.threshold().get()
    }

    pub fn procedure_policies(&self) -> &[(Word, ProcedurePolicy)] {
        &self.procedure_policies
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

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_SMART_CODE
    }

    /// Creates a new [`AuthMultisigSmart`] component from the provided configuration.
    pub fn new(config: AuthMultisigSmartConfig) -> Result<Self, AccountError> {
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
}

impl From<AuthMultisigSmart> for AccountComponent {
    fn from(multisig: AuthMultisigSmart) -> Self {
        let mut storage_slots = Vec::with_capacity(5);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisigSmart::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries = multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
            (StorageMapKey::from_index(i as u32), Word::from(approver.pub_key()))
        });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisigSmart::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot
        let scheme_id_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
                (
                    StorageMapKey::from_index(i as u32),
                    Word::from([approver.auth_scheme() as u32, 0, 0, 0]),
                )
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

        let storage_schema = StorageSchema::new(vec![
            AuthMultisigSmart::threshold_config_slot_schema(),
            AuthMultisigSmart::approver_public_keys_slot_schema(),
            AuthMultisigSmart::approver_auth_scheme_slot_schema(),
            AuthMultisigSmart::executed_transactions_slot_schema(),
            AuthMultisigSmart::procedure_policies_slot_schema(),
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

    #[test]
    fn test_multisig_smart_component_setup() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];
        let num_approvers = approvers.len() as u32;
        let default_threshold = 2u32;
        let receive_asset_immediate_threshold = 1u32;

        let approver_set =
            ApproverSet::new(approvers, default_threshold).expect("invalid approver set");
        let config = AuthMultisigSmartConfig::new(approver_set)
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
                StorageMapKey::from_raw(BasicWallet::receive_asset_root().as_word()),
            )
            .expect("receive_asset policy should be present");
        assert_eq!(
            receive_asset_policy,
            Word::from([receive_asset_immediate_threshold, 0u32, 0u32, 0u32])
        );
    }

    #[test]
    fn test_multisig_smart_component_rejects_duplicate_procedure_roots() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let receive_asset_root = BasicWallet::receive_asset_root().as_word();
        let policy_one =
            ProcedurePolicy::with_immediate_threshold(1).expect("procedure policy should be valid");
        let policy_two =
            ProcedurePolicy::with_immediate_threshold(2).expect("procedure policy should be valid");

        let approver_set = ApproverSet::new(approvers, 2).expect("invalid approver set");
        let result = AuthMultisigSmartConfig::new(approver_set).with_proc_policies(vec![
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
}
