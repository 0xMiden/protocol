use alloc::vec::Vec;

use miden_protocol::Word;
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

use super::ProcedurePolicy;
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

static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig_smart::procedure_policies")
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

        let storage_schema = StorageSchema::new(vec![
            AuthMultisigSmart::threshold_config_slot_schema(),
            AuthMultisigSmart::approver_public_keys_slot_schema(),
            AuthMultisigSmart::approver_auth_scheme_slot_schema(),
            AuthMultisigSmart::executed_transactions_slot_schema(),
            AuthMultisigSmart::procedure_policies_slot_schema(),
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
    use crate::account::auth::multisig_smart::ProcedurePolicyNoteRestriction;
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
                BasicWallet::receive_asset_digest(),
                ProcedurePolicy::with_immediate_threshold(1)
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
        assert_eq!(threshold_config, Word::from([2u32, 2u32, 0, 0]));

        let receive_asset_policy = account
            .storage()
            .get_map_item(
                AuthMultisigSmart::procedure_policies_slot(),
                BasicWallet::receive_asset_digest(),
            )
            .expect("receive_asset policy should be present");
        assert_eq!(receive_asset_policy, Word::from([1u32, 0u32, 0u32, 0u32]));
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
