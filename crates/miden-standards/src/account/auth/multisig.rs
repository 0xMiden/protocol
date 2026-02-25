use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaTypeId,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, StorageMap, StorageSlot, StorageSlotName};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::multisig_library;

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

static PRIVATE_STATE_MANAGER_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::private_state_manager_config")
        .expect("storage slot name should be valid")
});

static PRIVATE_STATE_MANAGER_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::psm_public_key")
        .expect("storage slot name should be valid")
});

static PRIVATE_STATE_MANAGER_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::psm_scheme")
        .expect("storage slot name should be valid")
});

// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisig`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigConfig {
    approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
    default_threshold: u32,
    proc_thresholds: Vec<(Word, u32)>,
    private_state_manager: Option<(PublicKeyCommitment, AuthScheme)>,
}

impl AuthMultisigConfig {
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

        if unique_approvers.len() != approvers.len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        Ok(Self {
            approvers,
            default_threshold,
            proc_thresholds: vec![],
            private_state_manager: None,
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

    /// Enables additional signature verification by a private state manager.
    ///
    /// The private state manager public key must be different from all approver public keys.
    pub fn with_private_state_manager(
        mut self,
        private_state_manager: (PublicKeyCommitment, AuthScheme),
    ) -> Result<Self, AccountError> {
        if self.approvers.iter().any(|(approver, _)| *approver == private_state_manager.0) {
            return Err(AccountError::other(
                "private state manager public key must be different from approvers",
            ));
        }

        self.private_state_manager = Some(private_state_manager);
        Ok(self)
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

    pub fn private_state_manager(&self) -> Option<(PublicKeyCommitment, AuthScheme)> {
        self.private_state_manager
    }
}

/// An [`AccountComponent`] implementing a multisig based on ECDSA signatures.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure thresholds overrides. Non-uniform thresholds (especially a threshold of one)
/// should be used with caution for private multisig accounts, as a single approver could withhold
///  the new state from other approvers, effectively locking them out.
///
/// The storage layout is:
/// - Slot 0(value): [threshold, num_approvers, 0, 0]
/// - Slot 1(map): A map with approver public keys (index -> pubkey)
/// - Slot 2(map): A map with approver scheme ids (index -> scheme_id)
/// - Slot 3(map): A map which stores executed transactions
/// - Slot 4(map): A map which stores procedure thresholds (PROC_ROOT -> threshold)
/// - Slot 5(value): [is_psm_signature_required, is_psm_initialized, 0, 0]
/// - Slot 6(map): A map with private state manager public key ([0, 0, 0, 0] -> pubkey)
/// - Slot 7(map): A map with private state manager scheme id ([0, 0, 0, 0] -> scheme_id)
///
/// This component supports all account types.
#[derive(Debug)]
pub struct AuthMultisig {
    config: AuthMultisigConfig,
}

impl AuthMultisig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::auth::multisig";

    /// Creates a new [`AuthMultisig`] component from the provided configuration.
    pub fn new(config: AuthMultisigConfig) -> Result<Self, AccountError> {
        Ok(Self { config })
    }

    /// Returns the [`StorageSlotName`] where the threshold configuration is stored.
    pub fn threshold_config_slot() -> &'static StorageSlotName {
        &THRESHOLD_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the approver public keys are stored.
    pub fn approver_public_keys_slot() -> &'static StorageSlotName {
        &APPROVER_PUBKEYS_SLOT_NAME
    }

    // Returns the [`StorageSlotName`] where the approver scheme IDs are stored.
    pub fn approver_scheme_ids_slot() -> &'static StorageSlotName {
        &APPROVER_SCHEME_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the executed transactions are stored.
    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        &EXECUTED_TRANSACTIONS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the procedure thresholds are stored.
    pub fn procedure_thresholds_slot() -> &'static StorageSlotName {
        &PROCEDURE_THRESHOLDS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the private state manager config is stored.
    pub fn private_state_manager_config_slot() -> &'static StorageSlotName {
        &PRIVATE_STATE_MANAGER_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the private state manager public key is stored.
    pub fn private_state_manager_public_keys_slot() -> &'static StorageSlotName {
        &PRIVATE_STATE_MANAGER_PUBKEY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the private state manager scheme IDs are stored.
    pub fn private_state_manager_scheme_ids_slot() -> &'static StorageSlotName {
        &PRIVATE_STATE_MANAGER_SCHEME_ID_SLOT_NAME
    }

    /// Returns PSM config word for `enabled + initialized` state.
    pub fn psm_config_enabled_initialized() -> Word {
        Word::from([1u32, 1, 0, 0])
    }

    /// Returns PSM config word for `enabled + uninitialized` state.
    pub fn psm_config_enabled_uninitialized() -> Word {
        Word::from([1u32, 0, 0, 0])
    }

    /// Returns PSM config word for `disabled + initialized` state.
    pub fn psm_config_disabled_initialized() -> Word {
        Word::from([0u32, 1, 0, 0])
    }

    /// Returns PSM config word for `disabled + uninitialized` state.
    pub fn psm_config_disabled_uninitialized() -> Word {
        Word::from([0u32, 0, 0, 0])
    }

    /// Returns the storage slot schema for the threshold configuration slot.
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

    /// Returns the storage slot schema for the approver public keys slot.
    pub fn approver_public_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::approver_public_keys_slot().clone(),
            StorageSlotSchema::map(
                "Approver public keys",
                SchemaTypeId::u32(),
                SchemaTypeId::pub_key(),
            ),
        )
    }

    // Returns the storage slot schema for the approver scheme IDs slot.
    pub fn approver_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::approver_scheme_ids_slot().clone(),
            StorageSlotSchema::map(
                "Approver scheme IDs",
                SchemaTypeId::u32(),
                SchemaTypeId::auth_scheme(),
            ),
        )
    }

    /// Returns the storage slot schema for the executed transactions slot.
    pub fn executed_transactions_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::executed_transactions_slot().clone(),
            StorageSlotSchema::map(
                "Executed transactions",
                SchemaTypeId::native_word(),
                SchemaTypeId::native_word(),
            ),
        )
    }

    /// Returns the storage slot schema for the procedure thresholds slot.
    pub fn procedure_thresholds_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::procedure_thresholds_slot().clone(),
            StorageSlotSchema::map(
                "Procedure thresholds",
                SchemaTypeId::native_word(),
                SchemaTypeId::u32(),
            ),
        )
    }

    /// Returns the storage slot schema for the private state manager config slot.
    pub fn private_state_manager_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::private_state_manager_config_slot().clone(),
            StorageSlotSchema::value(
                "Private state manager config",
                [
                    FeltSchema::u32("is_psm_signature_required").with_default(Felt::new(0)),
                    FeltSchema::u32("is_psm_initialized").with_default(Felt::new(0)),
                    FeltSchema::new_void(),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    /// Returns the storage slot schema for the private state manager public key slot.
    pub fn private_state_manager_public_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::private_state_manager_public_keys_slot().clone(),
            StorageSlotSchema::map(
                "Private state manager public keys",
                SchemaTypeId::u32(),
                SchemaTypeId::pub_key(),
            ),
        )
    }

    /// Returns the storage slot schema for the private state manager scheme IDs slot.
    pub fn psm_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::private_state_manager_scheme_ids_slot().clone(),
            StorageSlotSchema::map(
                "Private state manager scheme IDs",
                SchemaTypeId::u32(),
                SchemaTypeId::auth_scheme(),
            ),
        )
    }
}

impl From<AuthMultisig> for AccountComponent {
    fn from(multisig: AuthMultisig) -> Self {
        let mut storage_slots = Vec::with_capacity(8);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisig::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries = multisig
            .config
            .approvers()
            .iter()
            .enumerate()
            .map(|(i, (pub_key, _))| (Word::from([i as u32, 0, 0, 0]), Word::from(*pub_key)));

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot (map): [index, 0, 0, 0] => [scheme_id, 0, 0, 0]
        let scheme_id_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, (_, auth_scheme))| {
                (Word::from([i as u32, 0, 0, 0]), Word::from([*auth_scheme as u32, 0, 0, 0]))
            });

        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::approver_scheme_ids_slot().clone(),
            StorageMap::with_entries(scheme_id_entries).unwrap(),
        ));

        // Executed transactions slot (map)
        let executed_transactions = StorageMap::default();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::executed_transactions_slot().clone(),
            executed_transactions,
        ));

        // Procedure thresholds slot (map: PROC_ROOT -> threshold)
        let proc_threshold_roots = StorageMap::with_entries(
            multisig
                .config
                .proc_thresholds()
                .iter()
                .map(|(proc_root, threshold)| (*proc_root, Word::from([*threshold, 0, 0, 0]))),
        )
        .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::procedure_thresholds_slot().clone(),
            proc_threshold_roots,
        ));

        // Private state manager config slot (value: [is_psm_signature_required, is_psm_initialized,
        // 0, 0])
        let is_psm_initialized = u32::from(multisig.config.private_state_manager().is_some());
        let psm_config = if is_psm_initialized == 1 {
            AuthMultisig::psm_config_enabled_initialized()
        } else {
            AuthMultisig::psm_config_disabled_uninitialized()
        };
        storage_slots.push(StorageSlot::with_value(
            AuthMultisig::private_state_manager_config_slot().clone(),
            psm_config,
        ));

        // Private state manager public key slot (map: [0, 0, 0, 0] -> pubkey)
        let psm_public_key_entries = multisig
            .config
            .private_state_manager()
            .into_iter()
            .map(|(pub_key, _)| (Word::from([0u32, 0, 0, 0]), Word::from(pub_key)));
        storage_slots.push(StorageSlot::with_map(
            Authmultisig::psm_public_key_slot().clone(),
            StorageMap::with_entries(psm_public_key_entries).unwrap(),
        ));

        // Private state manager scheme IDs slot (map: [0, 0, 0, 0] -> [scheme_id, 0, 0, 0])
        let psm_scheme_id_entries =
            multisig.config.private_state_manager().into_iter().map(|(_, auth_scheme)| {
                (Word::from([0u32, 0, 0, 0]), Word::from([auth_scheme as u32, 0, 0, 0]))
            });
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::private_state_manager_scheme_ids_slot().clone(),
            StorageMap::with_entries(psm_scheme_id_entries).unwrap(),
        ));

        let storage_schema = StorageSchema::new([
            AuthMultisig::threshold_config_slot_schema(),
            AuthMultisig::approver_public_keys_slot_schema(),
            AuthMultisig::approver_auth_scheme_slot_schema(),
            AuthMultisig::executed_transactions_slot_schema(),
            AuthMultisig::procedure_thresholds_slot_schema(),
            AuthMultisig::private_state_manager_config_slot_schema(),
            Authmultisig::psm_public_key_slot_schema(),
            AuthMultisig::psm_auth_scheme_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthMultisig::NAME)
            .with_description("Multisig authentication component using hybrid signature schemes")
            .with_supports_all_types()
            .with_storage_schema(storage_schema);

        AccountComponent::new(multisig_library(), storage_slots, metadata).expect(
            "Multisig auth component should satisfy the requirements of a valid account component",
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::Word;
    use miden_protocol::account::auth::AuthSecretKey;
    use miden_protocol::account::{AccountBuilder, auth};

    use super::*;
    use crate::account::wallets::BasicWallet;

    /// Test multisig component setup with various configurations
    #[test]
    fn test_multisig_component_setup() {
        // Create test secret keys
        let sec_key_1 = AuthSecretKey::new_falcon512_rpo();
        let sec_key_2 = AuthSecretKey::new_falcon512_rpo();
        let sec_key_3 = AuthSecretKey::new_falcon512_rpo();

        // Create approvers list for multisig config
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
            (sec_key_3.public_key().to_commitment(), sec_key_3.auth_scheme()),
        ];

        let threshold = 2u32;

        // Create multisig component
        let multisig_component = AuthMultisig::new(
            AuthMultisigConfig::new(approvers.clone(), threshold).expect("invalid multisig config"),
        )
        .expect("multisig component creation failed");

        // Build account with multisig component
        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify config slot: [threshold, num_approvers, 0, 0]
        let config_slot = account
            .storage()
            .get_item(AuthMultisig::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        // Verify approver pub keys slot
        for (i, (expected_pub_key, _)) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthMultisig::approver_public_keys_slot(),
                    Word::from([i as u32, 0, 0, 0]),
                )
                .expect("approver public key storage map access failed");
            assert_eq!(stored_pub_key, Word::from(*expected_pub_key));
        }

        // Verify approver scheme IDs slot
        for (i, (_, expected_auth_scheme)) in approvers.iter().enumerate() {
            let stored_scheme_id = account
                .storage()
                .get_map_item(
                    AuthMultisig::approver_scheme_ids_slot(),
                    Word::from([i as u32, 0, 0, 0]),
                )
                .expect("approver scheme ID storage map access failed");
            assert_eq!(stored_scheme_id, Word::from([*expected_auth_scheme as u32, 0, 0, 0]));
        }

        let psm_config = account
            .storage()
            .get_item(AuthMultisig::private_state_manager_config_slot())
            .expect("private state manager config storage slot access failed");
        assert_eq!(psm_config, AuthMultisig::psm_config_disabled_uninitialized());

        // Verify no private state manager is configured by default.
        assert!(
            account
                .storage()
                .get_map_item(Authmultisig::psm_public_key_slot(), Word::from([0u32, 0, 0, 0]),)
                .is_err()
        );

        assert!(
            account
                .storage()
                .get_map_item(
                    AuthMultisig::private_state_manager_scheme_ids_slot(),
                    Word::from([0u32, 0, 0, 0]),
                )
                .is_err()
        );
    }

    /// Test multisig component with minimum threshold (1 of 1)
    #[test]
    fn test_multisig_component_minimum_threshold() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let approvers = vec![(pub_key, auth::AuthScheme::EcdsaK256Keccak)];
        let threshold = 1u32;

        let multisig_component = AuthMultisig::new(
            AuthMultisigConfig::new(approvers.clone(), threshold).expect("invalid multisig config"),
        )
        .expect("multisig component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify storage layout
        let config_slot = account
            .storage()
            .get_item(AuthMultisig::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        let stored_pub_key = account
            .storage()
            .get_map_item(AuthMultisig::approver_public_keys_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));

        let stored_scheme_id = account
            .storage()
            .get_map_item(AuthMultisig::approver_scheme_ids_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("approver scheme IDs storage map access failed");
        assert_eq!(
            stored_scheme_id,
            Word::from([auth::AuthScheme::EcdsaK256Keccak as u32, 0, 0, 0])
        );
    }

    /// Test multisig component setup with a private state manager.
    #[test]
    fn test_multisig_component_with_private_state_manager() {
        let sec_key_1 = AuthSecretKey::new_falcon512_rpo();
        let sec_key_2 = AuthSecretKey::new_falcon512_rpo();
        let psm_key = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let multisig_component = AuthMultisig::new(
            AuthMultisigConfig::new(approvers, 2)
                .expect("invalid multisig config")
                .with_private_state_manager((
                    psm_key.public_key().to_commitment(),
                    psm_key.auth_scheme(),
                ))
                .expect("invalid private state manager config"),
        )
        .expect("multisig component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        let psm_config = account
            .storage()
            .get_item(AuthMultisig::private_state_manager_config_slot())
            .expect("private state manager config storage slot access failed");
        assert_eq!(psm_config, AuthMultisig::psm_config_enabled_initialized());

        let psm_public_key = account
            .storage()
            .get_map_item(Authmultisig::psm_public_key_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("private state manager public key storage map access failed");
        assert_eq!(psm_public_key, Word::from(psm_key.public_key().to_commitment()));

        let psm_scheme_id = account
            .storage()
            .get_map_item(
                AuthMultisig::private_state_manager_scheme_ids_slot(),
                Word::from([0u32, 0, 0, 0]),
            )
            .expect("private state manager scheme ID storage map access failed");
        assert_eq!(psm_scheme_id, Word::from([psm_key.auth_scheme() as u32, 0, 0, 0]));
    }

    /// Test multisig component error cases
    #[test]
    fn test_multisig_component_error_cases() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let approvers = vec![(pub_key, auth::AuthScheme::EcdsaK256Keccak)];

        // Test threshold = 0 (should fail)
        let result = AuthMultisigConfig::new(approvers.clone(), 0);
        assert!(result.unwrap_err().to_string().contains("threshold must be at least 1"));

        // Test threshold > number of approvers (should fail)
        let result = AuthMultisigConfig::new(approvers, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("threshold cannot be greater than number of approvers")
        );
    }

    /// Test multisig component with duplicate approvers (should fail)
    #[test]
    fn test_multisig_component_duplicate_approvers() {
        // Create secret keys for approvers
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();

        // Create approvers list with duplicate public keys
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigConfig::new(approvers, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }

    /// Test multisig component rejects a private state manager key which is already an approver.
    #[test]
    fn test_multisig_component_private_state_manager_not_approver() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigConfig::new(approvers, 2).and_then(|cfg| {
            cfg.with_private_state_manager((
                sec_key_1.public_key().to_commitment(),
                sec_key_1.auth_scheme(),
            ))
        });

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("private state manager public key must be different from approvers")
        );
    }

    #[test]
    fn test_multisig_psm_config_state_constants() {
        assert_eq!(AuthMultisig::psm_config_enabled_initialized(), Word::from([1u32, 1, 0, 0]));
        assert_eq!(AuthMultisig::psm_config_enabled_uninitialized(), Word::from([1u32, 0, 0, 0]));
        assert_eq!(AuthMultisig::psm_config_disabled_initialized(), Word::from([0u32, 1, 0, 0]));
        assert_eq!(AuthMultisig::psm_config_disabled_uninitialized(), Word::from([0u32, 0, 0, 0]));
    }
}
