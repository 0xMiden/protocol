use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{AccountComponent, StorageMap, StorageSlot, StorageSlotName};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

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
    StorageSlotName::new("miden::standards::auth::multisig::approver_scheme_id")
        .expect("storage slot name should be valid")
});

static EXECUTED_TRANSACTIONS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new(
        "miden::standards::auth::multisig::executed_transactions",
    )
    .expect("storage slot name should be valid")
});

static PROCEDURE_THRESHOLDS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::procedure_thresholds")
        .expect("storage slot name should be valid")
});

// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthEcdsaK256KeccakMultisig`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigConfig {
    approvers: Vec<PublicKeyCommitment>,
    scheme_ids: Vec<u8>,
    default_threshold: u32,
    proc_thresholds: Vec<(Word, u32)>,
}

impl AuthMultisigConfig {
    /// Creates a new configuration with the given approvers and a default threshold.
    ///
    /// The `default_threshold` must be at least 1 and at most the number of approvers.
    pub fn new(
        approvers: Vec<PublicKeyCommitment>,
        scheme_ids: Vec<u8>,
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
        if approvers.len() != approvers.iter().collect::<BTreeSet<_>>().len() {
            return Err(AccountError::other("duplicate approver public keys are not allowed"));
        }

        // Check for scheme_ids for each approver
        if scheme_ids.len() != approvers.len() {
            return Err(AccountError::other(
                "number of scheme IDs must match number of approvers",
            ));
        }

        Ok(Self {
            approvers,
            scheme_ids,
            default_threshold,
            proc_thresholds: vec![],
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

    pub fn approvers(&self) -> &[PublicKeyCommitment] {
        &self.approvers
    }

    pub fn scheme_ids(&self) -> &[u8] {
        &self.scheme_ids
    }

    pub fn default_threshold(&self) -> u32 {
        self.default_threshold
    }

    pub fn proc_thresholds(&self) -> &[(Word, u32)] {
        &self.proc_thresholds
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
/// - Slot 2(map): A map which stores executed transactions
/// - Slot 3(map): A map which stores procedure thresholds (PROC_ROOT -> threshold)
///
/// This component supports all account types.
#[derive(Debug)]
pub struct AuthMultisig {
    config: AuthMultisigConfig,
}

impl AuthMultisig {
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
}

impl From<AuthMultisig> for AccountComponent {
    fn from(multisig: AuthMultisig) -> Self {
        let mut storage_slots = Vec::with_capacity(3);

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
            .map(|(i, pub_key)| (Word::from([i as u32, 0, 0, 0]), (*pub_key).into()));

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot (map)
        let scheme_id_entries = multisig
            .config
            .approvers()
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let pub_key = multisig.config.approvers()[i];
                let scheme_id = multisig.config.scheme_ids()[i];
                (Word::from(pub_key), Word::from([scheme_id as u32, 0, 0, 0]))
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

        AccountComponent::new(multisig_library(), storage_slots)
            .expect("Multisig auth component should satisfy the requirements of a valid account component")
            .with_supports_all_types()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;
    use crate::account::wallets::BasicWallet;

    /// Test multisig component setup with various configurations
    #[test]
    fn test_multisig_component_setup() {
        // Create test public keys
        let pub_key_1 = AuthSecretKey::new_falcon512_rpo().public_key_commitment();
        let pub_key_2 = AuthSecretKey::new_falcon512_rpo().public_key_commitment();
        let pub_key_3 = AuthSecretKey::new_falcon512_rpo().public_key_commitment();
        let approvers = vec![pub_key_1, pub_key_2, pub_key_3];

        let scheme_id_0 = 0u8; // Falcon512Rpo
        let scheme_id_1 = 0u8; // Falcon512Rpo
        let scheme_id_2 = 0u8; // Falcon512Rpo

        let scheme_ids = vec![scheme_id_0, scheme_id_1, scheme_id_2];
        let threshold = 2u32;

        // How de we know the corresponding scheme IDs for the approvers? 0 for falcon, 1 for ecdsa

        // Create multisig component
        let multisig_component = AuthMultisig::new(
            AuthMultisigConfig::new(approvers.clone(),scheme_ids.clone(), threshold)
                .expect("invalid multisig config"),
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
        for (i, expected_pub_key) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthMultisig::approver_public_keys_slot(),
                    Word::from([i as u32, 0, 0, 0]),
                )
                .expect("approver public key storage map access failed");
            assert_eq!(stored_pub_key, Word::from(*expected_pub_key));
        }
    }

    /// Test multisig component with minimum threshold (1 of 1)
    #[test]
    fn test_multisig_component_minimum_threshold() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key_commitment();
        let approvers = vec![pub_key];
        let scheme_ids = vec![1u8]; 
        let threshold = 1u32;

        let multisig_component = AuthMultisig::new(
            AuthMultisigConfig::new(approvers.clone(), scheme_ids.clone(), threshold)
                .expect("invalid multisig config"),
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
            .get_map_item(
                AuthMultisig::approver_public_keys_slot(),
                Word::from([0u32, 0, 0, 0]),
            )
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));
    }

    /// Test multisig component error cases
    #[test]
    fn test_multisig_component_error_cases() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key_commitment();
        let approvers = vec![pub_key];
        let scheme_ids = vec![1u8];

        // Test threshold = 0 (should fail)
        let result = AuthMultisigConfig::new(approvers.clone(), scheme_ids.clone(), 0);
        assert!(result.unwrap_err().to_string().contains("threshold must be at least 1"));

        // Test threshold > number of approvers (should fail)
        let result = AuthMultisigConfig::new(approvers, scheme_ids, 2);
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
        let pub_key_1 = AuthSecretKey::new_ecdsa_k256_keccak().public_key_commitment();
        let pub_key_2 = AuthSecretKey::new_ecdsa_k256_keccak().public_key_commitment();

        // Test with duplicate approvers (should fail)
        let approvers = vec![pub_key_1, pub_key_2, pub_key_1];
        let scheme_ids = vec![1u8, 1u8, 1u8];
        let result = AuthMultisigConfig::new(approvers, scheme_ids, 2);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }
}
