use alloc::vec::Vec;

use miden_protocol::Word;
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
    AccountComponentName,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

use super::{Approver, ApproverSet};
use crate::account::account_component_code;

account_component_code!(MULTISIG_CODE, "auth/multisig.masl");

// CONSTANTS
// ================================================================================================

pub(super) static THRESHOLD_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::threshold_config")
        .expect("storage slot name should be valid")
});

pub(super) static APPROVER_PUBKEYS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::approver_public_keys")
        .expect("storage slot name should be valid")
});

pub(super) static APPROVER_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::approver_schemes")
        .expect("storage slot name should be valid")
});

pub(super) static EXECUTED_TRANSACTIONS_SLOT_NAME: LazyLock<StorageSlotName> =
    LazyLock::new(|| {
        StorageSlotName::new("miden::standards::auth::multisig::executed_transactions")
            .expect("storage slot name should be valid")
    });

static PROCEDURE_THRESHOLDS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::multisig::procedure_thresholds")
        .expect("storage slot name should be valid")
});

// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisig`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigConfig {
    approver_set: ApproverSet,
    proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
}

impl AuthMultisigConfig {
    /// Creates a new configuration from the given approver set.
    pub fn new(approver_set: ApproverSet) -> Self {
        Self {
            approver_set,
            proc_thresholds: Vec::new(),
        }
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    ) -> Result<Self, AccountError> {
        let num_approvers = self.approver_set.approvers().len() as u32;
        for (_, threshold) in &proc_thresholds {
            if *threshold == 0 {
                return Err(AccountError::other("procedure threshold must be at least 1"));
            }
            if *threshold > num_approvers {
                return Err(AccountError::other(
                    "procedure threshold cannot be greater than number of approvers",
                ));
            }
        }
        self.proc_thresholds = proc_thresholds;
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

    pub fn proc_thresholds(&self) -> &[(AccountProcedureRoot, u32)] {
        &self.proc_thresholds
    }
}

/// An [`AccountComponent`] implementing a multisig authentication.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure threshold overrides.
///
/// For private accounts this component should be used with caution. A private account's state
/// lives off-chain, so whoever advances it must share the new state with the other approvers; any
/// quorum that advances the state and withholds it permanently locks the excluded approvers out.
/// A per-procedure threshold of one makes this trivial for a single approver. Without a guardian,
/// the only fully withholding-safe configuration is unanimity (`threshold == number of approvers`).
/// For a private `m`-of-`n` wallet among mutually distrusting approvers, prefer
/// [`AuthGuardedMultisig`](super::AuthGuardedMultisig), whose guardian forwards state updates. See
/// [`create_multisig_wallet`](crate::account::wallets::create_multisig_wallet) for the full
/// rationale.
#[derive(Debug)]
pub struct AuthMultisig {
    config: AuthMultisigConfig,
}

impl AuthMultisig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::multisig";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_CODE
    }

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
                SchemaType::u32(),
                SchemaType::pub_key(),
            ),
        )
    }

    // Returns the storage slot schema for the approver scheme IDs slot.
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

    /// Returns the storage slot schema for the executed transactions slot.
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

    /// Returns the storage slot schema for the procedure thresholds slot.
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

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([
            Self::threshold_config_slot_schema(),
            Self::approver_public_keys_slot_schema(),
            Self::approver_auth_scheme_slot_schema(),
            Self::executed_transactions_slot_schema(),
            Self::procedure_thresholds_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description("Multisig authentication component using hybrid signature schemes")
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthMultisig> for AccountComponent {
    fn from(multisig: AuthMultisig) -> Self {
        let mut storage_slots = Vec::with_capacity(5);

        // Threshold config slot (value: [threshold, num_approvers, 0, 0])
        let num_approvers = multisig.config.approvers().len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthMultisig::threshold_config_slot().clone(),
            Word::from([multisig.config.default_threshold(), num_approvers, 0, 0]),
        ));

        // Approver public keys slot (map)
        let map_entries = multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
            (StorageMapKey::from_index(i as u32), Word::from(approver.pub_key()))
        });

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::approver_public_keys_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        // Approver scheme IDs slot (map): [index, 0, 0, 0] => [scheme_id, 0, 0, 0]
        let scheme_id_entries =
            multisig.config.approvers().iter().enumerate().map(|(i, approver)| {
                (
                    StorageMapKey::from_index(i as u32),
                    Word::from([approver.auth_scheme() as u32, 0, 0, 0]),
                )
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
            multisig.config.proc_thresholds().iter().map(|(proc_root, threshold)| {
                (StorageMapKey::from_raw(proc_root.as_word()), Word::from([*threshold, 0, 0, 0]))
            }),
        )
        .unwrap();
        storage_slots.push(StorageSlot::with_map(
            AuthMultisig::procedure_thresholds_slot().clone(),
            proc_threshold_roots,
        ));

        let metadata = AuthMultisig::component_metadata();

        AccountComponent::new(AuthMultisig::code().clone(), storage_slots, metadata).expect(
            "Multisig auth component should satisfy the requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

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
        let sec_key_1 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_2 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_3 = AuthSecretKey::new_falcon512_poseidon2();

        // Create approvers list for multisig config
        let approvers = vec![
            Approver::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            Approver::new(sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
            Approver::new(sec_key_3.public_key().to_commitment(), sec_key_3.auth_scheme()),
        ];

        let threshold = 2u32;

        // Create multisig component
        let approver_set =
            ApproverSet::new(approvers.clone(), threshold).expect("invalid approver set");
        let multisig_component = AuthMultisig::new(AuthMultisigConfig::new(approver_set))
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
        for (i, approver) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthMultisig::approver_public_keys_slot(),
                    StorageMapKey::from_index(i as u32),
                )
                .expect("approver public key storage map access failed");
            assert_eq!(stored_pub_key, Word::from(approver.pub_key()));
        }

        // Verify approver scheme IDs slot
        for (i, approver) in approvers.iter().enumerate() {
            let stored_scheme_id = account
                .storage()
                .get_map_item(
                    AuthMultisig::approver_scheme_ids_slot(),
                    StorageMapKey::from_index(i as u32),
                )
                .expect("approver scheme ID storage map access failed");
            assert_eq!(stored_scheme_id, Word::from([approver.auth_scheme() as u32, 0, 0, 0]));
        }
    }

    /// Test multisig component with minimum threshold (1 of 1)
    #[test]
    fn test_multisig_component_minimum_threshold() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let approvers = vec![Approver::new(pub_key, auth::AuthScheme::EcdsaK256Keccak)];
        let threshold = 1u32;

        let approver_set =
            ApproverSet::new(approvers.clone(), threshold).expect("invalid approver set");
        let multisig_component = AuthMultisig::new(AuthMultisigConfig::new(approver_set))
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
            .get_map_item(AuthMultisig::approver_public_keys_slot(), StorageMapKey::from_index(0))
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));

        let stored_scheme_id = account
            .storage()
            .get_map_item(AuthMultisig::approver_scheme_ids_slot(), StorageMapKey::from_index(0))
            .expect("approver scheme IDs storage map access failed");
        assert_eq!(
            stored_scheme_id,
            Word::from([auth::AuthScheme::EcdsaK256Keccak as u32, 0, 0, 0])
        );
    }

    /// Test that a per-procedure threshold exceeding the number of approvers is rejected.
    #[test]
    fn test_proc_threshold_too_high() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let approvers = vec![Approver::new(pub_key, auth::AuthScheme::EcdsaK256Keccak)];
        let approver_set = ApproverSet::new(approvers, 1).expect("invalid approver set");

        let result = AuthMultisigConfig::new(approver_set)
            .with_proc_thresholds(vec![(BasicWallet::receive_asset_root(), 2)]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("procedure threshold cannot be greater than number of approvers")
        );
    }
}
