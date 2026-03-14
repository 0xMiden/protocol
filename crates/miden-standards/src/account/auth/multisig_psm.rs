use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentMetadata,
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

use super::multisig::{AuthMultisig, AuthMultisigConfig};
use crate::account::components::multisig_psm_library;

// CONSTANTS
// ================================================================================================

static PSM_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::psm::pub_key")
        .expect("storage slot name should be valid")
});

static PSM_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::psm::scheme")
        .expect("storage slot name should be valid")
});

// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthMultisigPsm`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthMultisigPsmConfig {
    multisig: AuthMultisigConfig,
    psm_config: PsmConfig,
}

/// Public configuration for the private state manager signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsmConfig {
    pub_key: PublicKeyCommitment,
    auth_scheme: AuthScheme,
}

impl PsmConfig {
    pub fn new(pub_key: PublicKeyCommitment, auth_scheme: AuthScheme) -> Self {
        Self { pub_key, auth_scheme }
    }

    pub fn pub_key(&self) -> PublicKeyCommitment {
        self.pub_key
    }

    pub fn auth_scheme(&self) -> AuthScheme {
        self.auth_scheme
    }

    fn public_key_slot() -> &'static StorageSlotName {
        &PSM_PUBKEY_SLOT_NAME
    }

    fn scheme_id_slot() -> &'static StorageSlotName {
        &PSM_SCHEME_ID_SLOT_NAME
    }

    fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::map(
                "Private state manager public keys",
                SchemaType::u32(),
                SchemaType::pub_key(),
            ),
        )
    }

    fn auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::scheme_id_slot().clone(),
            StorageSlotSchema::map(
                "Private state manager scheme IDs",
                SchemaType::u32(),
                SchemaType::auth_scheme(),
            ),
        )
    }

    fn into_component_parts(self) -> (Vec<StorageSlot>, Vec<(StorageSlotName, StorageSlotSchema)>) {
        let mut storage_slots = Vec::with_capacity(2);

        // Private state manager public key slot (map: [0, 0, 0, 0] -> pubkey)
        let psm_public_key_entries =
            [(StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0])), Word::from(self.pub_key))];
        storage_slots.push(StorageSlot::with_map(
            Self::public_key_slot().clone(),
            StorageMap::with_entries(psm_public_key_entries).unwrap(),
        ));

        // Private state manager scheme IDs slot (map: [0, 0, 0, 0] -> [scheme_id, 0, 0, 0])
        let psm_scheme_id_entries = [(
            StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0])),
            Word::from([self.auth_scheme as u32, 0, 0, 0]),
        )];
        storage_slots.push(StorageSlot::with_map(
            Self::scheme_id_slot().clone(),
            StorageMap::with_entries(psm_scheme_id_entries).unwrap(),
        ));

        let slot_metadata = vec![Self::public_key_slot_schema(), Self::auth_scheme_slot_schema()];

        (storage_slots, slot_metadata)
    }
}

impl AuthMultisigPsmConfig {
    /// Creates a new configuration with the given approvers, default threshold and PSM signer.
    ///
    /// The `default_threshold` must be at least 1 and at most the number of approvers.
    /// The private state manager public key must be different from all approver public keys.
    pub fn new(
        approvers: Vec<(PublicKeyCommitment, AuthScheme)>,
        default_threshold: u32,
        psm_config: PsmConfig,
    ) -> Result<Self, AccountError> {
        let multisig = AuthMultisigConfig::new(approvers, default_threshold)?;
        if multisig
            .approvers()
            .iter()
            .any(|(approver, _)| *approver == psm_config.pub_key())
        {
            return Err(AccountError::other(
                "private state manager public key must be different from approvers",
            ));
        }

        Ok(Self { multisig, psm_config })
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(Word, u32)>,
    ) -> Result<Self, AccountError> {
        self.multisig = self.multisig.with_proc_thresholds(proc_thresholds)?;
        Ok(self)
    }

    pub fn approvers(&self) -> &[(PublicKeyCommitment, AuthScheme)] {
        self.multisig.approvers()
    }

    pub fn default_threshold(&self) -> u32 {
        self.multisig.default_threshold()
    }

    pub fn proc_thresholds(&self) -> &[(Word, u32)] {
        self.multisig.proc_thresholds()
    }

    pub fn psm_config(&self) -> PsmConfig {
        self.psm_config
    }

    fn into_parts(self) -> (AuthMultisigConfig, PsmConfig) {
        (self.multisig, self.psm_config)
    }
}

/// An [`AccountComponent`] implementing a multisig authentication with a private state manager.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure threshold overrides. With Private State Manager (PSM) is configured,
/// multisig authorization is combined with PSM authorization, so operations require both
/// multisig approval and a valid PSM signature. This substantially mitigates low-threshold
/// state-withholding scenarios since the PSM is expected to forward state updates to other
/// approvers.
///
/// This component supports all account types.
#[derive(Debug)]
pub struct AuthMultisigPsm {
    multisig: AuthMultisig,
    psm_config: PsmConfig,
}

impl AuthMultisigPsm {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::multisig_psm";

    /// Creates a new [`AuthMultisigPsm`] component from the provided configuration.
    pub fn new(config: AuthMultisigPsmConfig) -> Result<Self, AccountError> {
        let (multisig_config, psm_config) = config.into_parts();
        Ok(Self {
            multisig: AuthMultisig::new(multisig_config)?,
            psm_config,
        })
    }

    /// Returns the [`StorageSlotName`] where the threshold configuration is stored.
    pub fn threshold_config_slot() -> &'static StorageSlotName {
        AuthMultisig::threshold_config_slot()
    }

    /// Returns the [`StorageSlotName`] where the approver public keys are stored.
    pub fn approver_public_keys_slot() -> &'static StorageSlotName {
        AuthMultisig::approver_public_keys_slot()
    }

    // Returns the [`StorageSlotName`] where the approver scheme IDs are stored.
    pub fn approver_scheme_ids_slot() -> &'static StorageSlotName {
        AuthMultisig::approver_scheme_ids_slot()
    }

    /// Returns the [`StorageSlotName`] where the executed transactions are stored.
    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        AuthMultisig::executed_transactions_slot()
    }

    /// Returns the [`StorageSlotName`] where the procedure thresholds are stored.
    pub fn procedure_thresholds_slot() -> &'static StorageSlotName {
        AuthMultisig::procedure_thresholds_slot()
    }

    /// Returns the [`StorageSlotName`] where the private state manager public key is stored.
    pub fn psm_public_key_slot() -> &'static StorageSlotName {
        PsmConfig::public_key_slot()
    }

    /// Returns the [`StorageSlotName`] where the private state manager scheme IDs are stored.
    pub fn psm_scheme_id_slot() -> &'static StorageSlotName {
        PsmConfig::scheme_id_slot()
    }

    /// Returns the storage slot schema for the threshold configuration slot.
    pub fn threshold_config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::threshold_config_slot_schema()
    }

    /// Returns the storage slot schema for the approver public keys slot.
    pub fn approver_public_keys_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::approver_public_keys_slot_schema()
    }

    // Returns the storage slot schema for the approver scheme IDs slot.
    pub fn approver_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::approver_auth_scheme_slot_schema()
    }

    /// Returns the storage slot schema for the executed transactions slot.
    pub fn executed_transactions_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::executed_transactions_slot_schema()
    }

    /// Returns the storage slot schema for the procedure thresholds slot.
    pub fn procedure_thresholds_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        AuthMultisig::procedure_thresholds_slot_schema()
    }

    /// Returns the storage slot schema for the private state manager public key slot.
    pub fn psm_public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        PsmConfig::public_key_slot_schema()
    }

    /// Returns the storage slot schema for the private state manager scheme IDs slot.
    pub fn psm_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        PsmConfig::auth_scheme_slot_schema()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([
            Self::threshold_config_slot_schema(),
            Self::approver_public_keys_slot_schema(),
            Self::approver_auth_scheme_slot_schema(),
            Self::executed_transactions_slot_schema(),
            Self::procedure_thresholds_slot_schema(),
            Self::psm_public_key_slot_schema(),
            Self::psm_auth_scheme_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME, AccountType::all())
            .with_description(
                "Multisig authentication component with private state manager \
                 using hybrid signature schemes",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthMultisigPsm> for AccountComponent {
    fn from(multisig: AuthMultisigPsm) -> Self {
        let AuthMultisigPsm { multisig, psm_config } = multisig;
        let multisig_component = AccountComponent::from(multisig);
        let (psm_slots, psm_slot_metadata) = psm_config.into_component_parts();

        let mut storage_slots = multisig_component.storage_slots().to_vec();
        storage_slots.extend(psm_slots);

        let mut slot_schemas: Vec<(StorageSlotName, StorageSlotSchema)> = multisig_component
            .storage_schema()
            .iter()
            .map(|(slot_name, slot_schema)| (slot_name.clone(), slot_schema.clone()))
            .collect();
        slot_schemas.extend(psm_slot_metadata);

        let storage_schema =
            StorageSchema::new(slot_schemas).expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(
            AuthMultisigPsm::NAME,
            multisig_component.supported_types().clone(),
        )
        .with_description(multisig_component.metadata().description())
        .with_version(multisig_component.metadata().version().clone())
        .with_storage_schema(storage_schema);

        AccountComponent::new(multisig_psm_library(), storage_slots, metadata).expect(
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
    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;
    use crate::account::wallets::BasicWallet;

    /// Test multisig component setup with various configurations
    #[test]
    fn test_multisig_component_setup() {
        // Create test secret keys
        let sec_key_1 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_2 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_3 = AuthSecretKey::new_falcon512_poseidon2();
        let psm_key = AuthSecretKey::new_ecdsa_k256_keccak();

        // Create approvers list for multisig config
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
            (sec_key_3.public_key().to_commitment(), sec_key_3.auth_scheme()),
        ];

        let threshold = 2u32;

        // Create multisig component
        let multisig_component = AuthMultisigPsm::new(
            AuthMultisigPsmConfig::new(
                approvers.clone(),
                threshold,
                PsmConfig::new(psm_key.public_key().to_commitment(), psm_key.auth_scheme()),
            )
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
            .get_item(AuthMultisigPsm::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        // Verify approver pub keys slot
        for (i, (expected_pub_key, _)) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthMultisigPsm::approver_public_keys_slot(),
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
                    AuthMultisigPsm::approver_scheme_ids_slot(),
                    Word::from([i as u32, 0, 0, 0]),
                )
                .expect("approver scheme ID storage map access failed");
            assert_eq!(stored_scheme_id, Word::from([*expected_auth_scheme as u32, 0, 0, 0]));
        }

        // Verify private state manager signer is configured.
        let psm_public_key = account
            .storage()
            .get_map_item(AuthMultisigPsm::psm_public_key_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("private state manager public key storage map access failed");
        assert_eq!(psm_public_key, Word::from(psm_key.public_key().to_commitment()));

        let psm_scheme_id = account
            .storage()
            .get_map_item(AuthMultisigPsm::psm_scheme_id_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("private state manager scheme ID storage map access failed");
        assert_eq!(psm_scheme_id, Word::from([psm_key.auth_scheme() as u32, 0, 0, 0]));
    }

    /// Test multisig component with minimum threshold (1 of 1)
    #[test]
    fn test_multisig_component_minimum_threshold() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let psm_key = AuthSecretKey::new_falcon512_poseidon2();
        let approvers = vec![(pub_key, AuthScheme::EcdsaK256Keccak)];
        let threshold = 1u32;

        let multisig_component = AuthMultisigPsm::new(
            AuthMultisigPsmConfig::new(
                approvers.clone(),
                threshold,
                PsmConfig::new(psm_key.public_key().to_commitment(), psm_key.auth_scheme()),
            )
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
            .get_item(AuthMultisigPsm::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        let stored_pub_key = account
            .storage()
            .get_map_item(AuthMultisigPsm::approver_public_keys_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));

        let stored_scheme_id = account
            .storage()
            .get_map_item(AuthMultisigPsm::approver_scheme_ids_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("approver scheme IDs storage map access failed");
        assert_eq!(stored_scheme_id, Word::from([AuthScheme::EcdsaK256Keccak as u32, 0, 0, 0]));
    }

    /// Test multisig component setup with a private state manager.
    #[test]
    fn test_multisig_component_with_psm() {
        let sec_key_1 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_2 = AuthSecretKey::new_falcon512_poseidon2();
        let psm_key = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let multisig_component = AuthMultisigPsm::new(
            AuthMultisigPsmConfig::new(
                approvers,
                2,
                PsmConfig::new(psm_key.public_key().to_commitment(), psm_key.auth_scheme()),
            )
            .expect("invalid multisig config"),
        )
        .expect("multisig component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        let psm_public_key = account
            .storage()
            .get_map_item(AuthMultisigPsm::psm_public_key_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("private state manager public key storage map access failed");
        assert_eq!(psm_public_key, Word::from(psm_key.public_key().to_commitment()));

        let psm_scheme_id = account
            .storage()
            .get_map_item(AuthMultisigPsm::psm_scheme_id_slot(), Word::from([0u32, 0, 0, 0]))
            .expect("private state manager scheme ID storage map access failed");
        assert_eq!(psm_scheme_id, Word::from([psm_key.auth_scheme() as u32, 0, 0, 0]));
    }

    /// Test multisig component error cases
    #[test]
    fn test_multisig_component_error_cases() {
        let pub_key = AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment();
        let psm_key = AuthSecretKey::new_falcon512_poseidon2();
        let approvers = vec![(pub_key, AuthScheme::EcdsaK256Keccak)];

        // Test threshold > number of approvers (should fail)
        let result = AuthMultisigPsmConfig::new(
            approvers,
            2,
            PsmConfig::new(psm_key.public_key().to_commitment(), psm_key.auth_scheme()),
        );

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
        let psm_key = AuthSecretKey::new_falcon512_poseidon2();

        // Create approvers list with duplicate public keys
        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigPsmConfig::new(
            approvers,
            2,
            PsmConfig::new(psm_key.public_key().to_commitment(), psm_key.auth_scheme()),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate approver public keys are not allowed")
        );
    }

    /// Test multisig component rejects a private state manager key which is already an approver.
    #[test]
    fn test_multisig_component_psm_not_approver() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![
            (sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
            (sec_key_2.public_key().to_commitment(), sec_key_2.auth_scheme()),
        ];

        let result = AuthMultisigPsmConfig::new(
            approvers,
            2,
            PsmConfig::new(sec_key_1.public_key().to_commitment(), sec_key_1.auth_scheme()),
        );

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("private state manager public key must be different from approvers")
        );
    }
}
