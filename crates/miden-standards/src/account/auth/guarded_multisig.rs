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
    AccountComponentName,
    AccountProcedureRoot,
    StorageMap,
    StorageMapKey,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

use super::multisig::{AuthMultisig, AuthMultisigConfig};
use super::{Approver, ApproverSet};
use crate::account::account_component_code;

account_component_code!(GUARDED_MULTISIG_CODE, "auth/guarded_multisig.masl");

// CONSTANTS
// ================================================================================================

static GUARDIAN_PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::guardian::pub_key")
        .expect("storage slot name should be valid")
});

static GUARDIAN_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::guardian::scheme")
        .expect("storage slot name should be valid")
});

// MULTISIG AUTHENTICATION COMPONENT
// ================================================================================================

/// Configuration for [`AuthGuardedMultisig`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthGuardedMultisigConfig {
    multisig: AuthMultisigConfig,
    guardian_config: GuardianConfig,
}

/// Public configuration for the guardian signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardianConfig {
    approver: Approver,
}

impl GuardianConfig {
    pub fn new(approver: Approver) -> Self {
        Self { approver }
    }

    pub fn approver(&self) -> Approver {
        self.approver
    }

    pub fn pub_key(&self) -> PublicKeyCommitment {
        self.approver.pub_key()
    }

    pub fn auth_scheme(&self) -> AuthScheme {
        self.approver.auth_scheme()
    }

    fn public_key_slot() -> &'static StorageSlotName {
        &GUARDIAN_PUBKEY_SLOT_NAME
    }

    fn scheme_id_slot() -> &'static StorageSlotName {
        &GUARDIAN_SCHEME_ID_SLOT_NAME
    }

    fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::map(
                "Guardian public keys",
                SchemaType::u32(),
                SchemaType::pub_key(),
            ),
        )
    }

    fn auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::scheme_id_slot().clone(),
            StorageSlotSchema::map(
                "Guardian scheme IDs",
                SchemaType::u32(),
                SchemaType::auth_scheme(),
            ),
        )
    }

    fn into_component_parts(self) -> (Vec<StorageSlot>, Vec<(StorageSlotName, StorageSlotSchema)>) {
        let mut storage_slots = Vec::with_capacity(2);

        // Guardian public key slot (map: [0, 0, 0, 0] -> pubkey)
        let guardian_public_key_entries =
            [(StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0])), Word::from(self.pub_key()))];
        storage_slots.push(StorageSlot::with_map(
            Self::public_key_slot().clone(),
            StorageMap::with_entries(guardian_public_key_entries).unwrap(),
        ));

        // Guardian scheme IDs slot (map: [0, 0, 0, 0] -> [scheme_id, 0, 0, 0])
        let guardian_scheme_id_entries = [(
            StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0])),
            Word::from([self.auth_scheme() as u32, 0, 0, 0]),
        )];
        storage_slots.push(StorageSlot::with_map(
            Self::scheme_id_slot().clone(),
            StorageMap::with_entries(guardian_scheme_id_entries).unwrap(),
        ));

        let slot_metadata = vec![Self::public_key_slot_schema(), Self::auth_scheme_slot_schema()];

        (storage_slots, slot_metadata)
    }
}

impl AuthGuardedMultisigConfig {
    /// Creates a new configuration with the given approver set and guardian signer.
    ///
    /// The guardian public key must be different from all approver public keys.
    pub fn new(
        approver_set: ApproverSet,
        guardian_config: GuardianConfig,
    ) -> Result<Self, AccountError> {
        if approver_set
            .approvers()
            .iter()
            .any(|approver| approver.pub_key() == guardian_config.pub_key())
        {
            return Err(AccountError::other(
                "guardian public key must be different from approvers",
            ));
        }

        Ok(Self {
            multisig: AuthMultisigConfig::new(approver_set),
            guardian_config,
        })
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    ) -> Result<Self, AccountError> {
        self.multisig = self.multisig.with_proc_thresholds(proc_thresholds)?;
        Ok(self)
    }

    pub fn approver_set(&self) -> &ApproverSet {
        self.multisig.approver_set()
    }

    pub fn approvers(&self) -> &[Approver] {
        self.multisig.approvers()
    }

    pub fn default_threshold(&self) -> u32 {
        self.multisig.default_threshold()
    }

    pub fn proc_thresholds(&self) -> &[(AccountProcedureRoot, u32)] {
        self.multisig.proc_thresholds()
    }

    pub fn guardian_config(&self) -> GuardianConfig {
        self.guardian_config
    }

    fn into_parts(self) -> (AuthMultisigConfig, GuardianConfig) {
        (self.multisig, self.guardian_config)
    }
}

/// An [`AccountComponent`] implementing multisig authentication integrated with a state guardian.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure threshold overrides. When a guardian is configured, multisig authorization is
/// combined with guardian authorization, so operations require both multisig approval and a valid
/// guardian signature. This substantially mitigates low-threshold state-withholding scenarios
/// since the guardian is expected to forward state updates to other approvers.
#[derive(Debug)]
pub struct AuthGuardedMultisig {
    multisig: AuthMultisig,
    guardian_config: GuardianConfig,
}

impl AuthGuardedMultisig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::guarded_multisig";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &GUARDED_MULTISIG_CODE
    }

    /// Creates a new [`AuthGuardedMultisig`] component from the provided configuration.
    pub fn new(config: AuthGuardedMultisigConfig) -> Result<Self, AccountError> {
        let (multisig_config, guardian_config) = config.into_parts();
        Ok(Self {
            multisig: AuthMultisig::new(multisig_config)?,
            guardian_config,
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

    /// Returns the [`StorageSlotName`] where the guardian public key is stored.
    pub fn guardian_public_key_slot() -> &'static StorageSlotName {
        GuardianConfig::public_key_slot()
    }

    /// Returns the [`StorageSlotName`] where the guardian scheme IDs are stored.
    pub fn guardian_scheme_id_slot() -> &'static StorageSlotName {
        GuardianConfig::scheme_id_slot()
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

    /// Returns the storage slot schema for the guardian public key slot.
    pub fn guardian_public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        GuardianConfig::public_key_slot_schema()
    }

    /// Returns the storage slot schema for the guardian scheme IDs slot.
    pub fn guardian_auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        GuardianConfig::auth_scheme_slot_schema()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new([
            Self::threshold_config_slot_schema(),
            Self::approver_public_keys_slot_schema(),
            Self::approver_auth_scheme_slot_schema(),
            Self::executed_transactions_slot_schema(),
            Self::procedure_thresholds_slot_schema(),
            Self::guardian_public_key_slot_schema(),
            Self::guardian_auth_scheme_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Guarded multisig authentication component integrated \
                 with a state guardian using hybrid signature schemes",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthGuardedMultisig> for AccountComponent {
    fn from(multisig: AuthGuardedMultisig) -> Self {
        let AuthGuardedMultisig { multisig, guardian_config } = multisig;
        let multisig_component = AccountComponent::from(multisig);
        let (guardian_slots, guardian_slot_metadata) = guardian_config.into_component_parts();

        let mut storage_slots = multisig_component.storage_slots().to_vec();
        storage_slots.extend(guardian_slots);

        let mut slot_schemas: Vec<(StorageSlotName, StorageSlotSchema)> = multisig_component
            .storage_schema()
            .iter()
            .map(|(slot_name, slot_schema)| (slot_name.clone(), slot_schema.clone()))
            .collect();
        slot_schemas.extend(guardian_slot_metadata);

        let storage_schema =
            StorageSchema::new(slot_schemas).expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthGuardedMultisig::NAME)
            .with_description(multisig_component.metadata().description())
            .with_version(multisig_component.metadata().version().clone())
            .with_storage_schema(storage_schema);

        AccountComponent::new(AuthGuardedMultisig::code().clone(), storage_slots, metadata).expect(
            "Guarded multisig auth component should satisfy the requirements of a valid \
             account component",
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

    fn approver(key: &AuthSecretKey) -> Approver {
        Approver::new(key.public_key().to_commitment(), key.auth_scheme())
    }

    /// Test guarded multisig component setup with various configurations.
    #[test]
    fn test_guarded_multisig_component_setup() {
        // Create test secret keys
        let sec_key_1 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_2 = AuthSecretKey::new_falcon512_poseidon2();
        let sec_key_3 = AuthSecretKey::new_falcon512_poseidon2();
        let guardian_key = AuthSecretKey::new_ecdsa_k256_keccak();

        // Create approvers list for multisig config
        let approvers = vec![approver(&sec_key_1), approver(&sec_key_2), approver(&sec_key_3)];

        let threshold = 2u32;

        // Create guarded multisig component.
        let approver_set =
            ApproverSet::new(approvers.clone(), threshold).expect("invalid approver set");
        let multisig_component = AuthGuardedMultisig::new(
            AuthGuardedMultisigConfig::new(
                approver_set,
                GuardianConfig::new(approver(&guardian_key)),
            )
            .expect("invalid guarded multisig config"),
        )
        .expect("guarded multisig component creation failed");

        // Build account with guarded multisig component.
        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify config slot: [threshold, num_approvers, 0, 0]
        let config_slot = account
            .storage()
            .get_item(AuthGuardedMultisig::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        // Verify approver pub keys slot
        for (i, expected) in approvers.iter().enumerate() {
            let stored_pub_key = account
                .storage()
                .get_map_item(
                    AuthGuardedMultisig::approver_public_keys_slot(),
                    StorageMapKey::from_index(i as u32),
                )
                .expect("approver public key storage map access failed");
            assert_eq!(stored_pub_key, Word::from(expected.pub_key()));
        }

        // Verify approver scheme IDs slot
        for (i, expected) in approvers.iter().enumerate() {
            let stored_scheme_id = account
                .storage()
                .get_map_item(
                    AuthGuardedMultisig::approver_scheme_ids_slot(),
                    StorageMapKey::from_index(i as u32),
                )
                .expect("approver scheme ID storage map access failed");
            assert_eq!(stored_scheme_id, Word::from([expected.auth_scheme() as u32, 0, 0, 0]));
        }

        // Verify guardian signer is configured.
        let guardian_public_key = account
            .storage()
            .get_map_item(
                AuthGuardedMultisig::guardian_public_key_slot(),
                StorageMapKey::from_index(0),
            )
            .expect("guardian public key storage map access failed");
        assert_eq!(guardian_public_key, Word::from(guardian_key.public_key().to_commitment()));

        let guardian_scheme_id = account
            .storage()
            .get_map_item(
                AuthGuardedMultisig::guardian_scheme_id_slot(),
                StorageMapKey::from_index(0),
            )
            .expect("guardian scheme ID storage map access failed");
        assert_eq!(guardian_scheme_id, Word::from([guardian_key.auth_scheme() as u32, 0, 0, 0]));
    }

    /// Test guarded multisig component with minimum threshold (1 of 1).
    #[test]
    fn test_guarded_multisig_component_minimum_threshold() {
        let approver_key = AuthSecretKey::new_ecdsa_k256_keccak();
        let pub_key = approver_key.public_key().to_commitment();
        let guardian_key = AuthSecretKey::new_falcon512_poseidon2();
        let approvers = vec![approver(&approver_key)];
        let threshold = 1u32;

        let approver_set =
            ApproverSet::new(approvers.clone(), threshold).expect("invalid approver set");
        let multisig_component = AuthGuardedMultisig::new(
            AuthGuardedMultisigConfig::new(
                approver_set,
                GuardianConfig::new(approver(&guardian_key)),
            )
            .expect("invalid guarded multisig config"),
        )
        .expect("guarded multisig component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(multisig_component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Verify storage layout
        let config_slot = account
            .storage()
            .get_item(AuthGuardedMultisig::threshold_config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, Word::from([threshold, approvers.len() as u32, 0, 0]));

        let stored_pub_key = account
            .storage()
            .get_map_item(
                AuthGuardedMultisig::approver_public_keys_slot(),
                StorageMapKey::from_index(0),
            )
            .expect("approver pub keys storage map access failed");
        assert_eq!(stored_pub_key, Word::from(pub_key));

        let stored_scheme_id = account
            .storage()
            .get_map_item(
                AuthGuardedMultisig::approver_scheme_ids_slot(),
                StorageMapKey::from_index(0),
            )
            .expect("approver scheme IDs storage map access failed");
        assert_eq!(stored_scheme_id, Word::from([AuthScheme::EcdsaK256Keccak as u32, 0, 0, 0]));
    }

    /// Test guarded multisig component rejects a guardian key which is already an approver.
    #[test]
    fn test_guarded_multisig_component_guardian_not_approver() {
        let sec_key_1 = AuthSecretKey::new_ecdsa_k256_keccak();
        let sec_key_2 = AuthSecretKey::new_ecdsa_k256_keccak();

        let approvers = vec![approver(&sec_key_1), approver(&sec_key_2)];
        let approver_set = ApproverSet::new(approvers, 2).expect("invalid approver set");

        let result =
            AuthGuardedMultisigConfig::new(approver_set, GuardianConfig::new(approver(&sec_key_1)));

        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("guardian public key must be different from approvers")
        );
    }
}
