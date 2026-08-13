use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
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
use crate::account::{account_component_code, package_metadata};

account_component_code!(GUARDED_MULTISIG_CODE, "miden-standards-auth-guarded-multisig.masp");

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

    /// Returns the storage slots holding the guardian's public key and signature scheme.
    fn into_slots(self) -> Vec<StorageSlot> {
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

        storage_slots
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

    pub fn proc_thresholds(&self) -> &BTreeMap<AccountProcedureRoot, u32> {
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
///
/// # Privacy
///
/// Approvers and the guardian using [`AuthScheme::EcdsaK256Keccak`][scheme] disclose their public
/// key and signature at proving time and therefore do not get public-key privacy; those using
/// [`Falcon512Poseidon2`][falcon] do. See [`Approver`](super::Approver) for details.
///
/// [scheme]: miden_protocol::account::auth::AuthScheme::EcdsaK256Keccak
/// [falcon]: miden_protocol::account::auth::AuthScheme::Falcon512Poseidon2
#[derive(Debug)]
pub struct AuthGuardedMultisig {
    multisig: AuthMultisig,
    guardian_config: GuardianConfig,
}

impl AuthGuardedMultisig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::guarded_multisig";

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

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        package_metadata(Self::code())
    }
}

impl From<AuthGuardedMultisig> for AccountComponent {
    fn from(multisig: AuthGuardedMultisig) -> Self {
        let AuthGuardedMultisig { multisig, guardian_config } = multisig;
        let multisig_component = AccountComponent::from(multisig);

        let mut storage_slots = multisig_component.storage_slots().to_vec();
        storage_slots.extend(guardian_config.into_slots());

        let metadata = AuthGuardedMultisig::component_metadata();

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
            .with_component(multisig_component)
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
            .with_component(multisig_component)
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
