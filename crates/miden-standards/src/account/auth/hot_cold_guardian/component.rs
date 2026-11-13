use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
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
use miden_protocol::utils::sync::LazyLock;

// The executed-transactions slot is shared with the multisig components so the replay
// protection helper of the multisig MASM module can be reused.
use super::super::multisig::EXECUTED_TRANSACTIONS_SLOT_NAME;
use super::{AuthHotColdGuardianConfig, HotColdDelayConfig, HotColdPolicy};
use crate::account::account_component_package;
use crate::account::auth::{Approver, GuardianConfig};
use crate::procedure_root;

account_component_package!(
    HOT_COLD_GUARDIAN_PACKAGE,
    "miden-standards-auth-hot-cold-guardian.masp"
);

// PROCEDURE ROOTS
// ================================================================================================

/// MASL library namespace used for procedure-root lookups. Distinct from
/// [`AuthHotColdGuardian::NAME`], which mirrors the standards-side MASM module path.
const HOT_COLD_GUARDIAN_LIBRARY_PATH: &str =
    "miden::standards::components::auth::hot_cold_guardian";

procedure_root!(
    HOT_COLD_GUARDIAN_UPDATE_HOT_KEYS,
    HOT_COLD_GUARDIAN_LIBRARY_PATH,
    AuthHotColdGuardian::UPDATE_HOT_KEYS_PROC_NAME,
    AuthHotColdGuardian::code()
);

procedure_root!(
    HOT_COLD_GUARDIAN_ROTATE_COLD_KEY,
    HOT_COLD_GUARDIAN_LIBRARY_PATH,
    AuthHotColdGuardian::ROTATE_COLD_KEY_PROC_NAME,
    AuthHotColdGuardian::code()
);

procedure_root!(
    HOT_COLD_GUARDIAN_UPDATE_GUARDIAN_PUBLIC_KEY,
    HOT_COLD_GUARDIAN_LIBRARY_PATH,
    AuthHotColdGuardian::UPDATE_GUARDIAN_PUBLIC_KEY_PROC_NAME,
    AuthHotColdGuardian::code()
);

procedure_root!(
    HOT_COLD_GUARDIAN_SET_PROCEDURE_POLICY,
    HOT_COLD_GUARDIAN_LIBRARY_PATH,
    AuthHotColdGuardian::SET_PROCEDURE_POLICY_PROC_NAME,
    AuthHotColdGuardian::code()
);

procedure_root!(
    HOT_COLD_GUARDIAN_UPDATE_DELAY_CONFIG,
    HOT_COLD_GUARDIAN_LIBRARY_PATH,
    AuthHotColdGuardian::UPDATE_DELAY_CONFIG_PROC_NAME,
    AuthHotColdGuardian::code()
);

// CONSTANTS
// ================================================================================================

static CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::config")
        .expect("storage slot name should be valid")
});

static HOT_PUBLIC_KEYS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::hot_public_keys")
        .expect("storage slot name should be valid")
});

static HOT_SCHEME_IDS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::hot_scheme_ids")
        .expect("storage slot name should be valid")
});

static COLD_PUBLIC_KEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::cold_public_key")
        .expect("storage slot name should be valid")
});

static COLD_SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::cold_scheme_id")
        .expect("storage slot name should be valid")
});

static PROCEDURE_POLICIES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::procedure_policies")
        .expect("storage slot name should be valid")
});

static DELAY_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::hot_cold_guardian::delay_config")
        .expect("storage slot name should be valid")
});

// HOT/COLD/GUARDIAN AUTHENTICATION COMPONENT
// ================================================================================================

/// An [`AccountComponent`] implementing authentication with three key categories.
///
/// - Hot keys: one key per device. Any one of them satisfies the hot category; several hot
///   signatures never count more than one.
/// - Cold key: a single offline key, the most trusted one. Replacing the hot keys requires it.
/// - Guardian key: co-signs every transaction. It provides data availability for private accounts
///   and can enforce off-chain rules, but holds no authority of its own.
///
/// Procedure policies ([`HotColdPolicy`]) count signed categories. A procedure without a policy
/// costs the default of one category plus the guardian. The component code presets policies for
/// its own procedures, see [`AuthHotColdGuardian::preset_policies`]:
///
/// - replacing the hot keys requires the cold category (cold + guardian),
/// - rotating the cold key, rotating the guardian and changing policies or the delay configuration
///   require both categories (hot + cold + guardian).
///
/// A transaction with a pending code upgrade requires both categories too, whichever procedure
/// initiated the upgrade, since the new code replaces the code that enforces the policies.
///
/// Delayed execution (proposing an action with the hot category and executing it after the
/// configured delay unless the cold key cancels it) is not part of this component yet; its delay
/// configuration is stored so adding it needs no storage change.
///
/// # Auth args
///
/// The transaction's auth args are the commitment to
/// [`MultisigAuthArgs`](crate::account::auth::MultisigAuthArgs).
///
/// # Fees
///
/// The transaction fee is paid as described for [`AuthMultisig`](super::super::AuthMultisig),
/// counting the hot keys, the cold key and the guardian as signers.
///
/// # Privacy
///
/// Keys using [`AuthScheme::EcdsaK256Keccak`][scheme] disclose their public key and signature at
/// proving time and therefore do not get public-key privacy; those using
/// [`Falcon512Eidos`][falcon] do. See [`Approver`] for details.
///
/// [scheme]: miden_protocol::account::auth::AuthScheme::EcdsaK256Keccak
/// [falcon]: miden_protocol::account::auth::AuthScheme::Falcon512Eidos
#[derive(Debug)]
pub struct AuthHotColdGuardian {
    config: AuthHotColdGuardianConfig,
}

impl AuthHotColdGuardian {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::hot_cold_guardian";

    /// The name of the procedure that replaces the hot key set.
    pub const UPDATE_HOT_KEYS_PROC_NAME: &'static str = "update_hot_keys";

    /// The name of the procedure that replaces the cold key.
    pub const ROTATE_COLD_KEY_PROC_NAME: &'static str = "rotate_cold_key";

    /// The name of the procedure that replaces the guardian key.
    pub const UPDATE_GUARDIAN_PUBLIC_KEY_PROC_NAME: &'static str = "update_guardian_public_key";

    /// The name of the procedure that edits per-procedure policies.
    pub const SET_PROCEDURE_POLICY_PROC_NAME: &'static str = "set_procedure_policy";

    /// The name of the procedure that edits the delay configuration.
    pub const UPDATE_DELAY_CONFIG_PROC_NAME: &'static str = "update_delay_config";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &HOT_COLD_GUARDIAN_PACKAGE.code
    }

    /// Creates a new [`AuthHotColdGuardian`] component from the provided configuration.
    pub fn new(config: AuthHotColdGuardianConfig) -> Self {
        Self { config }
    }

    /// Returns the preset policies of the component's own procedures. They are built into the
    /// component code and apply to a procedure while it has no stored policy, however the account
    /// was created. A configured or stored policy for the same procedure replaces the preset.
    ///
    /// - `update_hot_keys`: cold only. Device management is immediate for the cold key and closed
    ///   to the hot keys.
    /// - `rotate_cold_key`, `update_guardian_public_key`, `set_procedure_policy`,
    ///   `update_delay_config`: hot and cold. Rewriting any of them weakens what the other policies
    ///   protect, so they take the strongest quorum.
    pub fn preset_policies() -> BTreeMap<AccountProcedureRoot, HotColdPolicy> {
        BTreeMap::from([
            (Self::update_hot_keys_root(), HotColdPolicy::ColdOnly),
            (Self::rotate_cold_key_root(), HotColdPolicy::HotAndCold),
            (Self::update_guardian_public_key_root(), HotColdPolicy::HotAndCold),
            (Self::set_procedure_policy_root(), HotColdPolicy::HotAndCold),
            (Self::update_delay_config_root(), HotColdPolicy::HotAndCold),
        ])
    }

    /// Returns the configured hot keys.
    pub fn hot_keys(&self) -> &[Approver] {
        self.config.hot_keys()
    }

    /// Returns the configured cold key.
    pub fn cold_key(&self) -> Approver {
        self.config.cold_key()
    }

    /// Returns the configured guardian.
    pub fn guardian_config(&self) -> GuardianConfig {
        self.config.guardian_config()
    }

    /// Returns the configured delay configuration.
    pub fn delay_config(&self) -> HotColdDelayConfig {
        self.config.delay_config()
    }

    /// Returns the user-provided per-procedure policies, without the preset ones.
    pub fn procedure_policies(&self) -> &BTreeMap<AccountProcedureRoot, HotColdPolicy> {
        self.config.procedure_policies()
    }

    /// Returns the [`AccountProcedureRoot`] of the `update_hot_keys` procedure.
    pub fn update_hot_keys_root() -> AccountProcedureRoot {
        *HOT_COLD_GUARDIAN_UPDATE_HOT_KEYS
    }

    /// Returns the [`AccountProcedureRoot`] of the `rotate_cold_key` procedure.
    pub fn rotate_cold_key_root() -> AccountProcedureRoot {
        *HOT_COLD_GUARDIAN_ROTATE_COLD_KEY
    }

    /// Returns the [`AccountProcedureRoot`] of the `update_guardian_public_key` procedure.
    pub fn update_guardian_public_key_root() -> AccountProcedureRoot {
        *HOT_COLD_GUARDIAN_UPDATE_GUARDIAN_PUBLIC_KEY
    }

    /// Returns the [`AccountProcedureRoot`] of the `set_procedure_policy` procedure.
    pub fn set_procedure_policy_root() -> AccountProcedureRoot {
        *HOT_COLD_GUARDIAN_SET_PROCEDURE_POLICY
    }

    /// Returns the [`AccountProcedureRoot`] of the `update_delay_config` procedure.
    pub fn update_delay_config_root() -> AccountProcedureRoot {
        *HOT_COLD_GUARDIAN_UPDATE_DELAY_CONFIG
    }

    /// Returns the [`StorageSlotName`] holding `[num_hot_keys, 0, 0, 0]`.
    pub fn config_slot() -> &'static StorageSlotName {
        &CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the hot public key map.
    pub fn hot_public_keys_slot() -> &'static StorageSlotName {
        &HOT_PUBLIC_KEYS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the hot scheme id map.
    pub fn hot_scheme_ids_slot() -> &'static StorageSlotName {
        &HOT_SCHEME_IDS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the single-entry cold public key map.
    pub fn cold_public_key_slot() -> &'static StorageSlotName {
        &COLD_PUBLIC_KEY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the single-entry cold scheme id map.
    pub fn cold_scheme_id_slot() -> &'static StorageSlotName {
        &COLD_SCHEME_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the executed transactions map.
    pub fn executed_transactions_slot() -> &'static StorageSlotName {
        &EXECUTED_TRANSACTIONS_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the procedure policy map.
    pub fn procedure_policies_slot() -> &'static StorageSlotName {
        &PROCEDURE_POLICIES_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] holding the delay configuration.
    pub fn delay_config_slot() -> &'static StorageSlotName {
        &DELAY_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the guardian public key map.
    pub fn guardian_public_key_slot() -> &'static StorageSlotName {
        GuardianConfig::public_key_slot()
    }

    /// Returns the [`StorageSlotName`] of the guardian scheme id map.
    pub fn guardian_scheme_id_slot() -> &'static StorageSlotName {
        GuardianConfig::scheme_id_slot()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        HOT_COLD_GUARDIAN_PACKAGE.metadata.clone()
    }
}

impl From<AuthHotColdGuardian> for AccountComponent {
    fn from(component: AuthHotColdGuardian) -> Self {
        let config = component.config;
        let mut storage_slots = Vec::with_capacity(10);

        // Config slot (value: [num_hot_keys, 0, 0, 0])
        storage_slots.push(StorageSlot::with_value(
            AuthHotColdGuardian::config_slot().clone(),
            Word::from([config.hot_keys().len() as u32, 0, 0, 0]),
        ));

        // Hot public keys slot (map)
        let hot_public_key_entries = config.hot_keys().iter().enumerate().map(|(i, approver)| {
            (StorageMapKey::from_index(i as u32), Word::from(approver.pub_key()))
        });
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::hot_public_keys_slot().clone(),
            StorageMap::with_entries(hot_public_key_entries).unwrap(),
        ));

        // Hot scheme IDs slot (map)
        let hot_scheme_id_entries = config.hot_keys().iter().enumerate().map(|(i, approver)| {
            (
                StorageMapKey::from_index(i as u32),
                Word::from([approver.auth_scheme() as u32, 0, 0, 0]),
            )
        });
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::hot_scheme_ids_slot().clone(),
            StorageMap::with_entries(hot_scheme_id_entries).unwrap(),
        ));

        // Cold key slots (single-entry maps keyed by [0, 0, 0, 0], like the guardian's)
        let category_map_key = StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0]));
        let cold_key = config.cold_key();
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::cold_public_key_slot().clone(),
            StorageMap::with_entries([(category_map_key, Word::from(cold_key.pub_key()))]).unwrap(),
        ));
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::cold_scheme_id_slot().clone(),
            StorageMap::with_entries([(
                category_map_key,
                Word::from([cold_key.auth_scheme() as u32, 0, 0, 0]),
            )])
            .unwrap(),
        ));

        // Executed transactions slot (map)
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::executed_transactions_slot().clone(),
            StorageMap::default(),
        ));

        // Procedure policies slot (map): the configured policies only. The presets are built into
        // the component code and apply to procedures without a stored policy.
        let procedure_policies = StorageMap::with_entries(config.procedure_policies().iter().map(
            |(proc_root, policy)| (StorageMapKey::from_raw(proc_root.as_word()), policy.to_word()),
        ))
        .expect("the policy roots are unique");
        storage_slots.push(StorageSlot::with_map(
            AuthHotColdGuardian::procedure_policies_slot().clone(),
            procedure_policies,
        ));

        // Delay config slot (value: [min_delay, propose_expiration_delta, cancel_threshold, 0])
        let delay_config = config.delay_config();
        storage_slots.push(StorageSlot::with_value(
            AuthHotColdGuardian::delay_config_slot().clone(),
            Word::from([
                delay_config.min_delay(),
                delay_config.propose_expiration_delta() as u32,
                delay_config.cancel_threshold(),
                0u32,
            ]),
        ));

        // Guardian slots
        storage_slots.extend(config.guardian_config().into_slots());

        let metadata = AuthHotColdGuardian::component_metadata();

        AccountComponent::new(AuthHotColdGuardian::code().clone(), storage_slots, metadata).expect(
            "hot/cold/guardian auth component should satisfy the requirements of a valid account \
             component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_protocol::account::AccountBuilder;
    use miden_protocol::account::auth::AuthSecretKey;

    use super::*;
    use crate::account::wallets::BasicWallet;

    fn approver() -> Approver {
        let key = AuthSecretKey::new_ecdsa_k256_keccak();
        Approver::new(key.public_key().to_commitment(), key.auth_scheme())
    }

    fn config() -> AuthHotColdGuardianConfig {
        AuthHotColdGuardianConfig::new(
            vec![approver(), approver()],
            approver(),
            GuardianConfig::new(approver()),
            HotColdDelayConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn test_hot_cold_guardian_component_setup() {
        let config = config();
        let hot_keys = config.hot_keys().to_vec();
        let cold_key = config.cold_key();
        let guardian = config.guardian_config();
        let config = config.with_proc_policies(BTreeMap::from([(
            BasicWallet::receive_asset_root(),
            HotColdPolicy::HotAndCold,
        )]));

        let component = AuthHotColdGuardian::new(config);
        let account = AccountBuilder::new([0; 32])
            .with_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");
        let storage = account.storage();

        assert_eq!(
            storage.get_item(AuthHotColdGuardian::config_slot()).unwrap(),
            Word::from([2u32, 0, 0, 0])
        );

        for (i, hot_key) in hot_keys.iter().enumerate() {
            let key = StorageMapKey::from_index(i as u32);
            assert_eq!(
                storage.get_map_item(AuthHotColdGuardian::hot_public_keys_slot(), key).unwrap(),
                Word::from(hot_key.pub_key())
            );
            assert_eq!(
                storage.get_map_item(AuthHotColdGuardian::hot_scheme_ids_slot(), key).unwrap(),
                Word::from([hot_key.auth_scheme() as u32, 0, 0, 0])
            );
        }

        let category_key = StorageMapKey::from_raw(Word::from([0u32, 0, 0, 0]));
        assert_eq!(
            storage
                .get_map_item(AuthHotColdGuardian::cold_public_key_slot(), category_key)
                .unwrap(),
            Word::from(cold_key.pub_key())
        );
        assert_eq!(
            storage
                .get_map_item(AuthHotColdGuardian::cold_scheme_id_slot(), category_key)
                .unwrap(),
            Word::from([cold_key.auth_scheme() as u32, 0, 0, 0])
        );
        assert_eq!(
            storage
                .get_map_item(AuthHotColdGuardian::guardian_public_key_slot(), category_key)
                .unwrap(),
            Word::from(guardian.pub_key())
        );

        let policy_word = |root: AccountProcedureRoot| {
            storage
                .get_map_item(
                    AuthHotColdGuardian::procedure_policies_slot(),
                    StorageMapKey::from_raw(root.as_word()),
                )
                .unwrap()
        };
        assert_eq!(policy_word(BasicWallet::receive_asset_root()), Word::from([2u32, 0, 0, 0]));
        // the presets are built into the component code, so they are not stored
        for preset_root in AuthHotColdGuardian::preset_policies().keys() {
            assert_eq!(policy_word(*preset_root), Word::empty());
        }

        let delay = HotColdDelayConfig::default();
        assert_eq!(
            storage.get_item(AuthHotColdGuardian::delay_config_slot()).unwrap(),
            Word::from([
                delay.min_delay(),
                delay.propose_expiration_delta() as u32,
                delay.cancel_threshold(),
                0u32
            ])
        );
    }

    #[test]
    fn test_hot_cold_guardian_configured_policy_replaces_preset() {
        let config = config().with_proc_policies(BTreeMap::from([(
            AuthHotColdGuardian::update_hot_keys_root(),
            HotColdPolicy::HotAndCold,
        )]));

        let account = AccountBuilder::new([0; 32])
            .with_component(AuthHotColdGuardian::new(config))
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        assert_eq!(
            account
                .storage()
                .get_map_item(
                    AuthHotColdGuardian::procedure_policies_slot(),
                    StorageMapKey::from_raw(AuthHotColdGuardian::update_hot_keys_root().as_word()),
                )
                .unwrap(),
            HotColdPolicy::HotAndCold.to_word()
        );
    }
}
