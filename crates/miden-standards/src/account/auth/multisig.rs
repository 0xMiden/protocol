use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::component::{
    AccountComponentCode, AccountComponentMetadata, FeltSchema, SchemaType, StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent, AccountComponentName, AccountProcedureRoot, StorageMap, StorageMapKey,
    StorageSlot, StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

use super::{Approver, ApproverSet};
use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(MULTISIG_CODE, "miden-standards-auth-multisig.masp");

// Initialize the procedure root of the `set_procedure_threshold` procedure only once. It gates
// edits to per-procedure overrides, so [`AuthMultisig::new`] uses it to reject overrides that
// exceed its own threshold.
procedure_root!(
    MULTISIG_SET_PROCEDURE_THRESHOLD,
    AuthMultisig::NAME,
    AuthMultisig::SET_PROCEDURE_THRESHOLD_PROC_NAME,
    AuthMultisig::code()
);

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
    proc_thresholds: BTreeMap<AccountProcedureRoot, u32>,
}

impl AuthMultisigConfig {
    /// Creates a new configuration from the given approver set.
    pub fn new(approver_set: ApproverSet) -> Self {
        Self {
            approver_set,
            proc_thresholds: BTreeMap::new(),
        }
    }

    /// Attaches a per-procedure threshold map. Each procedure threshold must be at least 1 and
    /// at most the number of approvers.
    pub fn with_proc_thresholds(
        mut self,
        proc_thresholds: Vec<(AccountProcedureRoot, u32)>,
    ) -> Result<Self, AccountError> {
        let num_approvers = self.approver_set.approvers().len() as u32;
        let mut thresholds = BTreeMap::new();
        for (proc_root, threshold) in proc_thresholds {
            if threshold == 0 {
                return Err(AccountError::other("procedure threshold must be at least 1"));
            }
            if threshold > num_approvers {
                return Err(AccountError::other(
                    "procedure threshold cannot be greater than number of approvers",
                ));
            }
            // The map keys the threshold by procedure root, so a repeated root is a caller mistake
            // rather than a silent overwrite.
            if thresholds.insert(proc_root, threshold).is_some() {
                return Err(AccountError::other(
                    "duplicate procedure roots are not allowed in the procedure threshold map",
                ));
            }
        }
        self.proc_thresholds = thresholds;
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

    pub fn proc_thresholds(&self) -> &BTreeMap<AccountProcedureRoot, u32> {
        &self.proc_thresholds
    }
}

/// An [`AccountComponent`] implementing a multisig authentication.
///
/// It enforces a threshold of approver signatures for every transaction, with optional
/// per-procedure threshold overrides.
///
/// # Privacy
///
/// Approvers using [`AuthScheme::EcdsaK256Keccak`][scheme] disclose their public key and signature
/// at proving time and therefore do not get public-key privacy; approvers using
/// [`Falcon512Poseidon2`][falcon] do. See [`Approver`](super::Approver) for details.
///
/// [scheme]: miden_protocol::account::auth::AuthScheme::EcdsaK256Keccak
/// [falcon]: miden_protocol::account::auth::AuthScheme::Falcon512Poseidon2
///
/// # Security: private accounts and state withholding
///
/// A private account's state lives off-chain; the chain only holds a commitment to it. Whoever
/// advances the account must share the new state with the other approvers, otherwise those
/// approvers can no longer reconstruct the state behind the on-chain commitment and are
/// permanently locked out (and the signers retaining the state can drain its assets). This is a
/// data-availability problem inherent to private state, not an authorization one: the threshold
/// controls who *can* advance the state, not whether the resulting state is *shared*. A
/// per-procedure threshold of one lets a single approver do this; more generally, any quorum
/// smaller than the full approver set can advance the state and withhold it from the excluded
/// approvers.
///
/// The only configurations that fully prevent withholding are a public account (state is on-chain,
/// so nothing can be withheld), unanimity (`threshold == number of approvers`, so every approver
/// signs and therefore sees every state transition), or pairing the multisig with a guardian via
/// [`AuthGuardedMultisig`](super::AuthGuardedMultisig), whose guardian co-signs every transaction
/// and forwards the new state. For a private `m`-of-`n` wallet among mutually distrusting
/// approvers, prefer the guarded variant. The [`create_multisig_wallet`] helper enforces a related
/// bound: on private accounts it rejects per-procedure thresholds below the default.
///
/// [`create_multisig_wallet`]: crate::account::wallets::create_multisig_wallet
///
/// # Security: growing the signer set does not re-scale overrides
///
/// Per-procedure threshold overrides are absolute signature counts, not ratios. Updating the signer
/// set (via the `update_signers_and_threshold` account procedure) does not re-scale existing
/// overrides: the only cross-check is that each override stays `<= num_approvers`, which keeps it
/// reachable but never raises it. Growing the approver set therefore silently lowers the effective
/// signing ratio of every override (e.g. a `2`-of-`2` override becomes `2`-of-`n`). To preserve the
/// intended security level, re-evaluate the affected overrides and, where appropriate, raise them
/// via `set_procedure_threshold` in the same transaction that grows the signer set.
///
/// # Security: a raised override is only as strong as the threshold of `set_procedure_threshold`
///
/// An override can demand *more* signatures for a sensitive operation than the default, but that
/// extra protection is only as strong as the threshold guarding the procedure that can lower it,
/// `set_procedure_threshold`. That guard is `set_procedure_threshold`'s own override if one is set,
/// otherwise the default threshold; it is *not* necessarily the default. A group meeting that guard
/// can strip a stronger override in two transactions: first they lower it, then, in a later
/// transaction, they run the now-cheaper operation. Two transactions are required because the
/// signatures needed are read from the state as of the start of the transaction, so a lowered
/// override only takes effect in the next one.
///
/// For example, with 5 signers, a default of 2, `set_procedure_threshold` left at the default, and
/// a transfer requiring 4: two signers cannot transfer directly, but they can lower the transfer's
/// override to 2 in one transaction and transfer in the next.
///
/// It follows that setting an override higher than the threshold of `set_procedure_threshold`
/// (which may be the default) is pointless, because the excess signatures can always be removed by
/// that smaller group. To make a raised override hold, raise `set_procedure_threshold`'s own
/// threshold to at least that value, so undoing the protection costs as many signatures as the
/// operation it guards. [`AuthMultisig::new`] enforces this by rejecting any configuration whose
/// override exceeds the threshold of `set_procedure_threshold`. Note that
/// `update_signers_and_threshold` can also weaken an override by growing the signer set (see
/// above), so protect it the same way where relevant.
#[derive(Debug)]
pub struct AuthMultisig {
    config: AuthMultisigConfig,
}

impl AuthMultisig {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::multisig";

    /// The name of the procedure that edits per-procedure threshold overrides.
    const SET_PROCEDURE_THRESHOLD_PROC_NAME: &'static str = "set_procedure_threshold";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &MULTISIG_CODE
    }

    /// Returns the procedure root of the `set_procedure_threshold` account procedure.
    pub fn set_procedure_threshold_root() -> AccountProcedureRoot {
        *MULTISIG_SET_PROCEDURE_THRESHOLD
    }

    /// Creates a new [`AuthMultisig`] component from the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if a per-procedure override exceeds the threshold that guards
    /// `set_procedure_threshold` (its own override if set, otherwise the default threshold). Such
    /// an override is not enforceable, since a group meeting that lower threshold can strip it
    /// via `set_procedure_threshold`; see the type-level security notes.
    pub fn new(config: AuthMultisigConfig) -> Result<Self, AccountError> {
        // The threshold that must be met to edit overrides via `set_procedure_threshold`: its own
        // override if configured, otherwise the default threshold.
        let setter_threshold = config
            .proc_thresholds()
            .get(&Self::set_procedure_threshold_root())
            .copied()
            .unwrap_or_else(|| config.default_threshold());

        for &threshold in config.proc_thresholds().values() {
            if threshold > setter_threshold {
                return Err(AccountError::other(format!(
                    "per-procedure threshold override of {threshold} exceeds the threshold of \
                     {setter_threshold} that guards set_procedure_threshold; such an override can \
                     be removed by a smaller quorum. Raise the set_procedure_threshold override to \
                     at least {threshold} to make it enforceable"
                )));
            }
        }

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

    /// Test that an override exceeding the threshold guarding `set_procedure_threshold` (here the
    /// default, since it has no override of its own) is rejected by `AuthMultisig::new`, because a
    /// smaller quorum could lower it.
    #[test]
    fn test_proc_threshold_above_set_procedure_threshold_rejected() {
        let approvers = vec![
            Approver::new(
                AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment(),
                auth::AuthScheme::EcdsaK256Keccak,
            ),
            Approver::new(
                AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment(),
                auth::AuthScheme::EcdsaK256Keccak,
            ),
            Approver::new(
                AuthSecretKey::new_ecdsa_k256_keccak().public_key().to_commitment(),
                auth::AuthScheme::EcdsaK256Keccak,
            ),
        ];
        let approver_set = ApproverSet::new(approvers, 2).expect("invalid approver set");

        // The override (3) is within num_approvers, so `with_proc_thresholds` accepts it, but it
        // exceeds the default threshold (2) that guards `set_procedure_threshold`.
        let config = AuthMultisigConfig::new(approver_set)
            .with_proc_thresholds(vec![(BasicWallet::receive_asset_root(), 3)])
            .expect("an override within num_approvers is accepted by with_proc_thresholds");

        let err = AuthMultisig::new(config).unwrap_err();
        assert!(err.to_string().contains("exceeds the threshold"));
    }
}
