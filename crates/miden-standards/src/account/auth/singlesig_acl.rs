use alloc::collections::BTreeSet;
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
    AccountCode,
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

use crate::account::account_component_code;

account_component_code!(SINGLESIG_ACL_CODE, "auth/singlesig_acl.masl");

// CONSTANTS
// ================================================================================================

static PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::pub_key")
        .expect("storage slot name should be valid")
});

static SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::scheme")
        .expect("storage slot name should be valid")
});

static EXEMPT_PROCEDURE_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::exempt_procedure_roots")
        .expect("storage slot name should be valid")
});

/// Configuration for [`AuthSingleSigAcl`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSingleSigAclConfig {
    /// List of procedure roots that are exempt from requiring authentication when called.
    /// Any called procedure that is not on this list forces signature verification.
    pub exempt_procedures: Vec<AccountProcedureRoot>,
}

impl AuthSingleSigAclConfig {
    /// Creates a new configuration with an empty exempt list. Under this default, every
    /// account procedure call requires authentication.
    pub fn new() -> Self {
        Self { exempt_procedures: vec![] }
    }

    /// Sets the list of procedure roots that are exempt from requiring authentication.
    ///
    /// See [`AuthSingleSigAcl`] for the full semantics. In particular, condition 2 (the
    /// input-note check) is transaction-wide: exempting any kernel-detected procedure (even
    /// a benign read-only getter) also relaxes the input-note signature requirement for
    /// every input note consumed in the same transaction.
    pub fn with_exempt_procedures(mut self, procedures: Vec<AccountProcedureRoot>) -> Self {
        self.exempt_procedures = procedures;
        self
    }
}

impl Default for AuthSingleSigAclConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`AccountComponent`] implementing a procedure-based Access Control List (ACL) using either
/// the EcdsaK256Keccak or Falcon512 Poseidon2 signature scheme for authentication of transactions.
///
/// This component uses *exempt-list* ACL semantics: every called account procedure requires
/// authentication by default, and only procedures explicitly listed in
/// [`AuthSingleSigAclConfig::exempt_procedures`] are permitted to execute without a signature.
/// This makes the safe path the default - newly added setters cannot silently become
/// permissionless by being forgotten in the configuration.
///
/// ## Authentication Logic
///
/// Authentication is required if any of the following hold:
///
/// 1. A kernel-detected procedure not on the exempt list was called (other than the auth procedure
///    at index 0).
/// 2. An input note was consumed AND no procedure was detected as called anywhere in the
///    transaction. Combined with condition 1, which already catches the non-exempt-called case, the
///    practical effect is that input-note consumption requires authentication unless at least one
///    exempt procedure was detected as called. The most easily missed case this rule covers is a
///    transaction that consumes notes but invokes no account procedure at all.
/// 3. Any output note was created. This is unconditional (see the note-detection caveat below).
///
/// The vouching in condition 2 is transaction-wide, not per-note: a single detected procedure
/// call (even an exempt read-only getter) lifts the input-note signature requirement for
/// every input note in the same transaction. Asset exfiltration is still blocked by
/// condition 3, but exempting a detected procedure implicitly relaxes the input-note
/// signature requirement for any consumption happening alongside it. Authors should only
/// exempt procedures whose semantics they are happy to extend to "this procedure may run
/// unsigned AND any input notes may be consumed unsigned in the same transaction".
///
/// When none of these hold, only the nonce is conditionally incremented (when the account state
/// changed or the account is new) without verifying a signature.
///
/// Because the auth procedure runs *after* the rest of the transaction, the exempt list is
/// consulted against `was_procedure_called` results captured during execution.
///
/// ## Storage Layout
/// - [`Self::public_key_slot`]: Public key
/// - [`Self::scheme_id_slot`]: Signature scheme id
/// - [`Self::exempt_procedure_roots_slot`]: A map `PROC_ROOT => [1, 0, 0, 0]` whose presence marks
///   the procedure as exempt from signature verification.
///
/// ## Important Note on Procedure Detection
/// Procedure detection relies on the `was_procedure_called` kernel function, which only returns
/// `true` if the procedure invoked an account-restricted kernel API (vault add/remove, storage
/// write, storage read via `account::get_item`, etc.). Procedures that only touch unrestricted
/// APIs - for example, creating output notes via `output_note_create` without also moving assets
/// through the vault - are *not* flagged by this mechanism even when they execute. The explicit
/// output-note gate in condition 3 and the input-note check in condition 2 exist
/// specifically to close this gap, so that an unflagged side-effecting procedure cannot make
/// the account emit notes or process note consumptions without a signature.
///
/// Practical consequence for exempt-list authoring: a procedure that does not touch any
/// account-restricted kernel API will not be observed as called even if it is in the exempt
/// list, so listing it is a no-op (and consuming a note via such a procedure still trips
/// condition 2). When in doubt, prefer to exempt only procedures whose detection you can
/// verify in tests.
pub struct AuthSingleSigAcl {
    pub_key: PublicKeyCommitment,
    auth_scheme: AuthScheme,
    config: AuthSingleSigAclConfig,
}

impl AuthSingleSigAcl {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::auth::singlesig_acl";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &SINGLESIG_ACL_CODE
    }

    /// Creates a new [`AuthSingleSigAcl`] component with the given `public_key` and
    /// configuration.
    ///
    /// Returns an error if more than [`AccountCode::MAX_NUM_PROCEDURES`] procedures are
    /// specified, or if `config.exempt_procedures` contains duplicate procedure roots
    /// (since procedure roots are used as storage map keys).
    pub fn new(
        pub_key: PublicKeyCommitment,
        auth_scheme: AuthScheme,
        config: AuthSingleSigAclConfig,
    ) -> Result<Self, AccountError> {
        let max_procedures = AccountCode::MAX_NUM_PROCEDURES;
        if config.exempt_procedures.len() > max_procedures {
            return Err(AccountError::other(format!(
                "Cannot track more than {max_procedures} procedures (account limit)"
            )));
        }

        let unique_roots: BTreeSet<_> =
            config.exempt_procedures.iter().map(|p| p.as_word()).collect();
        if unique_roots.len() != config.exempt_procedures.len() {
            return Err(AccountError::other(
                "exempt_procedures contains duplicate procedure roots",
            ));
        }

        Ok(Self { pub_key, auth_scheme, config })
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &PUBKEY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the scheme ID is stored.
    pub fn scheme_id_slot() -> &'static StorageSlotName {
        &SCHEME_ID_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the exempt procedure roots are stored.
    pub fn exempt_procedure_roots_slot() -> &'static StorageSlotName {
        &EXEMPT_PROCEDURE_ROOTS_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", SchemaType::pub_key()),
        )
    }

    /// Returns the storage slot schema for the scheme ID slot.
    pub fn auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::scheme_id_slot().clone(),
            StorageSlotSchema::value("Scheme ID", SchemaType::auth_scheme()),
        )
    }

    /// Returns the storage slot schema for the exempt procedure roots slot.
    pub fn exempt_procedure_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::exempt_procedure_roots_slot().clone(),
            StorageSlotSchema::map(
                "Exempt procedure roots",
                SchemaType::native_word(),
                SchemaType::u32(),
            ),
        )
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            Self::public_key_slot_schema(),
            Self::auth_scheme_slot_schema(),
            Self::exempt_procedure_roots_slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Authentication component with exempt-list ACL using ECDSA K256 Keccak or Falcon512 Poseidon2 signature scheme",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthSingleSigAcl> for AccountComponent {
    fn from(singlesig_acl: AuthSingleSigAcl) -> Self {
        let mut storage_slots = Vec::with_capacity(3);

        // Public key slot
        storage_slots.push(StorageSlot::with_value(
            AuthSingleSigAcl::public_key_slot().clone(),
            singlesig_acl.pub_key.into(),
        ));

        // Scheme ID slot
        storage_slots.push(StorageSlot::with_value(
            AuthSingleSigAcl::scheme_id_slot().clone(),
            Word::from([singlesig_acl.auth_scheme.as_u8(), 0, 0, 0]),
        ));

        // Exempt procedure roots slot (map: PROC_ROOT -> [1, 0, 0, 0] presence marker).
        // We add the map even if there are no exempt procedures, to always maintain the same
        // storage layout.
        let map_entries = singlesig_acl.config.exempt_procedures.iter().map(|proc_root| {
            (StorageMapKey::from_raw(proc_root.as_word()), Word::from([1u32, 0, 0, 0]))
        });

        // Uniqueness of procedure roots is validated in `AuthSingleSigAcl::new`, so
        // `with_entries` cannot return `DuplicateKey` here.
        storage_slots.push(StorageSlot::with_map(
            AuthSingleSigAcl::exempt_procedure_roots_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        let metadata = AuthSingleSigAcl::component_metadata();

        AccountComponent::new(AuthSingleSigAcl::code().clone(), storage_slots, metadata).expect(
            "singlesig ACL component should satisfy the requirements of a valid account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;

    use super::*;
    use crate::account::components::StandardAccountComponent;
    use crate::account::wallets::BasicWallet;

    /// Helper that returns the two callable procedures of [`BasicWallet`].
    fn get_basic_wallet_procedures() -> Vec<AccountProcedureRoot> {
        let procedures: Vec<AccountProcedureRoot> =
            StandardAccountComponent::BasicWallet.procedure_roots().collect();
        assert_eq!(procedures.len(), 2);
        procedures
    }

    fn build_account(
        exempt_procedures: Vec<AccountProcedureRoot>,
    ) -> (PublicKeyCommitment, miden_protocol::account::Account) {
        let public_key = PublicKeyCommitment::from(Word::empty());
        let auth_scheme = AuthScheme::Falcon512Poseidon2;

        let acl_config = AuthSingleSigAclConfig::new().with_exempt_procedures(exempt_procedures);

        let component = AuthSingleSigAcl::new(public_key, auth_scheme, acl_config)
            .expect("component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        (public_key, account)
    }

    /// Empty exempt list: the public key is stored and the exempt map returns the empty word
    /// for every probed key.
    #[test]
    fn test_singlesig_acl_empty_exempt_list() {
        let (public_key, account) = build_account(vec![]);

        let public_key_slot = account
            .storage()
            .get_item(AuthSingleSigAcl::public_key_slot())
            .expect("public key storage slot access failed");
        assert_eq!(public_key_slot, public_key.into());

        // Probe an arbitrary key: the empty list means every lookup returns Word::empty().
        let probe = account
            .storage()
            .get_map_item(AuthSingleSigAcl::exempt_procedure_roots_slot(), Word::empty())
            .expect("storage map access failed");
        assert_eq!(probe, Word::empty());
    }

    /// Non-empty exempt list: each provided procedure root is stored with the presence marker
    /// `[1, 0, 0, 0]` and lookups for absent roots still return `Word::empty()`.
    #[test]
    fn test_singlesig_acl_with_exempt_procedures() {
        let procedures = get_basic_wallet_procedures();
        let (_public_key, account) = build_account(procedures.clone());

        let marker = Word::from([1u32, 0, 0, 0]);
        for proc_root in &procedures {
            let value = account
                .storage()
                .get_map_item(AuthSingleSigAcl::exempt_procedure_roots_slot(), proc_root.as_word())
                .expect("storage map access failed");
            assert_eq!(value, marker);
        }

        // A root that wasn't exempted reads as Word::empty().
        let probe = account
            .storage()
            .get_map_item(
                AuthSingleSigAcl::exempt_procedure_roots_slot(),
                Word::from([42u32, 0, 0, 0]),
            )
            .expect("storage map access failed");
        assert_eq!(probe, Word::empty());
    }

    /// Duplicate procedure roots in `exempt_procedures` must be rejected by `new` rather than
    /// panicking later inside `StorageMap::with_entries` when the component is converted.
    #[test]
    fn test_singlesig_acl_rejects_duplicate_exempt_procedures() {
        let procedures = get_basic_wallet_procedures();
        let dup = procedures[0];
        let config = AuthSingleSigAclConfig::new().with_exempt_procedures(vec![dup, dup]);

        let result = AuthSingleSigAcl::new(
            PublicKeyCommitment::from(Word::empty()),
            AuthScheme::Falcon512Poseidon2,
            config,
        );
        assert!(result.is_err(), "duplicate exempt procedures should be rejected");
    }

    /// More than `MAX_NUM_PROCEDURES` exempt entries must be rejected by `new`.
    #[test]
    fn test_singlesig_acl_rejects_exempt_list_above_account_limit() {
        let too_many: Vec<AccountProcedureRoot> = (0..=AccountCode::MAX_NUM_PROCEDURES as u32)
            .map(|i| AccountProcedureRoot::from_raw(Word::from([i, 0, 0, 0])))
            .collect();

        let config = AuthSingleSigAclConfig::new().with_exempt_procedures(too_many);

        let result = AuthSingleSigAcl::new(
            PublicKeyCommitment::from(Word::empty()),
            AuthScheme::Falcon512Poseidon2,
            config,
        );
        assert!(result.is_err(), "exempt list above MAX_NUM_PROCEDURES should be rejected");
    }
}
