use alloc::vec::Vec;

use miden_protocol::account::auth::{AuthScheme, PublicKeyCommitment};
use miden_protocol::account::component::{
    AccountComponentMetadata,
    FeltSchema,
    SchemaTypeId,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountCode,
    AccountComponent,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};

use crate::account::components::singlesig_acl_library;

static PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::pub_key")
        .expect("storage slot name should be valid")
});

static SCHEME_ID_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::scheme")
        .expect("storage slot name should be valid")
});

static CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::config")
        .expect("storage slot name should be valid")
});

static TRIGGER_PROCEDURE_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::singlesig_acl::trigger_procedure_roots")
        .expect("storage slot name should be valid")
});

/// Configuration for [`AuthSingleSigAcl`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSingleSigAclConfig {
    /// List of procedure roots that require authentication when called.
    pub auth_trigger_procedures: Vec<Word>,
    /// When `false`, creating output notes (sending notes to other accounts) requires
    /// authentication. When `true`, output notes can be created without authentication.
    pub allow_unauthorized_output_notes: bool,
    /// When `false`, consuming input notes (processing notes sent to this account) requires
    /// authentication. When `true`, input notes can be consumed without authentication.
    pub allow_unauthorized_input_notes: bool,
}

impl AuthSingleSigAclConfig {
    /// Creates a new configuration with no trigger procedures and both flags set to `false` (most
    /// restrictive).
    pub fn new() -> Self {
        Self {
            auth_trigger_procedures: vec![],
            allow_unauthorized_output_notes: false,
            allow_unauthorized_input_notes: false,
        }
    }

    /// Sets the list of procedure roots that require authentication when called.
    pub fn with_auth_trigger_procedures(mut self, procedures: Vec<Word>) -> Self {
        self.auth_trigger_procedures = procedures;
        self
    }

    /// Sets whether unauthorized output notes are allowed.
    pub fn with_allow_unauthorized_output_notes(mut self, allow: bool) -> Self {
        self.allow_unauthorized_output_notes = allow;
        self
    }

    /// Sets whether unauthorized input notes are allowed.
    pub fn with_allow_unauthorized_input_notes(mut self, allow: bool) -> Self {
        self.allow_unauthorized_input_notes = allow;
        self
    }
}

impl Default for AuthSingleSigAclConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`AccountComponent`] implementing a procedure-based Access Control List (ACL) using either
/// the EcdsaK256Keccak or Rpo Falcon 512 signature scheme for authentication of transactions.
///
/// This component provides fine-grained authentication control based on three conditions:
/// 1. **Procedure-based authentication**: Requires authentication when any of the specified trigger
///    procedures are called during the transaction.
/// 2. **Output note authentication**: Controls whether creating output notes requires
///    authentication. Output notes are new notes created by the account and sent to other accounts
///    (e.g., when transferring assets). When `allow_unauthorized_output_notes` is `false`, any
///    transaction that creates output notes must be authenticated, ensuring account owners control
///    when their account sends assets to other accounts.
/// 3. **Input note authentication**: Controls whether consuming input notes requires
///    authentication. Input notes are notes that were sent to this account by other accounts (e.g.,
///    incoming asset transfers). When `allow_unauthorized_input_notes` is `false`, any transaction
///    that consumes input notes must be authenticated, ensuring account owners control when their
///    account processes incoming notes.
///
/// ## Authentication Logic
///
/// Authentication is required if ANY of the following conditions are true:
/// - Any trigger procedure from the ACL was called
/// - Output notes were created AND `allow_unauthorized_output_notes` is `false`
/// - Input notes were consumed AND `allow_unauthorized_input_notes` is `false`
///
/// If none of these conditions are met, only the nonce is incremented without requiring a
/// signature.
///
/// ## Use Cases
///
/// - **Restrictive mode** (`allow_unauthorized_output_notes=false`,
///   `allow_unauthorized_input_notes=false`): All note operations require authentication, providing
///   maximum security.
/// - **Selective mode**: Allow some note operations without authentication while protecting
///   specific procedures, useful for accounts that need to process certain operations
///   automatically.
/// - **Procedure-only mode** (`allow_unauthorized_output_notes=true`,
///   `allow_unauthorized_input_notes=true`): Only specific procedures require authentication,
///   allowing free note processing.
///
/// ## Storage Layout
/// - [`Self::public_key_slot`]: Public key
/// - [`Self::config_slot`]: `[num_trigger_procs, allow_unauthorized_output_notes,
///   allow_unauthorized_input_notes, 0]`
/// - [`Self::trigger_procedure_roots_slot`]: A map with trigger procedure roots
///
/// ## Important Note on Procedure Detection
/// The procedure-based authentication relies on the `was_procedure_called` kernel function,
/// which only returns `true` if the procedure in question called into a kernel account API
/// that is restricted to the account context. Procedures that don't interact with account
/// state or kernel APIs may not be detected as "called" even if they were executed during
/// the transaction. This is an important limitation to consider when designing trigger
/// procedures for authentication.
///
/// This component supports all account types.
pub struct AuthSingleSigAcl {
    pub_key: PublicKeyCommitment,
    auth_scheme: AuthScheme,
    config: AuthSingleSigAclConfig,
}

impl AuthSingleSigAcl {
    /// The name of the component.
    pub const NAME: &'static str = "miden::auth::singlesig_acl";
    /// Creates a new [`AuthSingleSigAcl`] component with the given `public_key` and
    /// configuration.
    ///
    /// # Panics
    /// Panics if more than [AccountCode::MAX_NUM_PROCEDURES] procedures are specified.
    pub fn new(
        pub_key: PublicKeyCommitment,
        auth_scheme: AuthScheme,
        config: AuthSingleSigAclConfig,
    ) -> Result<Self, AccountError> {
        let max_procedures = AccountCode::MAX_NUM_PROCEDURES;
        if config.auth_trigger_procedures.len() > max_procedures {
            return Err(AccountError::other(format!(
                "Cannot track more than {max_procedures} procedures (account limit)"
            )));
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

    /// Returns the [`StorageSlotName`] where the component's configuration is stored.
    pub fn config_slot() -> &'static StorageSlotName {
        &CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the trigger procedure roots are stored.
    pub fn trigger_procedure_roots_slot() -> &'static StorageSlotName {
        &TRIGGER_PROCEDURE_ROOT_SLOT_NAME
    }

    /// Returns the storage slot schema for the public key slot.
    pub fn public_key_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::public_key_slot().clone(),
            StorageSlotSchema::value("Public key commitment", SchemaTypeId::pub_key()),
        )
    }

    /// Returns the storage slot schema for the configuration slot.
    pub fn config_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::config_slot().clone(),
            StorageSlotSchema::value(
                "ACL configuration",
                [
                    FeltSchema::u32("num_trigger_procs").with_default(Felt::new(0)),
                    FeltSchema::u32("allow_unauthorized_output_notes").with_default(Felt::new(0)),
                    FeltSchema::u32("allow_unauthorized_input_notes").with_default(Felt::new(0)),
                    FeltSchema::new_void(),
                ],
            ),
        )
    }

    // Returns the storage slot schema for the scheme ID slot.
    pub fn auth_scheme_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::scheme_id_slot().clone(),
            StorageSlotSchema::value("Scheme ID", SchemaTypeId::auth_scheme()),
        )
    }

    /// Returns the storage slot schema for the trigger procedure roots slot.
    pub fn trigger_procedure_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        (
            Self::trigger_procedure_roots_slot().clone(),
            StorageSlotSchema::map(
                "Trigger procedure roots",
                SchemaTypeId::u32(),
                SchemaTypeId::native_word(),
            ),
        )
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

        // Config slot
        let num_procs = singlesig_acl.config.auth_trigger_procedures.len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthSingleSigAcl::config_slot().clone(),
            Word::from([
                num_procs,
                u32::from(singlesig_acl.config.allow_unauthorized_output_notes),
                u32::from(singlesig_acl.config.allow_unauthorized_input_notes),
                0,
            ]),
        ));

        // Trigger procedure roots slot
        // We add the map even if there are no trigger procedures, to always maintain the same
        // storage layout.
        let map_entries = singlesig_acl
            .config
            .auth_trigger_procedures
            .iter()
            .enumerate()
            .map(|(i, proc_root)| (Word::from([i as u32, 0, 0, 0]), *proc_root));

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthSingleSigAcl::trigger_procedure_roots_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        let storage_schema = StorageSchema::new(vec![
            AuthSingleSigAcl::public_key_slot_schema(),
            AuthSingleSigAcl::auth_scheme_slot_schema(),
            AuthSingleSigAcl::config_slot_schema(),
            AuthSingleSigAcl::trigger_procedure_roots_slot_schema(),
        ])
        .expect("storage schema should be valid");

        let metadata = AccountComponentMetadata::new(AuthSingleSigAcl::NAME)
            .with_description("Authentication component with procedure-based ACL using ECDSA K256 Keccak or Rpo Falcon 512 signature scheme")
            .with_supports_all_types()
            .with_storage_schema(storage_schema);

        AccountComponent::new(singlesig_acl_library(), storage_slots, metadata).expect(
            "singlesig ACL component should satisfy the requirements of a valid account component",
        )
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::account::AccountBuilder;

    use super::*;
    use crate::account::components::StandardAccountComponent;
    use crate::account::wallets::BasicWallet;

    /// Test configuration for parametrized ACL tests
    struct AclTestConfig {
        /// Whether to include auth trigger procedures
        with_procedures: bool,
        /// Allow unauthorized output notes flag
        allow_unauthorized_output_notes: bool,
        /// Allow unauthorized input notes flag
        allow_unauthorized_input_notes: bool,
        /// Expected config slot value [num_procs, allow_output, allow_input, 0]
        expected_config_slot: Word,
    }

    /// Helper function to get the basic wallet procedures for testing
    fn get_basic_wallet_procedures() -> Vec<Word> {
        // Get the two trigger procedures from BasicWallet: `receive_asset`, `move_asset_to_note`.
        let procedures: Vec<Word> =
            StandardAccountComponent::BasicWallet.procedure_digests().collect();

        assert_eq!(procedures.len(), 2);
        procedures
    }

    /// Parametrized test helper for ACL component testing
    fn test_acl_component(config: AclTestConfig) {
        let public_key = PublicKeyCommitment::from(Word::empty());
        let auth_scheme = AuthScheme::Falcon512Rpo;

        // Build the configuration
        let mut acl_config = AuthSingleSigAclConfig::new()
            .with_allow_unauthorized_output_notes(config.allow_unauthorized_output_notes)
            .with_allow_unauthorized_input_notes(config.allow_unauthorized_input_notes);

        let auth_trigger_procedures = if config.with_procedures {
            let procedures = get_basic_wallet_procedures();
            acl_config = acl_config.with_auth_trigger_procedures(procedures.clone());
            procedures
        } else {
            vec![]
        };

        // Create component and account
        let component = AuthSingleSigAcl::new(public_key, auth_scheme, acl_config)
            .expect("component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Check public key storage
        let public_key_slot = account
            .storage()
            .get_item(AuthSingleSigAcl::public_key_slot())
            .expect("public key storage slot access failed");
        assert_eq!(public_key_slot, public_key.into());

        // Check configuration storage
        let config_slot = account
            .storage()
            .get_item(AuthSingleSigAcl::config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, config.expected_config_slot);

        // Check procedure roots
        if config.with_procedures {
            for (i, expected_proc_root) in auth_trigger_procedures.iter().enumerate() {
                let proc_root = account
                    .storage()
                    .get_map_item(
                        AuthSingleSigAcl::trigger_procedure_roots_slot(),
                        Word::from([i as u32, 0, 0, 0]),
                    )
                    .expect("storage map access failed");
                assert_eq!(proc_root, *expected_proc_root);
            }
        } else {
            // When no procedures, the map should return empty for key [0,0,0,0]
            let proc_root = account
                .storage()
                .get_map_item(AuthSingleSigAcl::trigger_procedure_roots_slot(), Word::empty())
                .expect("storage map access failed");
            assert_eq!(proc_root, Word::empty());
        }
    }

    /// Test ACL component with no procedures and both authorization flags set to false
    #[test]
    fn test_singlesig_acl_no_procedures() {
        test_acl_component(AclTestConfig {
            with_procedures: false,
            allow_unauthorized_output_notes: false,
            allow_unauthorized_input_notes: false,
            expected_config_slot: Word::empty(), // [0, 0, 0, 0]
        });
    }

    /// Test ACL component with two procedures and both authorization flags set to false
    #[test]
    fn test_singlesig_acl_with_two_procedures() {
        test_acl_component(AclTestConfig {
            with_procedures: true,
            allow_unauthorized_output_notes: false,
            allow_unauthorized_input_notes: false,
            expected_config_slot: Word::from([2u32, 0, 0, 0]),
        });
    }

    /// Test ACL component with no procedures and allow_unauthorized_output_notes set to true
    #[test]
    fn test_ecdsa_k256_keccak_acl_with_allow_unauthorized_output_notes() {
        test_acl_component(AclTestConfig {
            with_procedures: false,
            allow_unauthorized_output_notes: true,
            allow_unauthorized_input_notes: false,
            expected_config_slot: Word::from([0u32, 1, 0, 0]),
        });
    }

    /// Test ACL component with two procedures and allow_unauthorized_output_notes set to true
    #[test]
    fn test_ecdsa_k256_keccak_acl_with_procedures_and_allow_unauthorized_output_notes() {
        test_acl_component(AclTestConfig {
            with_procedures: true,
            allow_unauthorized_output_notes: true,
            allow_unauthorized_input_notes: false,
            expected_config_slot: Word::from([2u32, 1, 0, 0]),
        });
    }

    /// Test ACL component with no procedures and allow_unauthorized_input_notes set to true
    #[test]
    fn test_ecdsa_k256_keccak_acl_with_allow_unauthorized_input_notes() {
        test_acl_component(AclTestConfig {
            with_procedures: false,
            allow_unauthorized_output_notes: false,
            allow_unauthorized_input_notes: true,
            expected_config_slot: Word::from([0u32, 0, 1, 0]),
        });
    }

    /// Test ACL component with two procedures and both authorization flags set to true
    #[test]
    fn test_ecdsa_k256_keccak_acl_with_both_allow_flags() {
        test_acl_component(AclTestConfig {
            with_procedures: true,
            allow_unauthorized_output_notes: true,
            allow_unauthorized_input_notes: true,
            expected_config_slot: Word::from([2u32, 1, 1, 0]),
        });
    }
}
