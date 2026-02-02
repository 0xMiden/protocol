use alloc::vec::Vec;

use miden_protocol::Word;
use miden_protocol::account::auth::PublicKeyCommitment;
use miden_protocol::account::{
    AccountCode,
    AccountComponent,
    StorageMap,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::errors::AccountError;
use miden_protocol::utils::sync::LazyLock;

use crate::account::components::ecdsa_k256_keccak_acl_library;

static PUBKEY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_acl::public_key")
        .expect("storage slot name should be valid")
});

static CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_acl::config")
        .expect("storage slot name should be valid")
});

static TRIGGER_PROCEDURE_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::auth::ecdsa_k256_keccak_acl::trigger_procedure_roots")
        .expect("storage slot name should be valid")
});

/// Configuration for [`AuthEcdsaK256KeccakAcl`] component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEcdsaK256KeccakAclConfig {
    /// List of procedure roots that require authentication when called.
    pub auth_trigger_procedures: Vec<Word>,
    /// When `false`, creating output notes (sending notes to other accounts) requires
    /// authentication. When `true`, output notes can be created without authentication.
    pub allow_unauthorized_output_notes: bool,
    /// When `false`, consuming input notes (processing notes sent to this account) requires
    /// authentication. When `true`, input notes can be consumed without authentication.
    pub allow_unauthorized_input_notes: bool,
}

impl AuthEcdsaK256KeccakAclConfig {
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

impl Default for AuthEcdsaK256KeccakAclConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`AccountComponent`] implementing a procedure-based Access Control List (ACL) using the
/// EcdsaK256Keccak signature scheme for authentication of transactions.
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
pub struct AuthEcdsaK256KeccakAcl {
    pub_key: PublicKeyCommitment,
    config: AuthEcdsaK256KeccakAclConfig,
}

impl AuthEcdsaK256KeccakAcl {
    /// Creates a new [`AuthEcdsaK256KeccakAcl`] component with the given `public_key` and
    /// configuration.
    ///
    /// # Panics
    /// Panics if more than [AccountCode::MAX_NUM_PROCEDURES] procedures are specified.
    pub fn new(
        pub_key: PublicKeyCommitment,
        config: AuthEcdsaK256KeccakAclConfig,
    ) -> Result<Self, AccountError> {
        let max_procedures = AccountCode::MAX_NUM_PROCEDURES;
        if config.auth_trigger_procedures.len() > max_procedures {
            return Err(AccountError::other(format!(
                "Cannot track more than {max_procedures} procedures (account limit)"
            )));
        }

        Ok(Self { pub_key, config })
    }

    /// Returns the [`StorageSlotName`] where the public key is stored.
    pub fn public_key_slot() -> &'static StorageSlotName {
        &PUBKEY_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the component's configuration is stored.
    pub fn config_slot() -> &'static StorageSlotName {
        &CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] where the trigger procedure roots are stored.
    pub fn trigger_procedure_roots_slot() -> &'static StorageSlotName {
        &TRIGGER_PROCEDURE_ROOT_SLOT_NAME
    }
}

impl From<AuthEcdsaK256KeccakAcl> for AccountComponent {
    fn from(ecdsa: AuthEcdsaK256KeccakAcl) -> Self {
        let mut storage_slots = Vec::with_capacity(3);

        // Public key slot
        storage_slots.push(StorageSlot::with_value(
            AuthEcdsaK256KeccakAcl::public_key_slot().clone(),
            ecdsa.pub_key.into(),
        ));

        // Config slot
        let num_procs = ecdsa.config.auth_trigger_procedures.len() as u32;
        storage_slots.push(StorageSlot::with_value(
            AuthEcdsaK256KeccakAcl::config_slot().clone(),
            Word::from([
                num_procs,
                u32::from(ecdsa.config.allow_unauthorized_output_notes),
                u32::from(ecdsa.config.allow_unauthorized_input_notes),
                0,
            ]),
        ));

        // Trigger procedure roots slot
        // We add the map even if there are no trigger procedures, to always maintain the same
        // storage layout.
        let map_entries = ecdsa
            .config
            .auth_trigger_procedures
            .iter()
            .enumerate()
            .map(|(i, proc_root)| (Word::from([i as u32, 0, 0, 0]), *proc_root));

        // Safe to unwrap because we know that the map keys are unique.
        storage_slots.push(StorageSlot::with_map(
            AuthEcdsaK256KeccakAcl::trigger_procedure_roots_slot().clone(),
            StorageMap::with_entries(map_entries).unwrap(),
        ));

        AccountComponent::new(ecdsa_k256_keccak_acl_library(), storage_slots)
            .expect(
                "ACL auth component should satisfy the requirements of a valid account component",
            )
            .with_supports_all_types()
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

        // Build the configuration
        let mut acl_config = AuthEcdsaK256KeccakAclConfig::new()
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
        let component =
            AuthEcdsaK256KeccakAcl::new(public_key, acl_config).expect("component creation failed");

        let account = AccountBuilder::new([0; 32])
            .with_auth_component(component)
            .with_component(BasicWallet)
            .build()
            .expect("account building failed");

        // Check public key storage
        let public_key_slot = account
            .storage()
            .get_item(AuthEcdsaK256KeccakAcl::public_key_slot())
            .expect("public key storage slot access failed");
        assert_eq!(public_key_slot, public_key.into());

        // Check configuration storage
        let config_slot = account
            .storage()
            .get_item(AuthEcdsaK256KeccakAcl::config_slot())
            .expect("config storage slot access failed");
        assert_eq!(config_slot, config.expected_config_slot);

        // Check procedure roots
        if config.with_procedures {
            for (i, expected_proc_root) in auth_trigger_procedures.iter().enumerate() {
                let proc_root = account
                    .storage()
                    .get_map_item(
                        AuthEcdsaK256KeccakAcl::trigger_procedure_roots_slot(),
                        Word::from([i as u32, 0, 0, 0]),
                    )
                    .expect("storage map access failed");
                assert_eq!(proc_root, *expected_proc_root);
            }
        } else {
            // When no procedures, the map should return empty for key [0,0,0,0]
            let proc_root = account
                .storage()
                .get_map_item(AuthEcdsaK256KeccakAcl::trigger_procedure_roots_slot(), Word::empty())
                .expect("storage map access failed");
            assert_eq!(proc_root, Word::empty());
        }
    }

    /// Test ACL component with no procedures and both authorization flags set to false
    #[test]
    fn test_ecdsa_k256_keccak_acl_no_procedures() {
        test_acl_component(AclTestConfig {
            with_procedures: false,
            allow_unauthorized_output_notes: false,
            allow_unauthorized_input_notes: false,
            expected_config_slot: Word::empty(), // [0, 0, 0, 0]
        });
    }

    /// Test ACL component with two procedures and both authorization flags set to false
    #[test]
    fn test_ecdsa_k256_keccak_acl_with_two_procedures() {
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
