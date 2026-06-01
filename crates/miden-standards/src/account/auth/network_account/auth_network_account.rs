use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{AccountComponent, AccountComponentName, StorageSlotName};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionScriptRoot;

use super::{
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
    NetworkAccountTxScriptAllowlist,
};
use crate::account::account_component_code;

account_component_code!(NETWORK_ACCOUNT_AUTH_CODE, "auth/network_account.masl");

// AUTH NETWORK ACCOUNT
// ================================================================================================

/// An [`AccountComponent`] implementing an authentication scheme that restricts what notes an
/// account can consume to a fixed allowlist of note script roots, and what transaction scripts may
/// run against the account to a fixed allowlist of tx script roots.
///
/// This is intended for network-owned accounts (e.g. the AggLayer bridge or a network faucet)
/// whose only legitimate inputs are a known, finite set of system-issued notes and scripts.
///
/// The component exports a single auth procedure, `auth_network_transaction`, that rejects the
/// transaction unless:
/// - the transaction script root, if any, is present in the component's tx-script allowlist, and
/// - every consumed input note has a script root present in the component's note-script allowlist.
///
/// Because a network account has no signature gate, a transaction script is an unconstrained code
/// path that could call the account's procedures directly. The tx-script allowlist constrains this
/// to a fixed set of owner-approved scripts; an empty tx-script allowlist permits no transaction
/// scripts at all.
///
/// IMPORTANT: an allowlisted root pins the script's *code* (its MAST root), but not its
/// `TX_SCRIPT_ARGS` or advice-provider inputs, which anyone submitting a transaction against this
/// open account controls. An allowlisted script therefore runs for arbitrary callers with arbitrary
/// inputs, so only scripts that are safe for *every* possible input should be allowlisted - i.e.
/// input-closed scripts whose effect does not depend on attacker-controlled args/advice. The
/// canonical example is a script that sets the transaction expiration delta to a hardcoded constant
/// (the kernel only ever lets the expiration decrease, so the effect is harmless regardless of who
/// runs it). Allowlisting an input-dependent script re-opens the very code path the allowlist
/// exists to constrain.
///
/// The note allowlist is stored in the standardized [`NetworkAccountNoteAllowlist`] slot so
/// off-chain services can identify a network account by checking for this slot.
///
/// Both allowlists are fixed at account creation; there is intentionally no procedure to mutate
/// them after deployment.
pub struct AuthNetworkAccount {
    allowlist: NetworkAccountNoteAllowlist,
    tx_script_allowlist: NetworkAccountTxScriptAllowlist,
}

impl AuthNetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NETWORK_ACCOUNT_AUTH_CODE
    }

    /// Creates a new [`AuthNetworkAccount`] component with the provided list of allowed
    /// input-note script roots.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_script_roots` is empty since the account could not consume any
    /// notes.
    pub fn with_allowlist(
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        Ok(Self {
            allowlist: NetworkAccountNoteAllowlist::new(allowed_script_roots)?,
            tx_script_allowlist: NetworkAccountTxScriptAllowlist::default(),
        })
    }

    /// Sets the allowlist of transaction script roots this account will execute, replacing any
    /// previously configured tx-script allowlist.
    ///
    /// An empty set (the default) means the account permits no transaction scripts.
    ///
    /// Only input-closed scripts should be allowlisted: a root pins the script's code but not its
    /// `TX_SCRIPT_ARGS` or advice inputs, which the (arbitrary) transaction submitter controls. See
    /// the [`AuthNetworkAccount`] type docs for the full rationale.
    pub fn with_allowed_tx_scripts(
        mut self,
        allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
    ) -> Self {
        self.tx_script_allowlist = NetworkAccountTxScriptAllowlist::new(allowed_tx_script_roots);
        self
    }

    /// Returns the storage slot holding the allowlist of allowed input-note script roots.
    pub fn allowed_note_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountNoteAllowlist::slot_name()
    }

    /// Returns the storage slot schema for the note-script allowlist slot.
    pub fn allowed_note_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        NetworkAccountNoteAllowlist::slot_schema()
    }

    /// Returns the storage slot holding the allowlist of allowed transaction script roots.
    pub fn allowed_tx_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountTxScriptAllowlist::slot_name()
    }

    /// Returns the storage slot schema for the tx-script allowlist slot.
    pub fn allowed_tx_scripts_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
        NetworkAccountTxScriptAllowlist::slot_schema()
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        let storage_schema = StorageSchema::new(vec![
            NetworkAccountNoteAllowlist::slot_schema(),
            NetworkAccountTxScriptAllowlist::slot_schema(),
        ])
        .expect("storage schema should be valid");

        AccountComponentMetadata::new(Self::NAME)
            .with_description(
                "Authentication component that restricts input notes and transaction scripts to \
                 fixed allowlists of script roots",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthNetworkAccount> for AccountComponent {
    fn from(component: AuthNetworkAccount) -> Self {
        let storage_slots = vec![
            component.allowlist.into_storage_slot(),
            component.tx_script_allowlist.into_storage_slot(),
        ];
        let metadata = AuthNetworkAccount::component_metadata();

        AccountComponent::new(AuthNetworkAccount::code().clone(), storage_slots, metadata).expect(
            "AuthNetworkAccount component should satisfy the requirements of a valid \
             account component",
        )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, StorageSlotContent};

    use super::*;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn auth_network_account_component_builds() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let root_b = NoteScriptRoot::from_array([5, 6, 7, 8]);

        let _account = AccountBuilder::new([0; 32])
            .with_auth_component(
                AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([root_a, root_b]))
                    .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");
    }

    #[test]
    fn auth_network_account_with_empty_allowlist_is_rejected() {
        let result = AuthNetworkAccount::with_allowlist(BTreeSet::new());
        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::EmptyAllowlist)));
    }

    #[test]
    fn auth_network_account_uses_standardized_allowlist_slot() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let component: AccountComponent =
            AuthNetworkAccount::with_allowlist(BTreeSet::from_iter([root_a]))
                .expect("non-empty allowlist should construct")
                .into();

        let storage_slots = component.storage_slots();
        assert_eq!(storage_slots.len(), 2);
        assert_eq!(storage_slots[0].name(), NetworkAccountNoteAllowlist::slot_name());
        assert_eq!(storage_slots[1].name(), NetworkAccountTxScriptAllowlist::slot_name());

        for slot in storage_slots {
            let StorageSlotContent::Map(_) = slot.content() else {
                panic!("allowlist slots must be maps");
            };
        }
    }
}
