use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
    StorageSlotSchema,
};
use miden_protocol::account::{
    AccountComponent,
    AccountComponentName,
    AccountProcedureRoot,
    StorageSlotName,
};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionScriptRoot;

use super::{
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
    NetworkAccountTxScriptAllowlist,
};
use crate::account::account_component_code;
use crate::procedure_root;

account_component_code!(NETWORK_ACCOUNT_AUTH_CODE, "miden-standards-auth-network-account.masp");

procedure_root!(
    NETWORK_ACCOUNT_ADD_ALLOWED_NOTE_SCRIPT,
    AuthNetworkAccount::COMPONENT_PATH,
    AuthNetworkAccount::ADD_ALLOWED_NOTE_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_REMOVE_ALLOWED_NOTE_SCRIPT,
    AuthNetworkAccount::COMPONENT_PATH,
    AuthNetworkAccount::REMOVE_ALLOWED_NOTE_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_ADD_ALLOWED_TX_SCRIPT,
    AuthNetworkAccount::COMPONENT_PATH,
    AuthNetworkAccount::ADD_ALLOWED_TX_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

procedure_root!(
    NETWORK_ACCOUNT_REMOVE_ALLOWED_TX_SCRIPT,
    AuthNetworkAccount::COMPONENT_PATH,
    AuthNetworkAccount::REMOVE_ALLOWED_TX_SCRIPT_PROC_NAME,
    AuthNetworkAccount::code()
);

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
/// If both checks pass, the procedure pays the transaction fee by creating a public TX_FEE
/// note funded from the account's vault in the native fee asset at rate 1/1 (see
/// `miden::standards::fee::pay_fee` and `miden::standards::fee::native_conversion_info`). On
/// chains with a zero verification base fee no note is created.
///
/// Because a network account has no signature gate by default, a transaction script is an
/// unconstrained code path that could call the account's procedures directly. The tx-script
/// allowlist constrains this to a fixed set of owner-approved scripts; an empty tx-script allowlist
/// permits no transaction scripts at all.
///
/// IMPORTANT: an allowlisted root pins a script's *code* (its MAST root), not the inputs it runs
/// on. A tx script still receives caller-controlled `TX_SCRIPT_ARGS` and advice-provider inputs,
/// and a note script receives caller-controlled `NOTE_ARGS`; on an open network account anyone can
/// supply those. A root should therefore only be allowlisted when the script's effect is safe for
/// *every* possible input. The canonical example is a tx script that sets the transaction
/// expiration delta to a hardcoded constant: its effect is fixed regardless of caller or inputs,
/// and the kernel only ever lets a script tighten the current transaction's expiration window
/// (never extend it), so the worst a caller can do is make their own transaction expire sooner.
/// Allowlisting a script whose effect depends on its inputs re-opens the very code path the
/// allowlist exists to constrain.
///
/// The note allowlist is stored in the standardized [`NetworkAccountNoteAllowlist`] slot so
/// off-chain services can identify a network account by checking for this slot.
///
/// Both allowlists can be updated after deployment via the `add_allowed_note_script` /
/// `remove_allowed_note_script` and `add_allowed_tx_script` / `remove_allowed_tx_script` account
/// procedures. These are gated by the account-wide
/// [`Authority`](crate::account::access::Authority) component, which must be composed onto the
/// account in [`OwnerControlled`](crate::account::access::Authority::OwnerControlled) or
/// [`RbacControlled`](crate::account::access::Authority::RbacControlled) mode.
/// [`AuthControlled`](crate::account::access::Authority::AuthControlled) mode is unsafe here
/// because this component's auth scheme is intentionally permissionless (any allowlisted script
/// may run against the account), so authorization to mutate the allowlists must come from an owner
/// or a role rather than from the auth scheme itself.
///
/// Because owner and role checks authenticate the note sender, an update is driven by a note the
/// authorized party sends to the account (its script calls the relevant procedure); that admin
/// note's own script root must already be in the note-script allowlist so the transaction passes
/// auth. The auth procedure reads the allowlists from the transaction's initial state, so an update
/// only takes effect from the next transaction. Off-chain, the network transaction builder must
/// re-read the updated allowlist for changes to be reflected in note consumption.
///
/// Roots are matched exactly, so the allowlist must enumerate every root variant the account will
/// consume (including across compiler/standard versions, e.g. P2ID). A missing root means that note
/// is silently unconsumable until an authorized party adds the root.
pub struct AuthNetworkAccount {
    allowed_notes: NetworkAccountNoteAllowlist,
    allowed_tx_scripts: NetworkAccountTxScriptAllowlist,
}

impl AuthNetworkAccount {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account";

    /// The fully-qualified path of this component's compiled MASM library, used to resolve
    /// procedure roots. This is the package namespace declared in `miden-project.toml`, which
    /// differs from [`Self::NAME`].
    const COMPONENT_PATH: &'static str = "miden::standards::components::auth::network_account";

    const ADD_ALLOWED_NOTE_SCRIPT_PROC_NAME: &'static str = "add_allowed_note_script";
    const REMOVE_ALLOWED_NOTE_SCRIPT_PROC_NAME: &'static str = "remove_allowed_note_script";
    const ADD_ALLOWED_TX_SCRIPT_PROC_NAME: &'static str = "add_allowed_tx_script";
    const REMOVE_ALLOWED_TX_SCRIPT_PROC_NAME: &'static str = "remove_allowed_tx_script";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NETWORK_ACCOUNT_AUTH_CODE
    }

    /// Returns the procedure root of the `add_allowed_note_script` procedure exposed by this
    /// component.
    ///
    /// Use it to key the
    /// [`Authority::RbacControlled`](crate::account::access::Authority::RbacControlled)
    /// role map.
    pub fn add_allowed_note_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_ADD_ALLOWED_NOTE_SCRIPT
    }

    /// Returns the procedure root of the `remove_allowed_note_script` procedure exposed by this
    /// component.
    ///
    /// Use it to key the
    /// [`Authority::RbacControlled`](crate::account::access::Authority::RbacControlled)
    /// role map.
    pub fn remove_allowed_note_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_REMOVE_ALLOWED_NOTE_SCRIPT
    }

    /// Returns the procedure root of the `add_allowed_tx_script` procedure exposed by this
    /// component.
    ///
    /// Use it to key the
    /// [`Authority::RbacControlled`](crate::account::access::Authority::RbacControlled)
    /// role map.
    pub fn add_allowed_tx_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_ADD_ALLOWED_TX_SCRIPT
    }

    /// Returns the procedure root of the `remove_allowed_tx_script` procedure exposed by this
    /// component.
    ///
    /// Use it to key the
    /// [`Authority::RbacControlled`](crate::account::access::Authority::RbacControlled)
    /// role map.
    pub fn remove_allowed_tx_script_root() -> AccountProcedureRoot {
        *NETWORK_ACCOUNT_REMOVE_ALLOWED_TX_SCRIPT
    }

    /// Creates a new [`AuthNetworkAccount`] component with the provided list of allowed
    /// input-note script roots.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_script_roots` is empty since the account could not consume any
    /// notes.
    pub fn with_allowed_notes(
        allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        Ok(Self {
            allowed_notes: NetworkAccountNoteAllowlist::new(allowed_script_roots)?,
            allowed_tx_scripts: NetworkAccountTxScriptAllowlist::default(),
        })
    }

    /// Sets the allowlist of transaction script roots this account will execute, replacing any
    /// previously configured tx-script allowlist.
    ///
    /// An empty set (the default) means the account permits no transaction scripts.
    ///
    /// Only scripts whose effect is safe for every possible input should be allowlisted: a root
    /// pins the script's code but not its `TX_SCRIPT_ARGS` or advice inputs, which the
    /// (arbitrary) transaction submitter controls. See the [`AuthNetworkAccount`] type docs for
    /// the full rationale.
    pub fn with_allowed_tx_scripts(
        mut self,
        allowed_tx_script_roots: BTreeSet<TransactionScriptRoot>,
    ) -> Self {
        self.allowed_tx_scripts = NetworkAccountTxScriptAllowlist::new(allowed_tx_script_roots);
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
            component.allowed_notes.into_storage_slot(),
            component.allowed_tx_scripts.into_storage_slot(),
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
                AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([root_a, root_b]))
                    .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building with AuthNetworkAccount failed");
    }

    #[test]
    fn auth_network_account_with_empty_allowlist_is_rejected() {
        let result = AuthNetworkAccount::with_allowed_notes(BTreeSet::new());
        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::EmptyAllowlist)));
    }

    #[test]
    fn auth_network_account_procedure_roots_resolve() {
        // Each accessor resolves its procedure by path in the compiled component; a wrong path
        // (e.g. NAME vs the MASM package namespace) would panic here.
        let roots = [
            AuthNetworkAccount::add_allowed_note_script_root(),
            AuthNetworkAccount::remove_allowed_note_script_root(),
            AuthNetworkAccount::add_allowed_tx_script_root(),
            AuthNetworkAccount::remove_allowed_tx_script_root(),
        ];

        // The four procedures are distinct, so their roots must all differ.
        let unique: BTreeSet<_> = roots.iter().collect();
        assert_eq!(unique.len(), roots.len(), "procedure roots should be distinct");
    }

    #[test]
    fn auth_network_account_uses_standardized_allowlist_slot() {
        let root_a = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let component: AccountComponent =
            AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([root_a]))
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
