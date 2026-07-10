use alloc::collections::BTreeSet;
use alloc::vec;

use miden_protocol::account::component::{
    AccountComponentCode,
    AccountComponentMetadata,
    StorageSchema,
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
use crate::note::NetworkSponsorshipNote;

account_component_code!(
    NETWORK_ACCOUNT_WITH_FEES_AUTH_CODE,
    "miden-standards-auth-network-account-with-fees.masp"
);

// AUTH NETWORK ACCOUNT WITH FEES
// ================================================================================================

/// [`AuthNetworkAccount`](super::AuthNetworkAccount)'s allowlist checks plus fee settlement, for
/// network accounts that install the [`FeeManager`](crate::account::fees::FeeManager) component.
///
/// The auth procedure first enforces the tx-script and input-note allowlists exactly like
/// [`AuthNetworkAccount`](super::AuthNetworkAccount) (including its caveats about allowlisting
/// only scripts whose effect is safe for every input), then settles the transaction's fees via
/// `fee_manager::settle_fees`, then increments the nonce when the account state changed. The two
/// gates are independent: the allowlists decide what may run, fee settlement what it costs.
///
/// The allowlists live in the same standardized storage slots as
/// [`AuthNetworkAccount`](super::AuthNetworkAccount)'s, so off-chain services identify a
/// fee-managed network account exactly like a plain one.
///
/// # Dependencies
///
/// The account must also install [`FeeManager`](crate::account::fees::FeeManager), which holds the
/// fee schedule that settlement reads.
pub struct AuthNetworkAccountWithFees {
    allowed_notes: NetworkAccountNoteAllowlist,
    allowed_tx_scripts: NetworkAccountTxScriptAllowlist,
}

impl AuthNetworkAccountWithFees {
    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::auth::network_account_with_fees";

    /// Returns the canonical [`AccountComponentName`] of this component.
    pub const fn name() -> AccountComponentName {
        AccountComponentName::from_static_str(Self::NAME)
    }

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &NETWORK_ACCOUNT_WITH_FEES_AUTH_CODE
    }

    /// Creates a new [`AuthNetworkAccountWithFees`] component with the provided list of allowed
    /// input-note script roots.
    ///
    /// The [`NetworkSponsorshipNote`] script root is always added to the set: a fee-managed
    /// account that cannot consume sponsorship notes could never be paid.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_script_roots` is empty. A sponsorship note is never
    /// consumable on its own, so an account allowlisting nothing else could not consume any
    /// notes.
    pub fn with_allowed_notes(
        mut allowed_script_roots: BTreeSet<NoteScriptRoot>,
    ) -> Result<Self, NetworkAccountNoteAllowlistError> {
        // Validate the caller-supplied set before the auto-insertion, so an operator who
        // configured an account that can consume no feature notes gets a diagnostic instead of a
        // permanently inert account.
        if allowed_script_roots.is_empty() {
            return Err(NetworkAccountNoteAllowlistError::EmptyAllowlist);
        }
        allowed_script_roots.insert(NetworkSponsorshipNote::script_root());

        Ok(Self {
            allowed_notes: NetworkAccountNoteAllowlist::new(allowed_script_roots)?,
            allowed_tx_scripts: NetworkAccountTxScriptAllowlist::default(),
        })
    }

    /// Sets the allowlist of transaction script roots this account will execute, replacing any
    /// previously configured tx-script allowlist.
    ///
    /// An empty set (the default) means the account permits no transaction scripts. See
    /// [`AuthNetworkAccount::with_allowed_tx_scripts`](super::AuthNetworkAccount::with_allowed_tx_scripts)
    /// for the safety caveats.
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

    /// Returns the storage slot holding the allowlist of allowed transaction script roots.
    pub fn allowed_tx_scripts_slot() -> &'static StorageSlotName {
        NetworkAccountTxScriptAllowlist::slot_name()
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
                "Authentication component combining the network-account script allowlists with \
                 sponsorship fee settlement",
            )
            .with_storage_schema(storage_schema)
    }
}

impl From<AuthNetworkAccountWithFees> for AccountComponent {
    fn from(component: AuthNetworkAccountWithFees) -> Self {
        let storage_slots = vec![
            component.allowed_notes.into_storage_slot(),
            component.allowed_tx_scripts.into_storage_slot(),
        ];
        let metadata = AuthNetworkAccountWithFees::component_metadata();

        AccountComponent::new(AuthNetworkAccountWithFees::code().clone(), storage_slots, metadata)
            .expect(
                "AuthNetworkAccountWithFees component should satisfy the requirements of a valid \
                 account component",
            )
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountBuilder, AccountType, StorageSlotContent};

    use super::super::NetworkAccount;
    use super::*;
    use crate::account::wallets::BasicWallet;

    #[test]
    fn empty_allowlist_is_rejected() {
        let result = AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::new());
        assert!(matches!(result, Err(NetworkAccountNoteAllowlistError::EmptyAllowlist)));
    }

    /// The allowlists live in the same standardized slots as `AuthNetworkAccount`'s, so off-chain
    /// services identify a fee-managed network account exactly like a plain one.
    #[test]
    fn uses_standardized_allowlist_slots() {
        let root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let component: AccountComponent =
            AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from_iter([root]))
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

    /// An account built with this component round-trips through [`NetworkAccount`], and its
    /// allowlist contains the auto-inserted sponsorship root.
    #[test]
    fn network_account_round_trip_with_auto_inserted_sponsorship_root() {
        let root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let account = AccountBuilder::new([0; 32])
            .account_type(AccountType::Public)
            .with_auth_component(
                AuthNetworkAccountWithFees::with_allowed_notes(BTreeSet::from_iter([root]))
                    .expect("non-empty allowlist should construct"),
            )
            .with_component(BasicWallet)
            .build_existing()
            .expect("account building with AuthNetworkAccountWithFees failed");

        let network_account =
            NetworkAccount::new(account).expect("the standardized slot should be recognized");
        let allowed = network_account.allowed_notes().allowed_script_roots();
        assert!(allowed.contains(&root));
        assert!(allowed.contains(&NetworkSponsorshipNote::script_root()));
    }
}
