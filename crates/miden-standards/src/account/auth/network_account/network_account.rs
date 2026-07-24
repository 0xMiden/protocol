use alloc::collections::BTreeSet;

use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountStorage, AccountType};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionScriptRoot;

use crate::account::auth::network_account::{
    AuthNetworkAccount,
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
    NetworkAccountTxScriptAllowlist,
    NetworkAccountTxScriptAllowlistError,
};
use crate::tx_script::ExpirationTransactionScript;

// NETWORK ACCOUNT
// ================================================================================================

/// A wrapper around an [`Account`] that is guaranteed to be a network account.
///
/// # Specification
///
/// An [`Account`] is a network account if and only if all of the following hold:
///
/// - It MUST be public, i.e. [`Account::is_public`] returns `true`. The network needs to read
///   account storage to identify the account and route notes to it, so private accounts cannot be
///   network accounts.
/// - Its storage MUST contain a valid [`NetworkAccountNoteAllowlist`] slot. Concretely:
///   - the storage slot named [`NetworkAccountNoteAllowlist::slot_name`] MUST be present,
///   - the slot MUST be a [`StorageMap`](miden_protocol::account::StorageMap) (not a value slot),
///   - the map MUST be non-empty (the allowlist contains at least one allowed
///     [`NoteScriptRoot`](miden_protocol::note::NoteScriptRoot)).
/// - Its storage MUST contain a [`NetworkAccountTxScriptAllowlist`] slot, and the slot (a
///   [`StorageMap`](miden_protocol::account::StorageMap)) MUST contain the root of the canonical
///   [`ExpirationTransactionScript`]. The network transaction builder attaches that script to every
///   network transaction it executes, so an account without the root could never be serviced.
///
/// The allowlist slots are the shared abstraction across every network-account component: they let
/// off-chain services identify a network account without knowing which component it uses.
/// [`NetworkAccount::builder`] produces accounts satisfying this specification by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAccount {
    account: Account,
    note_allowlist: NetworkAccountNoteAllowlist,
    tx_script_allowlist: NetworkAccountTxScriptAllowlist,
}

impl NetworkAccount {
    /// Attempts to construct a [`NetworkAccount`] from `account`.
    ///
    /// Returns an error if:
    /// - the account is not [`public`](Account::is_public), or
    /// - the account's storage does not contain a valid [`NetworkAccountNoteAllowlist`] slot (see
    ///   [`NetworkAccountNoteAllowlist::try_from`] for the exact storage-level checks), or
    /// - the account's storage does not contain a valid [`NetworkAccountTxScriptAllowlist`] slot,
    ///   or the allowlist does not contain the canonical [`ExpirationTransactionScript`] root.
    pub fn new(account: Account) -> Result<Self, NetworkAccountError> {
        if !account.is_public() {
            return Err(NetworkAccountError::AccountNotPublic(account.id()));
        }

        let note_allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())
            .map_err(NetworkAccountError::NoteAllowlist)?;

        let tx_script_allowlist = NetworkAccountTxScriptAllowlist::try_from(account.storage())
            .map_err(NetworkAccountError::TxScriptAllowlist)?;
        if !tx_script_allowlist
            .allowed_script_roots()
            .contains(&ExpirationTransactionScript::script_root())
        {
            return Err(NetworkAccountError::ExpirationScriptNotAllowlisted);
        }

        Ok(Self {
            account,
            note_allowlist,
            tx_script_allowlist,
        })
    }

    /// Creates an [`AccountBuilder`] pre-configured as a network account.
    ///
    /// The returned builder is set to [`AccountType::Public`] and has the [`AuthNetworkAccount`]
    /// auth component installed with the provided note allowlist. The component's tx-script
    /// allowlist contains the canonical [`ExpirationTransactionScript`], which the network
    /// transaction builder attaches to every network transaction it executes, so the built
    /// account is serviceable by the network by construction.
    ///
    /// Callers add their functional components to the returned builder and finish with
    /// [`AccountBuilder::build`]; the built account satisfies the [`NetworkAccount`]
    /// specification. Accounts that need to allowlist additional transaction scripts should
    /// construct the [`AuthNetworkAccount`] component manually instead.
    ///
    /// # Errors
    ///
    /// Returns an error if `allowed_notes` is empty since the account could not consume any
    /// notes.
    pub fn builder(
        init_seed: [u8; 32],
        allowed_notes: BTreeSet<NoteScriptRoot>,
    ) -> Result<AccountBuilder, NetworkAccountNoteAllowlistError> {
        let auth_component = AuthNetworkAccount::with_allowed_notes(allowed_notes)?
            .with_allowed_tx_scripts(
                [ExpirationTransactionScript::script_root()].into_iter().collect(),
            );

        Ok(AccountBuilder::new(init_seed)
            .account_type(AccountType::Public)
            .with_component(auth_component))
    }

    /// Consumes `self` and returns the underlying [`Account`].
    pub fn into_account(self) -> Account {
        self.account
    }

    /// Returns a reference to the underlying [`Account`].
    pub fn as_account(&self) -> &Account {
        &self.account
    }

    /// Returns the [`AccountId`] of the underlying account.
    pub fn id(&self) -> AccountId {
        self.account.id()
    }

    /// Returns a reference to the [`AccountStorage`] of the underlying account.
    pub fn storage(&self) -> &AccountStorage {
        self.account.storage()
    }

    /// Returns the [`NetworkAccountNoteAllowlist`] decoded from the underlying account's storage.
    pub fn allowed_notes(&self) -> &NetworkAccountNoteAllowlist {
        &self.note_allowlist
    }

    /// Returns the [`NetworkAccountTxScriptAllowlist`] decoded from the underlying account's
    /// storage. It always contains at least the canonical [`ExpirationTransactionScript`] root.
    pub fn allowed_tx_scripts(&self) -> &NetworkAccountTxScriptAllowlist {
        &self.tx_script_allowlist
    }

    /// Returns `true` if the account allowlists the transaction script with the given `root`.
    ///
    /// A transaction executed against this account that carries a transaction script whose root
    /// is not allowlisted is rejected by the account's auth procedure.
    pub fn allows_tx_script(&self, root: &TransactionScriptRoot) -> bool {
        self.tx_script_allowlist.allowed_script_roots().contains(root)
    }
}

impl TryFrom<Account> for NetworkAccount {
    type Error = NetworkAccountError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        Self::new(account)
    }
}

// NETWORK ACCOUNT ERROR
// ================================================================================================

/// Errors that can occur when constructing a [`NetworkAccount`] from an [`Account`].
#[derive(Debug, thiserror::Error)]
pub enum NetworkAccountError {
    #[error("network account must have public account type, but account {0} does not")]
    AccountNotPublic(AccountId),
    #[error("failed to decode the note-script allowlist from account storage")]
    NoteAllowlist(#[source] NetworkAccountNoteAllowlistError),
    #[error("failed to decode the tx-script allowlist from account storage")]
    TxScriptAllowlist(#[source] NetworkAccountTxScriptAllowlistError),
    #[error(
        "network account tx-script allowlist must contain the canonical expiration transaction \
         script root"
    )]
    ExpirationScriptNotAllowlisted,
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use miden_protocol::Word;
    use miden_protocol::account::{AccountBuilder, AccountType};
    use miden_protocol::note::NoteScriptRoot;

    use super::*;
    use crate::account::auth::network_account::AuthNetworkAccount;
    use crate::account::wallets::BasicWallet;

    fn build_account(account_type: AccountType, roots: BTreeSet<NoteScriptRoot>) -> Account {
        AccountBuilder::new([0; 32])
            .account_type(account_type)
            .with_component(
                AuthNetworkAccount::with_allowed_notes(roots)
                    .expect("non-empty allowlist")
                    .with_allowed_tx_scripts(
                        [ExpirationTransactionScript::script_root()].into_iter().collect(),
                    ),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building should succeed")
    }

    #[test]
    fn public_account_with_allowlist_is_a_network_account() {
        let root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let roots = BTreeSet::from_iter([root]);
        let account = build_account(AccountType::Public, roots.clone());

        let network_account = NetworkAccount::new(account).expect("should be a network account");
        let actual: BTreeSet<NoteScriptRoot> =
            network_account.allowed_notes().allowed_script_roots().iter().copied().collect();

        let mut expected = roots;
        expected.insert(crate::note::NetworkAccountConfigNote::script_root());
        assert_eq!(actual, expected);
    }

    #[test]
    fn private_account_is_rejected_even_with_allowlist() {
        let root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let account = build_account(AccountType::Private, BTreeSet::from_iter([root]));

        let id = account.id();
        let err = NetworkAccount::new(account).expect_err("private account must be rejected");
        assert!(matches!(
            err,
            NetworkAccountError::AccountNotPublic(account_id) if account_id == id
        ));
    }

    #[test]
    fn public_account_without_allowlist_is_not_a_network_account() {
        let account = AccountBuilder::new([0; 32])
            .account_type(AccountType::Public)
            .with_component(crate::account::auth::NoAuth)
            .with_component(BasicWallet)
            .build()
            .expect("account building should succeed");

        let err = NetworkAccount::new(account).expect_err("missing allowlist must be rejected");
        assert!(matches!(
            err,
            NetworkAccountError::NoteAllowlist(NetworkAccountNoteAllowlistError::SlotNotFound)
        ));
    }

    /// An account whose tx-script allowlist lacks the canonical expiration script root is not a
    /// network account: the network transaction builder could never service it.
    #[test]
    fn account_without_expiration_script_is_rejected() {
        let note_root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let account = AccountBuilder::new([0; 32])
            .account_type(AccountType::Public)
            .with_component(
                AuthNetworkAccount::with_allowed_notes(BTreeSet::from_iter([note_root]))
                    .expect("non-empty allowlist"),
            )
            .with_component(BasicWallet)
            .build()
            .expect("account building should succeed");

        let err = NetworkAccount::new(account).expect_err("missing expiration root");
        assert!(matches!(err, NetworkAccountError::ExpirationScriptNotAllowlisted));
    }

    /// `NetworkAccount::builder` produces an account that satisfies the network account
    /// specification and allowlists the canonical expiration tx script.
    #[test]
    fn builder_produces_network_account_with_expiration_script_allowlisted() {
        let note_root = NoteScriptRoot::from_array([1, 2, 3, 4]);

        let account = NetworkAccount::builder([0; 32], BTreeSet::from_iter([note_root]))
            .expect("non-empty allowlist")
            .with_component(BasicWallet)
            .build()
            .expect("account building should succeed");

        let network_account = NetworkAccount::new(account).expect("should be a network account");
        assert!(network_account.allows_tx_script(&ExpirationTransactionScript::script_root()));

        let other_root = TransactionScriptRoot::from_raw(Word::from([9u32, 10, 11, 12]));
        assert!(!network_account.allows_tx_script(&other_root));
    }
}
