use miden_protocol::account::{Account, AccountId, AccountStorage};

use crate::account::auth::network_account::{
    NetworkAccountNoteAllowlist,
    NetworkAccountNoteAllowlistError,
};

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
///
/// The allowlist slot is the shared abstraction across every network-account component, so
/// off-chain services can identify a network account by inspecting its storage for this slot
/// without needing to know which specific component the account uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkAccount {
    account: Account,
    allowlist: NetworkAccountNoteAllowlist,
}

impl NetworkAccount {
    /// Attempts to construct a [`NetworkAccount`] from `account`.
    ///
    /// Returns an error if:
    /// - the account is not [`public`](Account::is_public), or
    /// - the account's storage does not contain a valid [`NetworkAccountNoteAllowlist`] slot (see
    ///   [`NetworkAccountNoteAllowlist::try_from`] for the exact storage-level checks).
    pub fn new(account: Account) -> Result<Self, NetworkAccountNoteAllowlistError> {
        if !account.is_public() {
            return Err(NetworkAccountNoteAllowlistError::AccountNotPublic(account.id()));
        }

        let allowlist = NetworkAccountNoteAllowlist::try_from(account.storage())?;

        Ok(Self { account, allowlist })
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
        &self.allowlist
    }
}

impl TryFrom<Account> for NetworkAccount {
    type Error = NetworkAccountNoteAllowlistError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        Self::new(account)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use miden_protocol::account::{AccountBuilder, AccountType};
    use miden_protocol::note::NoteScriptRoot;

    use super::*;
    use crate::account::auth::network_account::AuthNetworkAccount;
    use crate::account::wallets::BasicWallet;

    fn build_account(account_type: AccountType, roots: BTreeSet<NoteScriptRoot>) -> Account {
        AccountBuilder::new([0; 32])
            .account_type(account_type)
            .with_auth_component(
                AuthNetworkAccount::with_allowlist(roots).expect("non-empty allowlist"),
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
        assert_eq!(actual, roots);
    }

    #[test]
    fn private_account_is_rejected_even_with_allowlist() {
        let root = NoteScriptRoot::from_array([1, 2, 3, 4]);
        let account = build_account(AccountType::Private, BTreeSet::from_iter([root]));

        let id = account.id();
        let err = NetworkAccount::new(account).expect_err("private account must be rejected");
        assert!(matches!(
            err,
            NetworkAccountNoteAllowlistError::AccountNotPublic(account_id) if account_id == id
        ));
    }

    #[test]
    fn public_account_without_allowlist_is_not_a_network_account() {
        let account = AccountBuilder::new([0; 32])
            .account_type(AccountType::Public)
            .with_auth_component(crate::account::auth::NoAuth)
            .with_component(BasicWallet)
            .build()
            .expect("account building should succeed");

        let err = NetworkAccount::new(account).expect_err("missing allowlist must be rejected");
        assert!(matches!(err, NetworkAccountNoteAllowlistError::SlotNotFound));
    }
}
