use alloc::string::ToString;

use miden_core::utils::{Deserializable, Serializable};
use miden_core::{Felt, ZERO};

use super::{Account, AccountCode, AccountId, PartialStorage};
use crate::Word;
use crate::account::{hash_account, validate_account_seed};
use crate::asset::PartialVault;
use crate::errors::AccountError;
use crate::utils::serde::DeserializationError;

/// A partial representation of an account.
///
/// A partial account is used as inputs to the transaction kernel and contains only the essential
/// data needed for verification and transaction processing without requiring the full account
/// state.
///
/// For new accounts, the partial storage must be the full initial account storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialAccount {
    /// The ID for the partial account
    id: AccountId,
    /// Partial representation of the account's vault, containing the vault root and necessary
    /// proof information for asset verification
    partial_vault: PartialVault,
    /// Partial representation of the account's storage, containing the storage commitment and
    /// proofs for specific storage slots that need to be accessed
    partial_storage: PartialStorage,
    /// Account code
    code: AccountCode,
    /// The current transaction nonce of the account
    nonce: Felt,
    /// The seed of the account ID, if any.
    seed: Option<Word>,
}

impl PartialAccount {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new [`PartialAccount`] with the provided account parts and seed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - an account seed is provided but the account's nonce indicates the account already exists.
    /// - an account seed is not provided but the account's nonce indicates the account is new.
    /// - an account seed is provided but the account ID derived from it is invalid or does not
    ///   match the provided ID.
    pub fn new(
        id: AccountId,
        nonce: Felt,
        code: AccountCode,
        partial_storage: PartialStorage,
        partial_vault: PartialVault,
        seed: Option<Word>,
    ) -> Result<Self, AccountError> {
        validate_account_seed(id, code.commitment(), partial_storage.commitment(), seed, nonce)?;

        let account = Self {
            id,
            nonce,
            code,
            partial_storage,
            partial_vault,
            seed,
        };

        Ok(account)
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account's unique identifier.
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Returns the account's current nonce value.
    pub fn nonce(&self) -> Felt {
        self.nonce
    }

    /// Returns a reference to the account code.
    pub fn code(&self) -> &AccountCode {
        &self.code
    }

    /// Returns a reference to the partial storage representation of the account.
    pub fn storage(&self) -> &PartialStorage {
        &self.partial_storage
    }

    /// Returns a reference to the partial vault representation of the account.
    pub fn vault(&self) -> &PartialVault {
        &self.partial_vault
    }

    /// Returns the seed of the account's ID if the account is new.
    ///
    /// That is, if [`PartialAccount::is_new`] returns `true`, the seed will be `Some`.
    pub fn seed(&self) -> Option<Word> {
        self.seed
    }

    /// Returns `true` if the account is new, `false` otherwise.
    ///
    /// An account is considered new if the account's nonce is zero and it hasn't been registered on
    /// chain yet.
    pub fn is_new(&self) -> bool {
        self.nonce == ZERO
    }

    /// Returns the commitment of this account.
    ///
    /// The commitment of an account is computed as:
    ///
    /// ```text
    /// hash(id, nonce, vault_root, storage_commitment, code_commitment).
    /// ```
    pub fn commitment(&self) -> Word {
        hash_account(
            self.id,
            self.nonce,
            self.vault().root(),
            self.storage().commitment(),
            self.code().commitment(),
        )
    }

    /// Returns the commitment of this account as used for the initial account state commitment in
    /// transaction proofs.
    ///
    /// For existing accounts, this is exactly the same as [Account::commitment()], however, for new
    /// accounts this value is set to [`Word::empty`]. This is because when a transaction is
    /// executed against a new account, public input for the initial account state is set to
    /// [`Word::empty`] to distinguish new accounts from existing accounts. The actual
    /// commitment of the initial account state (and the initial state itself), are provided to
    /// the VM via the advice provider.
    pub fn initial_commitment(&self) -> Word {
        if self.is_new() {
            Word::empty()
        } else {
            self.commitment()
        }
    }

    /// Returns `true` if the full state of the account is public on chain, and `false` otherwise.
    pub fn has_public_state(&self) -> bool {
        self.id.has_public_state()
    }

    /// Consumes self and returns the underlying parts of the partial account.
    pub fn into_parts(
        self,
    ) -> (AccountId, PartialVault, PartialStorage, AccountCode, Felt, Option<Word>) {
        (
            self.id,
            self.partial_vault,
            self.partial_storage,
            self.code,
            self.nonce,
            self.seed,
        )
    }
}

impl From<&Account> for PartialAccount {
    /// Constructs a [`PartialAccount`] from the provided account.
    ///
    /// The behavior is different whether the [`Account::is_new`] or not:
    /// - For new accounts, the storage is tracked in full. This is because transactions that create
    ///   accounts need the full state.
    /// - For existing accounts, the storage is tracked minimally, i.e. the minimal necessary data
    ///   is included.
    ///
    /// Because new accounts always have empty vaults, in both cases, the asset vault is a minimal
    /// representation.
    ///
    /// For precise control over how an account is converted to a partial account, use
    /// [`PartialAccount::new`].
    fn from(account: &Account) -> Self {
        let partial_storage = if account.is_new() {
            // This is somewhat expensive, but it allows us to do this conversion from &Account and
            // it penalizes only the rare case (new accounts).
            PartialStorage::new_full(account.storage.clone())
        } else {
            PartialStorage::new_minimal(account.storage())
        };

        Self::new(
            account.id(),
            account.nonce(),
            account.code().clone(),
            partial_storage,
            PartialVault::new_minimal(account.vault()),
            account.seed(),
        )
        .expect("account should ensure that seed is valid for account")
    }
}

impl Serializable for PartialAccount {
    fn write_into<W: miden_core::utils::ByteWriter>(&self, target: &mut W) {
        target.write(self.id);
        target.write(self.nonce);
        target.write(&self.code);
        target.write(&self.partial_storage);
        target.write(&self.partial_vault);
        target.write(self.seed);
    }
}

impl Deserializable for PartialAccount {
    fn read_from<R: miden_core::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_processor::DeserializationError> {
        let account_id = source.read()?;
        let nonce = source.read()?;
        let account_code = source.read()?;
        let partial_storage = source.read()?;
        let partial_vault = source.read()?;
        let seed: Option<Word> = source.read()?;

        PartialAccount::new(account_id, nonce, account_code, partial_storage, partial_vault, seed)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}
