//! Domain construction for decoded account messages.

#[cfg(test)]
pub(crate) mod test_utils;

mod core;
pub use core::{
    Account,
    AccountCode,
    AccountCodeUpgrade,
    AccountHeader,
    AccountHeaderError,
    AccountId,
    AccountIdV1,
    AccountVersionError,
    AccountWitness,
};

mod storage;
pub use storage::{
    AccountStorage,
    AccountStorageHeader,
    AccountStorageHeaderStorageSlot,
    StorageMap,
    StorageMapEntry,
    StorageMapEntryError,
    StorageSlot,
    StorageSlotId,
};

mod patch;
pub use patch::{
    AccountCodePatch,
    AccountPatch,
    AccountPatchError,
    AccountStoragePatch,
    AccountUpdateDetails,
    AccountVaultPatch,
    AccountVaultPatchEntry,
    PrivateAccountUpdate,
    StorageMapPatch,
    StorageMapPatchEntries,
    StorageMapPatchError,
    StorageSlotPatch,
    StorageValuePatch,
    VaultPatchError,
};

mod partial;
pub use partial::{
    PartialAccount,
    PartialStorage,
    PartialStorageError,
    PartialStorageMap,
    PartialVault,
};
