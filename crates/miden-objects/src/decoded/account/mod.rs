//! Domain construction for decoded account messages.

#[cfg(test)]
pub(crate) mod test_utils;

mod core;
pub use core::{
    AccountCode,
    AccountHeader,
    AccountHeaderError,
    AccountId,
    AccountIdV1,
    AccountWitness,
};

mod storage;
pub use storage::{
    AccountStorageHeader,
    AccountStorageHeaderStorageSlot,
    StorageMapEntry,
    StorageSlotId,
};

mod patch;
pub use patch::{
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
