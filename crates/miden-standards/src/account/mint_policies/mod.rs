use miden_protocol::Word;
use miden_protocol::account::component::{FeltSchema, SchemaType, StorageSlotSchema};
use miden_protocol::account::{StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

mod auth_controlled;
mod owner_controlled;

pub use auth_controlled::{MintAuthControlled, MintAuthControlledConfig};
pub use owner_controlled::{MintOwnerControlled, MintOwnerControlledConfig};

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

/// Active / allowed policy root slot names shared by auth-controlled and owner-controlled
/// components
fn active_policy_proc_root_slot_name() -> &'static StorageSlotName {
    &ACTIVE_POLICY_PROC_ROOT_SLOT_NAME
}

fn allowed_policy_proc_roots_slot_name() -> &'static StorageSlotName {
    &ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME
}

/// Shared storage layout for mint policy manager slots (auth- and owner-controlled components).
pub(super) fn active_policy_proc_root_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
    (
        ACTIVE_POLICY_PROC_ROOT_SLOT_NAME.clone(),
        StorageSlotSchema::value(
            "Active mint policy procedure root",
            [
                FeltSchema::felt("proc_root_0"),
                FeltSchema::felt("proc_root_1"),
                FeltSchema::felt("proc_root_2"),
                FeltSchema::felt("proc_root_3"),
            ],
        ),
    )
}

pub(super) fn allowed_policy_proc_roots_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
    (
        ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME.clone(),
        StorageSlotSchema::map(
            "Allowed mint policy procedure roots",
            SchemaType::native_word(),
            SchemaType::native_word(),
        ),
    )
}

pub(super) fn policy_authority_slot_schema() -> (StorageSlotName, StorageSlotSchema) {
    (
        POLICY_AUTHORITY_SLOT_NAME.clone(),
        StorageSlotSchema::value(
            "Mint policy authority",
            [
                FeltSchema::u8("mint_policy_authority"),
                FeltSchema::new_void(),
                FeltSchema::new_void(),
                FeltSchema::new_void(),
            ],
        ),
    )
}

/// Identifies which authority is allowed to manage the active mint policy for a faucet.
///
/// This value is stored in the policy authority slot so the account can distinguish whether mint
/// policy updates are governed by authentication component logic or by the account owner.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintPolicyAuthority {
    /// Mint policy changes are authorized by the account's authentication component logic.
    AuthControlled = 0,
    /// Mint policy changes are authorized by the external account owner.
    OwnerControlled = 1,
}

impl MintPolicyAuthority {
    /// Returns the [`StorageSlotName`] containing the mint policy authority mode.
    pub fn slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }
}

impl From<MintPolicyAuthority> for Word {
    fn from(value: MintPolicyAuthority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

impl From<MintPolicyAuthority> for StorageSlot {
    fn from(value: MintPolicyAuthority) -> Self {
        StorageSlot::with_value(MintPolicyAuthority::slot().clone(), value.into())
    }
}
