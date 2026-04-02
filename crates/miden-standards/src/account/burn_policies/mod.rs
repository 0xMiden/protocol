use miden_protocol::Word;
use miden_protocol::account::{StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

mod auth_controlled;
mod owner_controlled;

pub use auth_controlled::{BurnAuthControlled, BurnAuthControlledConfig};
pub use owner_controlled::{BurnOwnerControlled, BurnOwnerControlledConfig};

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

static ACTIVE_POLICY_PROC_ROOT_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::active_policy_proc_root")
        .expect("storage slot name should be valid")
});

static ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::burn_policy_manager::allowed_policy_proc_roots")
        .expect("storage slot name should be valid")
});

/// Active / allowed policy root slot names shared by auth-controlled and owner-controlled
/// components.
fn active_policy_proc_root_slot_name() -> &'static StorageSlotName {
    &ACTIVE_POLICY_PROC_ROOT_SLOT_NAME
}

fn allowed_policy_proc_roots_slot_name() -> &'static StorageSlotName {
    &ALLOWED_POLICY_PROC_ROOTS_SLOT_NAME
}

/// Identifies which authority is allowed to manage the active burn policy for a faucet.
///
/// This value is stored in the policy authority slot so the account can distinguish whether burn
/// policy updates are governed by authentication component logic or by the account owner.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnPolicyAuthority {
    /// Burn policy changes are authorized by the account's authentication component logic.
    AuthControlled = 0,
    /// Burn policy changes are authorized by the external account owner.
    OwnerControlled = 1,
}

impl BurnPolicyAuthority {
    /// Returns the [`StorageSlotName`] containing the burn policy authority mode.
    pub fn slot() -> &'static StorageSlotName {
        &POLICY_AUTHORITY_SLOT_NAME
    }
}

impl From<BurnPolicyAuthority> for Word {
    fn from(value: BurnPolicyAuthority) -> Self {
        Word::from([value as u8, 0, 0, 0])
    }
}

impl From<BurnPolicyAuthority> for StorageSlot {
    fn from(value: BurnPolicyAuthority) -> Self {
        StorageSlot::with_value(BurnPolicyAuthority::slot().clone(), value.into())
    }
}
