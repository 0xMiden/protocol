use miden_protocol::Word;
use miden_protocol::account::{StorageSlot, StorageSlotName};
use miden_protocol::utils::sync::LazyLock;

mod auth_controlled;
mod owner_controlled;

pub use auth_controlled::{AuthControlled, AuthControlledInitConfig};
pub use owner_controlled::{OwnerControlled, OwnerControlledInitConfig};

static POLICY_AUTHORITY_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("miden::standards::mint_policy_manager::policy_authority")
        .expect("storage slot name should be valid")
});

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintPolicyAuthority {
    AuthControlled = 0,
    OwnerControlled = 1,
}

impl From<MintPolicyAuthority> for Word {
    fn from(value: MintPolicyAuthority) -> Self {
        Word::from([value as u32, 0, 0, 0])
    }
}

impl From<MintPolicyAuthority> for StorageSlot {
    fn from(value: MintPolicyAuthority) -> Self {
        StorageSlot::with_value(policy_authority_slot_name().clone(), value.into())
    }
}

pub(super) fn policy_authority_slot_name() -> &'static StorageSlotName {
    &POLICY_AUTHORITY_SLOT_NAME
}
