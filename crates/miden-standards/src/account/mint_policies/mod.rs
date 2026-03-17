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
        Word::from([value as u32, 0, 0, 0])
    }
}

impl From<MintPolicyAuthority> for StorageSlot {
    fn from(value: MintPolicyAuthority) -> Self {
        StorageSlot::with_value(MintPolicyAuthority::slot().clone(), value.into())
    }
}
