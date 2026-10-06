//! The standardized config notes: notes that carry a management action for the account that
//! consumes them.
//!
//! Each config note pairs one note script with a variant in its storage, dispatching to
//! the admin procedure of the component it manages. The action is fixed at note creation and
//! bound into the note commitment, so the authorized party is the note sender.
//!
//! # Note variant
//!
//! A standard note that has more than one code path reads which one to take from a dedicated
//! variant value in its storage: a single felt, fixed when the note is created and bound into the
//! note commitment along with the rest of the storage.
//!
//! A note adopting the convention:
//!
//! - Numbers the variants contiguously from `0`.
//! - Asserts both that the variant is one it knows (`ERR_*_UNKNOWN_VARIANT`) and that the storage
//!   item count matches that variant (`ERR_*_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS`).
//!
//! # Note type
//!
//! The config note scripts require a public note, so the management action a config note carries
//! cannot be dispatched from a hand-crafted private note with the same script and storage. The
//! requirement holds at every layer: the builders always produce
//! [`NoteType::Public`](miden_protocol::note::NoteType::Public) notes, network execution rejects
//! a non-public note ([`AccountTargetNetworkNote`](crate::note::AccountTargetNetworkNote)), and
//! each script asserts it before dispatching. Authorization is separate and unaffected: the
//! called procedures authorize the note sender, which the kernel pins to the account that created
//! the note.

mod allowlist_config;
pub use allowlist_config::{AllowlistConfig, AllowlistConfigNote};

mod blocklist_config;
pub use blocklist_config::{BlocklistConfig, BlocklistConfigNote};

mod constant_fee_policy_config;
pub use constant_fee_policy_config::ConstantFeePolicyConfigNote;

mod faucet_metadata_config;
pub use faucet_metadata_config::{FaucetMetadataConfig, FaucetMetadataConfigNote};

mod faucet_policy_config;
pub use faucet_policy_config::{FaucetPolicyConfig, FaucetPolicyConfigNote};

mod min_burn_amount_config;
pub use min_burn_amount_config::MinBurnAmountConfigNote;

mod network_account_config;
pub use network_account_config::{NetworkAccountConfig, NetworkAccountConfigNote};

mod owner_config;
pub use owner_config::{OwnerConfig, OwnerConfigNote};

mod pause_config;
pub use pause_config::{PauseConfig, PauseConfigNote};

mod rbac_config;
pub use rbac_config::{RbacConfig, RbacConfigNote};
