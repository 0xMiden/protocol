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
//! variant value in its storage. The variant is never inferred from the number of storage items
//! the note carries, nor from the procedures the consuming account happens to expose: the first
//! overloads one number to both select the path and size the payload, and the second makes the
//! path depend on the account the note is consumed against rather than on what the note was
//! built for.
//!
//! A note adopting the convention:
//!
//! - Carries the variant as a single felt in its first storage item, so reading it requires neither
//!   the item count nor any other part of the layout.
//! - Numbers the variants contiguously from `0`.
//! - Asserts both that the variant is one it knows (`ERR_*_UNKNOWN_VARIANT`) and that the storage
//!   item count matches that variant (`ERR_*_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS`), which keeps the
//!   item count a length check rather than a second encoding of the variant.
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
