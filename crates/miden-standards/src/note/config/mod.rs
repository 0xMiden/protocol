//! The standardized config notes: notes that carry a management action for the account that
//! consumes them.
//!
//! Each config note pairs one note script with a selector in the note's storage, dispatching to
//! the admin procedure of the component it manages. The action is fixed at note creation and
//! bound into the note commitment, so the authorized party is the note sender.
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
