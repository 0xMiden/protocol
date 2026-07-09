//! Fee handling for network accounts.
//!
//! Under the sponsorship fee model, a feature note stays entirely fee-unaware and its fee travels
//! in a separate [`NetworkSponsorshipNote`](crate::note::NetworkSponsorshipNote). The
//! [`FeeManager`] component holds the price list a network account charges, and exposes read-only
//! estimation over FPI so a sponsorship can be sized before the note it pays for exists.

mod fee_manager;
pub use fee_manager::{FeeManager, FeeScheduleEntry};
