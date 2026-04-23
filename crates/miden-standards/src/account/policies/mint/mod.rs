//! Mint policies and the mint policy manager.

mod allow_all;
pub mod manager;
pub mod owner_controlled;

pub use allow_all::AllowAll;

pub use super::PolicyAuthority;

/// The mint policy manager — kind-specific alias for the generic
/// [`super::PolicyManager`] instantiated with [`super::Mint`].
///
/// Kind-specific constructors (`auth_controlled`, `owner_controlled`) are defined in
/// [`manager`].
pub type PolicyManager = super::PolicyManager<super::Mint>;
