//! Burn policies and the burn policy manager.

mod allow_all;
pub mod manager;
pub mod owner_controlled;

pub use allow_all::AllowAll;

pub use super::PolicyAuthority;

/// The burn policy manager — kind-specific alias for the generic
/// [`super::PolicyManager`] instantiated with [`super::Burn`].
///
/// Kind-specific constructors (`auth_controlled`, `owner_controlled`) are defined in
/// [`manager`].
pub type PolicyManager = super::PolicyManager<super::Burn>;
