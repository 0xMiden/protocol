//! The error type the faucet-account builder returns
//! ([`XReserveStablecoinBuilderError`]).
//!
//! The variants describe wiring the builder refuses to compose.

use core::fmt;

use miden_protocol::errors::{AccountError, StorageMapError};
use miden_standards::account::auth::NetworkAccountNoteAllowlistError;
use miden_standards::account::faucets::FungibleFaucetError;
use miden_standards::account::policies::{BurnPolicyError, MintPolicyError};
use miden_tx::NotePricingError;

use super::{
    ATTESTATION_MINT_POLICY_PROC_PATH, MIN_BURN_SIZE_FLOOR, XRESERVE_BURN_POLICY_PROC_PATH,
};

/// Errors returned while composing the xUSDC faucet account.
#[derive(Debug)]
pub enum XReserveStablecoinBuilderError {
    /// The fixed-identity USDCx [`FungibleFaucet`](miden_standards::account::faucets::FungibleFaucet)
    /// could not be constructed from the supplied supply parameters (the crate-root
    /// `build_faucet_account` path). Carries the stock faucet error.
    FaucetComposition(FungibleFaucetError),
    /// The production `AuthNetworkAccount` auth component could not be assembled from the note-script
    /// allowlist (the crate-root `build_account` path). Carries the stock allowlist error.
    NetworkAuth(NetworkAccountNoteAllowlistError),
    /// The composed faucet [`Account`](miden_protocol::account::Account) could not be built from the
    /// component set (the crate-root `build_account` path). Carries the stock account error.
    AccountComposition(AccountError),
    /// The xUSDC fee schedule could not be priced from the supplied network fee parameters.
    FeePricing(NotePricingError),
    /// The supplied `xreserve` component does not export the attestation mint policy procedure
    /// (assembly/path drift). Carries the expected path for diagnosis.
    AttestationPolicyProcNotFound,
    /// The burn policy component does not export the expected procedure.
    BurnPolicyProcNotFound,
    /// The requested `min_burn_amount` is below [`MIN_BURN_SIZE_FLOOR`]
    /// (= 1). The stock `MinBurnAmount` policy asserts only `min <= amount` and its stock setter
    /// accepts `0`, so a sub-floor seed would silently allow zero-amount burns;
    /// rejected at construction (the post-deploy twin is the `XReserveMinBurnAmountNote`
    /// factory's floor refusal). Carries the offending value.
    MinBurnSizeBelowFloor(u64),
    /// A `blocklist_manager_holders` member (a seeded `BLK_MANAGER` member) collides with
    /// `ADMIN`, `ATTEST_ADMIN`, `DOM_PAUSER` or `DOM_UNPAUSER`. The transfer-blocklist
    /// administrators must be external entities with no other faucet-admin capability.
    /// `collides_with` names the offending role.
    BlocklistManagerNotIsolated { collides_with: &'static str },
    /// A `pauser_holders` member collides with another role's holder. A pause holder must hold
    /// no other role, or a single signer gains a high-consequence power. `collides_with` names
    /// the offending role.
    PauserNotIsolated { collides_with: &'static str },
    /// A role lists the same member twice; each holder appears once per role.
    DuplicateRoleMember { role: &'static str },
    /// The build-seeded attester allowlist lists a key twice. Carries the storage-map error.
    AttesterAllowlist(StorageMapError),
    /// The mint-policy descriptor rejected its construction (`MintPolicy::custom` validates
    /// the root against the supplied companion components).
    MintPolicy(MintPolicyError),
    /// The burn-policy descriptor rejected its construction — the burn-slot twin of
    /// [`Self::MintPolicy`].
    BurnPolicy(BurnPolicyError),
}

impl fmt::Display for XReserveStablecoinBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FaucetComposition(_) => {
                write!(f, "the fixed-identity USDCx faucet could not be constructed")
            }
            Self::NetworkAuth(_) => write!(
                f,
                "the production network-account auth component could not be assembled"
            ),
            Self::AccountComposition(_) => {
                write!(f, "the composed faucet account could not be built")
            }
            Self::FeePricing(_) => write!(f, "the xUSDC fee schedule could not be priced"),
            Self::AttestationPolicyProcNotFound => write!(
                f,
                "the xreserve component does not export the attestation mint policy procedure \
                 '{ATTESTATION_MINT_POLICY_PROC_PATH}'"
            ),
            Self::BurnPolicyProcNotFound => write!(
                f,
                "the burn-policy component does not export the burn policy procedure \
                 '{XRESERVE_BURN_POLICY_PROC_PATH}'"
            ),
            Self::MinBurnSizeBelowFloor(value) => write!(
                f,
                "min_burn_amount {value} is below the construction floor \
                 {MIN_BURN_SIZE_FLOOR}"
            ),
            Self::BlocklistManagerNotIsolated { collides_with } => write!(
                f,
                "a BLK_MANAGER holder (transfer-blocklist administrator) must be an external entity \
                 with no other faucet-admin capability, but one collides with the {collides_with} — \
                 F4-reversal two-way capability isolation is violated"
            ),
            Self::PauserNotIsolated { collides_with } => write!(
                f,
                "a DOM_PAUSER holder must hold no other role, but one collides with {collides_with}"
            ),
            Self::DuplicateRoleMember { role } => {
                write!(f, "the {role} role lists the same member twice")
            }
            Self::AttesterAllowlist(_) => {
                write!(f, "the build-seeded attester allowlist lists a key twice")
            }
            Self::MintPolicy(_) => write!(f, "mint policy descriptor construction failed"),
            Self::BurnPolicy(_) => write!(f, "burn policy descriptor construction failed"),
        }
    }
}

impl core::error::Error for XReserveStablecoinBuilderError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::MintPolicy(source) => Some(source),
            Self::BurnPolicy(source) => Some(source),
            Self::FaucetComposition(source) => Some(source),
            Self::NetworkAuth(source) => Some(source),
            Self::AccountComposition(source) => Some(source),
            Self::FeePricing(source) => Some(source),
            Self::AttesterAllowlist(source) => Some(source),
            _ => None,
        }
    }
}

impl From<MintPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: MintPolicyError) -> Self {
        Self::MintPolicy(source)
    }
}

impl From<BurnPolicyError> for XReserveStablecoinBuilderError {
    fn from(source: BurnPolicyError) -> Self {
        Self::BurnPolicy(source)
    }
}

impl From<NetworkAccountNoteAllowlistError> for XReserveStablecoinBuilderError {
    fn from(source: NetworkAccountNoteAllowlistError) -> Self {
        Self::NetworkAuth(source)
    }
}

impl From<NotePricingError> for XReserveStablecoinBuilderError {
    fn from(source: NotePricingError) -> Self {
        Self::FeePricing(source)
    }
}
