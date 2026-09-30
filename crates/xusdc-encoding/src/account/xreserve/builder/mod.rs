//! `XReserveStablecoinBuilder` — the faucet account composition for the xUSDC faucet.
//! The mint path is the STOCK
//! `FungibleFaucet::mint_and_send` gated by the custom **attestation mint policy**
//! (`xreserve::mint_policy::check_policy` — the ENTIRE attestation pipeline lives in
//! the policy dispatch), so every supply increase passes the attestation gate — the
//! faucet's core mint-security invariant.
//!
//! Composes the `FungibleFaucet`, the attestation mint policy and `set_attester` extension,
//! a `TokenPolicyManager` whose burn policy checks required attachments and the minimum amount
//! stored by [`MinBurnAmount`], plus the stock [`PausableManager`], [`BlocklistManager`],
//! [`ConstantFeeManager`] and [`UpgradeManager`].
//! The RBAC seed holds five roles: `ADMIN`, `ATTEST_ADMIN`, `DOM_PAUSER`, `DOM_UNPAUSER` and
//! `BLK_MANAGER`. Every role is administered directly by `ADMIN`; there is no ownership component.
//! The standard role-action note rotates membership and can change role administration at runtime.
//!
//! [`XReserveAdminAuthority`] maps `pause` to `DOM_PAUSER`, `unpause` to `DOM_UNPAUSER`,
//! `set_attester` to `ATTEST_ADMIN`, and block/unblock to `BLK_MANAGER`. Other authority-gated
//! procedures, including `set_note_fee`, resolve to `ADMIN`. Pause and blocklist storage belong
//! to the base `Pausable` and `BasicBlocklist` companions; their managers add no storage.
//!
//! Fee administration uses a standard
//! [`BasicConstantFeePolicy`](miden_standards::account::fees::BasicConstantFeePolicy) constructed
//! from the network fee parameters and the xUSDC note-cost table.
//!
//! Domain config is entirely BUILD-SEEDED: `domain` is a required builder input written into its
//! declared slot at composition time. The faucet identifier has no slot — it is the account's own
//! id, which the mint path derives on chain, so the composed faucet is mint-ready when it exists.
//! The attester allowlist can be build-seeded the same way: the optional `attesters` input
//! allowlists keys at composition time, so their attestations mint without a `set_attester` note.

use bon::bon;
use miden_protocol::account::{AccountComponent, AccountId, RoleSymbol};
use miden_protocol::asset::{AssetAmount, AssetId};
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_standards::account::access::{
    Pausable, PausableManager, RoleBasedAccessControl, RoleConfig,
};
use miden_standards::account::faucets::FungibleFaucet;
use miden_standards::account::fees::ConstantFeeManager;
use miden_standards::account::policies::{
    BlocklistManager, BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager, TransferPolicy,
};
use miden_standards::account::upgrade::UpgradeManager;

use crate::account::xreserve::XReserveAdminAuthority;
use crate::xreserve::encoding::CircleDomain;

mod construction;
mod error;
mod network_auth;

use construction::build_usdcx_faucet;
pub use construction::{build_faucet_account, record_used_nonces, XReserveFaucetExtension};
pub use error::XReserveStablecoinBuilderError;

/// Dedicated role symbols mapped to attester administration, pause and unpause by
/// [`XReserveAdminAuthority`]. All role administration resolves directly to `ADMIN`.
pub const DOM_PAUSER_ROLE: &str = "DOM_PAUSER";
pub const ATTEST_ADMIN_ROLE: &str = "ATTEST_ADMIN";
pub const DOM_UNPAUSER_ROLE: &str = "DOM_UNPAUSER";

/// The dedicated blocklist-administration RoleSymbol this faucet seeds under the ratified
/// transfer-blocklist decision: `BLK_MANAGER` is held by an EXTERNAL entity that
/// manages the transfer blocklist for Miden and has NO other admin capability (capability isolation
/// is two-way — the holder can ONLY block/unblock, and the administrator, lacking the role, cannot). The
/// stock `BlocklistManager`'s `block_account` / `unblock_account` roots are assigned this symbol by
/// [`XReserveAdminAuthority`], which is what keeps the capability off the administrator — the
/// owner-gated `BlocklistOwnerControlled` variant is the wrong identity and is not installed. Its
/// admin is left unset → resolves to the built-in `ADMIN`, so Miden rotates
/// or revokes the external entity through the allowlisted standard role-action note —
/// no new rotation machinery. `BLK_MANAGER` is seeded role id 4.
pub const BLK_MANAGER_ROLE: &str = "BLK_MANAGER";

/// Path of the attestation mint policy's `check_policy` procedure as the faucet component EXPORTS
/// it. The procedure is defined in the library's `mint_policy` module; the component re-exports it
/// under its own namespace, and it is that re-export the account installs and resolves by.
pub const ATTESTATION_MINT_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_extension::check_policy";

/// Path of the attester setter exported by the shipped faucet extension.
pub const XRESERVE_SET_ATTESTER_PROC_PATH: &str =
    "xreserve::components::faucet_extension::set_attester";

/// Path of the procedure exported by the burn policy component.
pub const XRESERVE_BURN_POLICY_PROC_PATH: &str =
    "xreserve::components::faucet_burn_policy::check_burn_policy";

/// The smallest admissible `min_burn_amount` (the zero floor). The stock [`MinBurnAmount`]
/// policy
/// asserts `min <= amount` ONLY (its authority-gated stock setter even accepts `0`), so the
/// zero-burn reject is enforced at note-building time: the builder rejects a floor below this at
/// construction, and the [`XReserveMinBurnAmountNote`](crate::note::xreserve_admin::XReserveMinBurnAmountNote)
/// factory refuses a sub-floor value before assembling the standard config note.
pub const MIN_BURN_SIZE_FLOOR: u64 = 1;

/// The shipped on-chain `TokenSymbol` guard constant (token config). The token's identity is
/// **USDCx** — a DISTINCT identity from the "xUSDC" working label;
/// the two must not be confused.
pub const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// The spec-mandated token decimals (`token_config` decimals = 6; a Circle requirement of six
/// decimal places — the amount reducer scales to 6dp, so a mismatched faucet would silently
/// mis-scale every minted amount).
pub const USDCX_DECIMALS: u8 = 6;

/// Composes the xUSDC faucet account: `FungibleFaucet` + the assembled `xreserve` library
/// component (attestation mint policy, admin procs) + a `TokenPolicyManager`
/// with the attestation mint policy and a burn policy that checks the required attachments
/// and the minimum amount stored by [`MinBurnAmount`], plus [`PausableManager`], [`BlocklistManager`], and
/// [`ConstantFeeManager`] components + a seeded `RoleBasedAccessControl` governed by
/// [`XReserveAdminAuthority`]'s `Authority::RbacControlled`.
///
/// Construct with the generated [`Self::builder`] (the faucet supply parameters, the `owner` and
/// role holders, the network fee parameters, and the build-seeded domain; the
/// min-burn floor and the build-seeded attesters are the optional inputs), then call
/// [`XReserveStablecoinBuilder::build_components`] (or the crate-root `build_faucet_account` /
/// [`Self::build_account`] for the finished `Account`).
#[derive(Debug)]
pub struct XReserveStablecoinBuilder {
    faucet: FungibleFaucet,
    /// The administrator: seeded as the sole member of the built-in `ADMIN` role, which is what
    /// gates every unmapped authority-gated procedure (the
    /// stock `set_min_burn_amount` / stock `set_max_supply` / the policy setters) under
    /// `Authority::RbacControlled`. It is the account's ONLY authority handle; rotating it is a
    /// grant and a revoke of `ADMIN` through the standard role-action note.
    owner: AccountId,
    /// The seeded `ATTEST_ADMIN` role members, authorized to call `set_attester`. May be empty:
    /// the role is then populated later through the standard role-action note.
    attest_admin_holders: Vec<AccountId>,
    /// The seeded `DOM_PAUSER` role members, authorized to pause the faucet.
    pauser_holders: Vec<AccountId>,
    /// The seeded `DOM_UNPAUSER` role members, authorized to unpause the faucet.
    unpauser_holders: Vec<AccountId>,
    /// The seeded `BLK_MANAGER` role members — the EXTERNAL entities that administer the transfer
    /// blocklist (block/unblock) and hold NO other admin capability. Their concrete
    /// account ids are supplied at deploy time; the built-in `ADMIN` rotates/revokes them via
    /// the standard role-action note.
    blocklist_manager_holders: Vec<AccountId>,
    /// Parameters used to price notes.
    fee_parameters: FeeParameters,
    /// The network fee asset the fee policies charge in.
    fee_asset_id: AssetId,
    /// The minimum burn amount stored by [`MinBurnAmount`]. Defaults to [`MIN_BURN_SIZE_FLOOR`]
    /// and is validated at construction.
    min_burn_amount: AssetAmount,
    /// The composed faucet extension.
    faucet_extension: XReserveFaucetExtension,
}

#[bon]
impl XReserveStablecoinBuilder {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a builder from the initial `token_supply`, the
    /// `owner` (the seeded `ADMIN` member that gates every unmapped authority-gated procedure), the
    /// `attest_admin_holder`, `pauser_holder` and `unpauser_holder` seeded as the sole members of
    /// `ATTEST_ADMIN`, `DOM_PAUSER` and `DOM_UNPAUSER`, and the
    /// `blocklist_manager_holder` seeded as the sole member of `BLK_MANAGER` (the external
    /// transfer-blocklist administrator), the network `fee_parameters` and `fee_asset_id`, plus the BUILD-SEEDED
    /// `domain`. The domain is required because a faucet without it would ship a domain
    /// compare that reads an empty slot. `attesters` (default empty) are allowlisted at
    /// composition time.
    ///
    /// The faucet is NOT a parameter: it has a fixed identity — name `USDCx`, symbol
    /// [`USDCX_TOKEN_SYMBOL`], [`USDCX_DECIMALS`] decimals, the supply cap at [`AssetAmount::MAX`],
    /// and `is_max_supply_mutable(true)` — so the
    /// builder BUILDS it here from `token_supply`, and the cap, the mutability invariant, the
    /// decimals and the symbol are guaranteed BY CONSTRUCTION. There is no way to hand the
    /// builder an immutable or mis-configured faucet. The `xreserve` component is likewise not a
    /// parameter — there is exactly one valid value (the shipped MASM), so the builder assembles it
    /// via [`XReserveFaucetExtension`]. The active mint and burn policies are fixed by the
    /// composition. The burn policy reads `min_burn_amount` from [`MinBurnAmount`]; this builder
    /// input defaults to [`MIN_BURN_SIZE_FLOOR`].
    ///
    /// # Errors
    ///
    /// [`XReserveStablecoinBuilderError::FaucetComposition`] if the supply parameters do not form a
    /// valid `FungibleFaucet`;
    /// [`XReserveStablecoinBuilderError::MinBurnSizeBelowFloor`] if `min_burn_amount` is below
    /// [`MIN_BURN_SIZE_FLOOR`] (the zero-floor invariant);
    /// [`XReserveStablecoinBuilderError::AttesterAllowlist`] if a key in `attesters` is listed
    /// twice.
    #[builder]
    pub fn new(
        token_supply: AssetAmount,
        owner: AccountId,
        attest_admin_holders: Vec<AccountId>,
        pauser_holders: Vec<AccountId>,
        unpauser_holders: Vec<AccountId>,
        blocklist_manager_holders: Vec<AccountId>,
        fee_parameters: FeeParameters,
        fee_asset_id: AssetId,
        domain: CircleDomain,
        #[builder(default)] attesters: Vec<PublicKey>,
        min_burn_amount: Option<AssetAmount>,
    ) -> Result<Self, XReserveStablecoinBuilderError> {
        let min_burn_amount = min_burn_amount.unwrap_or(
            AssetAmount::new(MIN_BURN_SIZE_FLOOR)
                .expect("the shipped burn floor is a valid asset amount"),
        );
        if min_burn_amount.as_u64() < MIN_BURN_SIZE_FLOOR {
            return Err(XReserveStablecoinBuilderError::MinBurnSizeBelowFloor(
                min_burn_amount.as_u64(),
            ));
        }
        let faucet_extension = XReserveFaucetExtension::new(domain, &attesters)
            .map_err(XReserveStablecoinBuilderError::AttesterAllowlist)?;
        for (role, members) in [
            ("ATTEST_ADMIN", &attest_admin_holders),
            ("DOM_PAUSER", &pauser_holders),
            ("DOM_UNPAUSER", &unpauser_holders),
            ("BLK_MANAGER", &blocklist_manager_holders),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            if !members.iter().all(|member| seen.insert(member)) {
                return Err(XReserveStablecoinBuilderError::DuplicateRoleMember { role });
            }
        }
        Ok(Self {
            faucet: build_usdcx_faucet(token_supply)?,
            owner,
            attest_admin_holders,
            pauser_holders,
            unpauser_holders,
            blocklist_manager_holders,
            fee_parameters,
            fee_asset_id,
            min_burn_amount,
            faucet_extension,
        })
    }
}

impl XReserveStablecoinBuilder {
    // BUILD / COMPOSE
    // --------------------------------------------------------------------------------------------

    /// Production composition: seeds the build-time domain,
    /// then composes the account components. The
    /// faucet's `max_supply` mutability is guaranteed by construction (the crate-root
    /// [`Self::build_account`] path builds the faucet `is_max_supply_mutable(true)`), so there is no
    /// runtime mutability reject. Public for the integration suite, which composes
    /// these components under a TEST auth account; [`Self::build_account`] is the production path.
    pub fn build_components(
        &self,
    ) -> Result<Vec<AccountComponent>, XReserveStablecoinBuilderError> {
        let overlaps = |left: &[AccountId], right: &[AccountId]| {
            left.iter().any(|member| right.contains(member))
        };
        let owner_holders = [self.owner];
        // No BLK_MANAGER member may hold any other role.
        for (collides_with, holders) in [
            ("ADMIN", owner_holders.as_slice()),
            ("ATTEST_ADMIN", &self.attest_admin_holders),
            ("DOM_PAUSER", &self.pauser_holders),
            ("DOM_UNPAUSER", &self.unpauser_holders),
        ] {
            if overlaps(&self.blocklist_manager_holders, holders) {
                return Err(
                    XReserveStablecoinBuilderError::BlocklistManagerNotIsolated { collides_with },
                );
            }
        }
        // No DOM_PAUSER member may hold another role; BLK_MANAGER collisions were checked above.
        for (collides_with, holders) in [
            ("ADMIN", owner_holders.as_slice()),
            ("ATTEST_ADMIN", &self.attest_admin_holders),
            ("DOM_UNPAUSER", &self.unpauser_holders),
        ] {
            if overlaps(&self.pauser_holders, holders) {
                return Err(XReserveStablecoinBuilderError::PauserNotIsolated { collides_with });
            }
        }
        let xreserve_component = AccountComponent::from(self.faucet_extension.clone());
        let burn_policy_component = Self::burn_policy_component();
        let burn_root = burn_policy_component
            .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
            .ok_or(XReserveStablecoinBuilderError::BurnPolicyProcNotFound)?;

        let manager = TokenPolicyManager::builder()
            .active_mint_policy(
                MintPolicy::custom(
                    xreserve_component
                        .get_procedure_root_by_path(ATTESTATION_MINT_POLICY_PROC_PATH)
                        .ok_or(XReserveStablecoinBuilderError::AttestationPolicyProcNotFound)?,
                    [xreserve_component],
                )
                .map_err(XReserveStablecoinBuilderError::MintPolicy)?,
            )
            .active_burn_policy(BurnPolicy::custom(
                burn_root,
                [
                    burn_policy_component,
                    MinBurnAmount::new(self.min_burn_amount).into(),
                ],
            )?)
            .active_send_policy(TransferPolicy::empty_basic_blocklist())
            .active_receive_policy(TransferPolicy::empty_basic_blocklist())
            .build();

        let mut components = Vec::new();
        components.push(self.faucet.clone().into());
        components.push(Pausable::unpaused().into());
        components.extend(manager);
        components.push(PausableManager.into());
        components.push(BlocklistManager.into());
        components.push(ConstantFeeManager::for_basic_constant_fee_policy().into());
        components.push(UpgradeManager.into());
        components.push(seeded_dom_roles_rbac(
            self.owner,
            &self.attest_admin_holders,
            &self.pauser_holders,
            &self.unpauser_holders,
            &self.blocklist_manager_holders,
        ));
        components.push(XReserveAdminAuthority::new().into());
        Ok(components)
    }
}

/// Seeds `ADMIN` with its sole owner and the four operational roles with their configured
/// members (possibly none) and direct `ADMIN` administration.
/// Construction failures are invariants, so this mirrors the stock `.expect()` pattern.
fn seeded_dom_roles_rbac(
    owner: AccountId,
    attest_admin_holders: &[AccountId],
    pauser_holders: &[AccountId],
    unpauser_holders: &[AccountId],
    blocklist_manager_holders: &[AccountId],
) -> AccountComponent {
    let pauser =
        RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol (≤12)");
    let attest_admin = RoleSymbol::new(ATTEST_ADMIN_ROLE)
        .expect("ATTEST_ADMIN is a fixed valid role symbol (≤12)");
    let unpauser = RoleSymbol::new(DOM_UNPAUSER_ROLE)
        .expect("DOM_UNPAUSER is a fixed valid role symbol (≤12)");
    let blk_manager =
        RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol (≤12)");
    let admin = RoleBasedAccessControl::admin_role();

    // The stock RBAC builder rejects a zero-member role declaration, so an empty role is simply
    // not declared: it materializes when its first member is granted through the standard
    // role-action note, and its administration resolves to the built-in `ADMIN` either way.
    let mut builder = RoleBasedAccessControl::builder();
    for (role, holders) in [
        (pauser, pauser_holders),
        (attest_admin, attest_admin_holders),
        (unpauser, unpauser_holders),
        (blk_manager, blocklist_manager_holders),
    ] {
        if !holders.is_empty() {
            builder = builder.role(RoleConfig::new(role).with_members(holders.iter().copied()));
        }
    }
    builder
        .role(RoleConfig::new(admin).with_member(owner))
        .build()
        .expect("the seeded DOM-roles RBAC configuration should be valid")
        .into()
}
