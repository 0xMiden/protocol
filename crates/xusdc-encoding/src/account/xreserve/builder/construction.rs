//! Faucet-account CONSTRUCTION: the faucet-extension component type, the fixed-identity USDCx
//! faucet, the crate-root `Account` constructor, and [`XReserveStablecoinBuilder::build_account`].
//!
//! Split out of `builder/mod.rs` (which composes the component SET) so the two separable concerns —
//! composing the components vs. turning them into the deployable `Account` — live apart and each file
//! stays within the Rust file-size ceiling.

use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountType, StorageMap, StorageMapKey, StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{AssetAmount, AssetId, TokenSymbol};
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::errors::StorageMapError;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::Package;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::fees::FeePolicyManager;

use super::{
    XReserveStablecoinBuilder, XReserveStablecoinBuilderError, USDCX_DECIMALS, USDCX_TOKEN_SYMBOL,
};
use crate::xreserve::encoding::{CircleDomain, DepositNonce};

// CONSTANTS
// ================================================================================================

/// The metadata label the assembled `xreserve` component carries. It is a build-time label only —
/// the account's code commitment is over the procedure roots and its storage over the slot values,
/// neither of which depends on this string (the byte-identity suite proves it).
const XRESERVE_COMPONENT_LABEL: &str = "xusdc-xreserve";
const BURN_POLICY_COMPONENT_LABEL: &str = "xusdc-burn-policy";

/// The allowlist row the attestation check accepts (the MASM `ATTESTER_ENABLED_MARKER`).
const ATTESTER_ENABLED_MARKER: [u32; 4] = [1, 0, 0, 0];

/// The registry row the mint policy writes for a consumed nonce (the MASM `NONCE_USED_MARKER`).
const NONCE_USED_MARKER: [u32; 4] = [1, 0, 0, 0];

/// What the faucet adds on top of the stock fungible faucet, assembled at build time from
/// `asm/components/faucet_extension/`: the attestation mint policy and the attester allowlist
/// setter.
static FAUCET_EXTENSION_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    AccountComponentCode::from(
        Package::read_from_bytes_trusted(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/assets/components/xreserve-faucet-extension.masp"
        )))
        .expect("the shipped account-component package deserializes"),
    )
});

static BURN_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    AccountComponentCode::from(
        Package::read_from_bytes_trusted(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/assets/components/xreserve-faucet-burn-policy.masp"
        )))
        .expect("the shipped burn-policy package deserializes"),
    )
});

static DOMAIN_CONFIG_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::domain_config::domain")
        .expect("storage slot name should be valid")
});

/// The nonce registry the replay guard reads and the mint path writes.
static USED_NONCES_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::nonce_registry::used_nonces")
        .expect("storage slot name should be valid")
});

/// The attester allowlist: the attestation check reads it and the `set_attester` admin path writes
/// it, so the two co-own the same slot.
static XRESERVE_ATTESTERS_SLOT_NAME: LazyLock<StorageSlotName> = LazyLock::new(|| {
    StorageSlotName::new("xusdc::xreserve::attester_admin::xreserve_attesters")
        .expect("storage slot name should be valid")
});

/// The xUSDC faucet's extension of the stock [`FungibleFaucet`] component:
/// - the attestation-gated mint policy
/// - the attester administration
#[derive(Debug, Clone)]
pub struct XReserveFaucetExtension {
    domain: CircleDomain,
    attesters: StorageMap,
}

impl XReserveFaucetExtension {
    /// Instantiates a new [`XReserveFaucetExtension`] for `domain` with every key in `attesters`
    /// allowlisted under its [`PublicKey::to_commitment`], so the faucet accepts their
    /// attestations from its first block.
    ///
    /// # Errors
    ///
    /// [`StorageMapError::DuplicateKey`] if a key is listed twice.
    pub fn new(domain: CircleDomain, attesters: &[PublicKey]) -> Result<Self, StorageMapError> {
        let attesters = StorageMap::with_entries(attesters.iter().map(|key| {
            (
                StorageMapKey::new(key.to_commitment()),
                Word::from(ATTESTER_ENABLED_MARKER),
            )
        }))?;
        Ok(Self { domain, attesters })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the [`AccountComponentCode`] of this component.
    pub fn code() -> &'static AccountComponentCode {
        &FAUCET_EXTENSION_CODE
    }

    /// Returns the [`StorageSlotName`] holding the faucet's own Circle domain id.
    pub fn domain_config_slot() -> &'static StorageSlotName {
        &DOMAIN_CONFIG_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the consumed-nonce registry map.
    pub fn used_nonces_slot() -> &'static StorageSlotName {
        &USED_NONCES_SLOT_NAME
    }

    /// Returns the [`StorageSlotName`] of the attester allowlist map.
    pub fn xreserve_attesters_slot() -> &'static StorageSlotName {
        &XRESERVE_ATTESTERS_SLOT_NAME
    }
}

impl From<XReserveFaucetExtension> for AccountComponent {
    fn from(faucet_ext: XReserveFaucetExtension) -> Self {
        AccountComponent::new(
            FAUCET_EXTENSION_CODE.clone(),
            vec![
                StorageSlot::with_value(
                    XReserveFaucetExtension::domain_config_slot().clone(),
                    Word::from([faucet_ext.domain.as_u32(), 0, 0, 0]),
                ),
                StorageSlot::with_empty_map(XReserveFaucetExtension::used_nonces_slot().clone()),
                StorageSlot::with_map(
                    XReserveFaucetExtension::xreserve_attesters_slot().clone(),
                    faucet_ext.attesters,
                ),
            ],
            AccountComponentMetadata::new(XRESERVE_COMPONENT_LABEL),
        )
        .expect("the faucet extension binds with its three declared slots")
    }
}

impl XReserveStablecoinBuilder {
    /// Builds the burn policy component. It reads the minimum burn amount from the storage slot
    /// owned by `MinBurnAmount` and has no storage slots of its own.
    pub fn burn_policy_component() -> AccountComponent {
        AccountComponent::new(
            BURN_POLICY_CODE.clone(),
            vec![],
            AccountComponentMetadata::new(BURN_POLICY_COMPONENT_LABEL),
        )
        .expect("the burn policy binds with no storage slots")
    }

    /// Builds the final composed faucet [`Account`] from `init_seed`: [`Self::build_components`] plus
    /// the production keyless-network `AuthNetworkAccount` auth component ([`Self::auth_component`]),
    /// assembled as `AccountType::Public`, with asset
    /// callbacks enabled iff the composition installs the transfer-policy callback slots (it does:
    /// xUSDC is a policed asset).
    ///
    /// This entry is byte-identical to composing the components and auth component with the same
    /// seed.
    pub fn build_account(
        &self,
        init_seed: [u8; 32],
    ) -> Result<Account, XReserveStablecoinBuilderError> {
        let components = self.build_components()?;
        let mut builder = Account::builder(init_seed).account_type(AccountType::Public);
        for component in components {
            builder = builder.with_component(component);
        }
        builder = builder.with_components(Self::auth_component(
            self.fee_parameters.clone(),
            self.fee_asset_id,
        )?);
        builder
            .build()
            .map_err(XReserveStablecoinBuilderError::AccountComposition)
    }

    /// Builds the faucet for inclusion in a genesis block.
    /// The account is created with a nonce of one and its own ID as the fee asset. Consumed
    /// deposit nonces are recorded afterwards with [`record_used_nonces`].
    ///
    /// # Warning
    ///
    /// The returned account can only be added at genesis. With nonce one and no seed it cannot be
    /// deployed in a transaction.
    pub fn build_genesis_account(
        &self,
        init_seed: [u8; 32],
    ) -> Result<Account, XReserveStablecoinBuilderError> {
        let account = self.build_account(init_seed)?;
        let fee_asset_id = AssetId::new_fungible(account.id());
        let (id, vault, mut storage, code, _nonce, _seed) = account.into_parts();
        storage
            .set_item(
                FeePolicyManager::fee_asset_id_slot(),
                fee_asset_id.to_word(),
            )
            .map_err(XReserveStablecoinBuilderError::AccountComposition)?;
        Account::new(id, vault, storage, code, Felt::ONE, None)
            .map_err(XReserveStablecoinBuilderError::AccountComposition)
    }
}

/// Records every nonce in `used_nonces` as consumed in the genesis faucet `account` and returns
/// it in genesis form (nonce one, no seed). Recording a nonce twice is a no-op.
///
/// # Errors
///
/// [`XReserveStablecoinBuilderError::AccountComposition`] if `account` has no nonce registry
/// slot, i.e. it is not an xUSDC faucet.
///
/// # Warning
///
/// The returned account can only be added at genesis. With nonce one and no seed it cannot be
/// deployed in a transaction.
pub fn record_used_nonces(
    account: Account,
    used_nonces: &[DepositNonce],
) -> Result<Account, XReserveStablecoinBuilderError> {
    let (id, vault, mut storage, code, _nonce, _seed) = account.into_parts();
    for nonce in used_nonces {
        storage
            .set_map_item(
                XReserveFaucetExtension::used_nonces_slot(),
                nonce.to_storage_map_key(),
                Word::from(NONCE_USED_MARKER),
            )
            .map_err(XReserveStablecoinBuilderError::AccountComposition)?;
    }
    Account::new(id, vault, storage, code, Felt::ONE, None)
        .map_err(XReserveStablecoinBuilderError::AccountComposition)
}

/// Crate-root constructor for the final xUSDC faucet [`Account`]: builds the fixed-identity USDCx
/// faucet (`is_max_supply_mutable(true)` — the mutability invariant enforced BY CONSTRUCTION rather
/// than a runtime reject), then composes it into the attestation-gated keyless network account via
/// [`XReserveStablecoinBuilder`]. It is the single entry point that turns deploy parameters into the
/// deployable account, so account construction is traceable from the library root (the agglayer
/// `create_bridge_account` pattern). `init_seed` seeds the account id. The optional inputs (the
/// min-burn floor and the build-seeded attesters) keep their defaults here and are set through
/// [`XReserveStablecoinBuilder::builder`].
#[allow(clippy::too_many_arguments)]
pub fn build_faucet_account(
    init_seed: [u8; 32],
    token_supply: AssetAmount,
    owner: AccountId,
    attest_admin_holders: Vec<AccountId>,
    pauser_holders: Vec<AccountId>,
    unpauser_holders: Vec<AccountId>,
    blocklist_manager_holders: Vec<AccountId>,
    fee_parameters: FeeParameters,
    fee_asset_id: AssetId,
    domain: CircleDomain,
) -> Result<Account, XReserveStablecoinBuilderError> {
    XReserveStablecoinBuilder::builder()
        .token_supply(token_supply)
        .owner(owner)
        .attest_admin_holders(attest_admin_holders)
        .pauser_holders(pauser_holders)
        .unpauser_holders(unpauser_holders)
        .blocklist_manager_holders(blocklist_manager_holders)
        .fee_parameters(fee_parameters)
        .fee_asset_id(fee_asset_id)
        .domain(domain)
        .build()?
        .build_account(init_seed)
}

/// Builds the fixed-identity USDCx [`FungibleFaucet`]: name `USDCx`, symbol [`USDCX_TOKEN_SYMBOL`],
/// [`USDCX_DECIMALS`] decimals, the supply cap at [`AssetAmount::MAX`], and
/// `is_max_supply_mutable(true)` so the deployed `set_max_supply`
/// stays operable. The identity fields are constants (the `.expect`s are invariants); setting the
/// mutability flag here is what guarantees it by construction, replacing the removed runtime reject.
pub(super) fn build_usdcx_faucet(
    token_supply: AssetAmount,
) -> Result<FungibleFaucet, XReserveStablecoinBuilderError> {
    FungibleFaucet::builder()
        .name(TokenName::new("USDCx").expect("USDCx is a valid token name"))
        .symbol(TokenSymbol::new(USDCX_TOKEN_SYMBOL).expect("the USDCX symbol constant is valid"))
        .decimals(USDCX_DECIMALS)
        .max_supply(AssetAmount::MAX)
        .token_supply(token_supply)
        .is_max_supply_mutable(true)
        .build()
        .map_err(XReserveStablecoinBuilderError::FaucetComposition)
}
