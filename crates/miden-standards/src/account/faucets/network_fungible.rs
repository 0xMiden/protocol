use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorage,
    AccountStorageMode,
    AccountType,
};

use super::FungibleFaucetError;
use crate::account::access::AccessControl;
use crate::account::auth::NoAuth;
use crate::account::components::network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::account::metadata::FungibleTokenMetadata;
use crate::account::policies::{
    BurnPolicyConfig,
    MintPolicyConfig,
    PolicyAuthority,
    TokenPolicyManager,
};
use crate::procedure_digest;

// NETWORK FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `mint_and_send` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_MINT_AND_SEND,
    NetworkFungibleFaucet::NAME,
    NetworkFungibleFaucet::MINT_PROC_NAME,
    network_fungible_faucet_library
);

// Initialize the digest of the `burn` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_BURN,
    NetworkFungibleFaucet::NAME,
    NetworkFungibleFaucet::BURN_PROC_NAME,
    network_fungible_faucet_library
);

/// An [`AccountComponent`] implementing a network fungible faucet.
///
/// It reexports the procedures from `miden::standards::faucets::network_fungible`. When linking
/// against this component, the `miden` library (i.e.
/// [`ProtocolLib`](miden_protocol::ProtocolLib)) must be available to the assembler which is the
/// case when using [`CodeBuilder`][builder]. The procedures of this component are:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `mint_and_send` and `burn` can only be called from note scripts. `mint_and_send` requires
/// authentication while `burn` is governed by the active burn policy (which defaults to
/// `allow_all`).
/// Thus, this component must be combined with a component providing authentication.
///
/// This component relies on [`crate::account::access::Ownable2Step`] for ownership checks in
/// `mint_and_send`. When building an account with this component,
/// [`crate::account::access::Ownable2Step`] must also be included.
///
/// This component depends on [`FungibleTokenMetadata`] being present in the account for storage
/// of token metadata. It has no storage slots of its own.
///
/// [builder]: crate::code_builder::CodeBuilder
pub struct NetworkFungibleFaucet;

impl NetworkFungibleFaucet {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The name of the component.
    pub const NAME: &'static str = "miden::standards::components::faucets::network_fungible_faucet";

    const MINT_PROC_NAME: &str = "mint_and_send";
    const BURN_PROC_NAME: &str = "burn";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `mint_and_send` account procedure.
    pub fn mint_and_send_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_MINT_AND_SEND
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_BURN
    }

    /// Checks that the account contains the network fungible faucet interface.
    fn try_from_interface(
        interface: AccountInterface,
        _storage: &AccountStorage,
    ) -> Result<Self, FungibleFaucetError> {
        if !interface
            .components()
            .contains(&AccountComponentInterface::NetworkFungibleFaucet)
        {
            return Err(FungibleFaucetError::MissingNetworkFungibleFaucetInterface);
        }

        Ok(NetworkFungibleFaucet)
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(Self::NAME, [AccountType::FungibleFaucet])
            .with_description("Network fungible faucet component for minting and burning tokens")
    }
}

impl From<NetworkFungibleFaucet> for AccountComponent {
    fn from(_network_faucet: NetworkFungibleFaucet) -> Self {
        let metadata = NetworkFungibleFaucet::component_metadata();

        AccountComponent::new(network_fungible_faucet_library(), vec![], metadata)
            .expect("network fungible faucet component should satisfy the requirements of a valid account component")
    }
}

impl TryFrom<Account> for NetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(&account);

        NetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

impl TryFrom<&Account> for NetworkFungibleFaucet {
    type Error = FungibleFaucetError;

    fn try_from(account: &Account) -> Result<Self, Self::Error> {
        let account_interface = AccountInterface::from_account(account);

        NetworkFungibleFaucet::try_from_interface(account_interface, account.storage())
    }
}

/// Creates a new faucet account with network fungible faucet interface and provided metadata
/// and access control.
///
/// The network faucet interface exposes two procedures:
/// - `mint_and_send`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `mint_and_send` and `burn` can only be called from note scripts. `mint_and_send` requires
/// authentication using the NoAuth scheme. `burn` does not require authentication and can be
/// called by anyone.
///
/// Network fungible faucets always use:
/// - [`AccountStorageMode::Network`] for storage
/// - [`NoAuth`] for authentication
///
/// The storage layout of the faucet account is documented on the [`NetworkFungibleFaucet`],
/// [`TokenPolicyManager`], and [`crate::account::access::Ownable2Step`] component types. The mint
/// and burn policy components produced alongside the manager (`MintOwnerOnly` and `BurnAllowAll`)
/// are storage-free. The faucet contains no additional storage slots for its auth ([`NoAuth`]).
///
/// Component dependency graph:
/// ```text
/// NetworkFungibleFaucet
/// └── TokenPolicyManager (owner-controlled)
///     ├── MintOwnerOnly  (active mint policy, requires Ownable2Step)
///     └── BurnAllowAll   (active burn policy)
/// ```
/// The manager only allows its initial policies by default. Custom faucets that want runtime
/// policy switching can register additional roots via
/// [`TokenPolicyManager::with_allowed_mint_policy`] /
/// [`TokenPolicyManager::with_allowed_burn_policy`] and install the matching policy components.
pub fn create_network_fungible_faucet(
    init_seed: [u8; 32],
    metadata: FungibleTokenMetadata,
    access_control: AccessControl,
) -> Result<Account, FungibleFaucetError> {
    // Validate that access_control is Ownable2Step, as this faucet depends on it.
    // When new variants are added to AccessControl, update this match to either support
    // them or return Err(FungibleFaucetError::UnsupportedAccessControl).
    match access_control {
        AccessControl::Ownable2Step { .. } => {},
        #[allow(unreachable_patterns)]
        _ => {
            return Err(FungibleFaucetError::UnsupportedAccessControl(
                "network fungible faucets require Ownable2Step access control".into(),
            ));
        },
    }

    let auth_component: AccountComponent = NoAuth::new().into();

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(auth_component)
        .with_component(metadata)
        .with_component(NetworkFungibleFaucet)
        .with_component(access_control)
        .with_components(TokenPolicyManager::new(
            PolicyAuthority::OwnerControlled,
            MintPolicyConfig::OwnerOnly,
            BurnPolicyConfig::AllowAll,
        ))
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::TokenSymbol;

    use super::*;
    use crate::account::access::Ownable2Step;
    use crate::account::metadata::{FungibleTokenMetadataBuilder, TokenName};

    #[test]
    fn test_create_network_fungible_faucet() {
        let init_seed = [7u8; 32];

        let owner = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );

        let metadata = FungibleTokenMetadataBuilder::new(
            TokenName::new("NET").expect("valid name"),
            TokenSymbol::new("NET").expect("valid symbol"),
            8u8,
            1_000u64,
        )
        .build()
        .expect("valid metadata");

        let account = create_network_fungible_faucet(
            init_seed,
            metadata,
            AccessControl::Ownable2Step { owner },
        )
        .expect("network faucet creation should succeed");

        let expected_owner_word = Ownable2Step::new(owner).to_word();
        assert_eq!(
            account.storage().get_item(Ownable2Step::slot_name()).unwrap(),
            expected_owner_word
        );

        let _faucet = NetworkFungibleFaucet::try_from(&account)
            .expect("network fungible faucet should be extractable from account");
    }
}
