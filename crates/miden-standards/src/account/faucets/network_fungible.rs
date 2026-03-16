use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountStorageMode,
    AccountType,
};

use super::{FungibleFaucetError, FungibleTokenMetadata};
use crate::account::access::AccessControl;
use crate::account::auth::NoAuth;
use crate::account::components::network_fungible_faucet_library;
use crate::account::interface::{AccountComponentInterface, AccountInterface, AccountInterfaceExt};
use crate::procedure_digest;

// NETWORK FUNGIBLE FAUCET ACCOUNT COMPONENT
// ================================================================================================

// Initialize the digest of the `distribute` procedure of the Network Fungible Faucet only once.
procedure_digest!(
    NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE,
    NetworkFungibleFaucet::NAME,
    NetworkFungibleFaucet::DISTRIBUTE_PROC_NAME,
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
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication while `burn` does not require authentication and can be called by anyone.
/// Thus, this component must be combined with a component providing authentication.
///
/// This component relies on [`crate::account::access::Ownable2Step`] for ownership checks in
/// `distribute`. When building an account with this component,
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

    const DISTRIBUTE_PROC_NAME: &str = "distribute";
    const BURN_PROC_NAME: &str = "burn";

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the digest of the `distribute` account procedure.
    pub fn distribute_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_DISTRIBUTE
    }

    /// Returns the digest of the `burn` account procedure.
    pub fn burn_digest() -> Word {
        *NETWORK_FUNGIBLE_FAUCET_BURN
    }

    /// Checks that the account contains the network fungible faucet interface.
    fn try_from_interface(
        interface: AccountInterface,
        _storage: &miden_protocol::account::AccountStorage,
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
/// - `distribute`, which mints an assets and create a note for the provided recipient.
/// - `burn`, which burns the provided asset.
///
/// Both `distribute` and `burn` can only be called from note scripts. `distribute` requires
/// authentication using the NoAuth scheme. `burn` does not require authentication and can be
/// called by anyone.
///
/// Network fungible faucets always use:
/// - [`AccountStorageMode::Network`] for storage
/// - [`NoAuth`] for authentication
///
/// The storage layout of the faucet account is documented on the [`FungibleTokenMetadata`] and
/// [`crate::account::access::Ownable2Step`] types, and contains no additional storage slots for
/// its auth ([`NoAuth`]).
pub fn create_network_fungible_faucet(
    init_seed: [u8; 32],
    metadata: FungibleTokenMetadata,
    access_control: AccessControl,
) -> Result<Account, FungibleFaucetError> {
    let auth_component: AccountComponent = NoAuth::new().into();

    let account = AccountBuilder::new(init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Network)
        .with_auth_component(auth_component)
        .with_component(metadata)
        .with_component(NetworkFungibleFaucet)
        .with_component(access_control)
        .build()
        .map_err(FungibleFaucetError::AccountError)?;

    Ok(account)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Felt;
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::TokenSymbol;

    use super::*;
    use crate::account::access::Ownable2Step;
    use crate::account::faucets::{FungibleTokenMetadata, TokenName};

    #[test]
    fn test_create_network_fungible_faucet() {
        let init_seed = [7u8; 32];

        let owner = AccountId::dummy(
            [1u8; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Private,
        );

        let metadata = FungibleTokenMetadata::new(
            TokenSymbol::new("NET").expect("valid symbol"),
            8u8,
            Felt::new(1_000),
            TokenName::new("NET").expect("valid name"),
            None,
            None,
            None,
        )
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
