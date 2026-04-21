use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_processor::mast::MastNodeExt;
use miden_protocol::Word;
use miden_protocol::account::AccountProcedureRoot;
use miden_protocol::assembly::{Library, LibraryExport};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::utils::sync::LazyLock;

use crate::account::interface::AccountComponentInterface;

// WALLET LIBRARIES
// ================================================================================================

// Initialize the Basic Wallet library only once.
static BASIC_WALLET_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/wallets/basic_wallet.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Basic Wallet library is well-formed")
});

// ACCESS LIBRARIES
// ================================================================================================

// Initialize the Ownable2Step library only once.
static OWNABLE2STEP_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/access/ownable2step.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Ownable2Step library is well-formed")
});

// AUTH LIBRARIES
// ================================================================================================

/// Initialize the ECDSA K256 Keccak library only once.
static SINGLESIG_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/account_components/auth/singlesig.masl"));
    Library::read_from_bytes(bytes).expect("Shipped Singlesig library is well-formed")
});

// Initialize the ECDSA K256 Keccak ACL library only once.
static SINGLESIG_ACL_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/singlesig_acl.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Singlesig ACL library is well-formed")
});

/// Initialize the Multisig library only once.
static MULTISIG_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/account_components/auth/multisig.masl"));
    Library::read_from_bytes(bytes).expect("Shipped Multisig library is well-formed")
});

/// Initialize the Guarded Multisig library only once.
static GUARDED_MULTISIG_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/guarded_multisig.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Guarded Multisig library is well-formed")
});

// Initialize the NoAuth library only once.
static NO_AUTH_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes =
        include_bytes!(concat!(env!("OUT_DIR"), "/assets/account_components/auth/no_auth.masl"));
    Library::read_from_bytes(bytes).expect("Shipped NoAuth library is well-formed")
});

// FAUCET LIBRARIES
// ================================================================================================

// Initialize the Basic Fungible Faucet library only once.
static BASIC_FUNGIBLE_FAUCET_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/basic_fungible_faucet.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Basic Fungible Faucet library is well-formed")
});

// Initialize the Network Fungible Faucet library only once.
static NETWORK_FUNGIBLE_FAUCET_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/network_fungible_faucet.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Network Fungible Faucet library is well-formed")
});

// Initialize the Fungible Token Metadata library only once.
static FUNGIBLE_TOKEN_METADATA_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/faucets/fungible_token_metadata.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Fungible Token Metadata library is well-formed")
});

// Initialize the Mint Policy Owner Controlled library only once.
static MINT_POLICY_OWNER_CONTROLLED_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/mint_policies/owner_controlled.masl"
    ));
    Library::read_from_bytes(bytes)
        .expect("Shipped Mint Policy Owner Controlled library is well-formed")
});

// Initialize the Mint Policy Auth Controlled library only once.
static MINT_POLICY_AUTH_CONTROLLED_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/mint_policies/auth_controlled.masl"
    ));
    Library::read_from_bytes(bytes)
        .expect("Shipped Mint Policy Auth Controlled library is well-formed")
});

/// Returns the Basic Wallet Library.
pub fn basic_wallet_library() -> Library {
    BASIC_WALLET_LIBRARY.clone()
}

/// Returns the Ownable2Step Library.
pub fn ownable2step_library() -> Library {
    OWNABLE2STEP_LIBRARY.clone()
}

/// Returns the Basic Fungible Faucet Library.
pub fn basic_fungible_faucet_library() -> Library {
    BASIC_FUNGIBLE_FAUCET_LIBRARY.clone()
}

/// Returns the Network Fungible Faucet Library.
pub fn network_fungible_faucet_library() -> Library {
    NETWORK_FUNGIBLE_FAUCET_LIBRARY.clone()
}

/// Returns the Fungible Token Metadata Library.
pub fn fungible_token_metadata_library() -> Library {
    FUNGIBLE_TOKEN_METADATA_LIBRARY.clone()
}

/// Returns the Mint Policy Owner Controlled Library.
pub fn owner_controlled_library() -> Library {
    MINT_POLICY_OWNER_CONTROLLED_LIBRARY.clone()
}

/// Returns the Mint Policy Auth Controlled Library.
pub fn auth_controlled_library() -> Library {
    MINT_POLICY_AUTH_CONTROLLED_LIBRARY.clone()
}

/// Returns the Singlesig Library.
pub fn singlesig_library() -> Library {
    SINGLESIG_LIBRARY.clone()
}

/// Returns the Singlesig ACL Library.
pub fn singlesig_acl_library() -> Library {
    SINGLESIG_ACL_LIBRARY.clone()
}

/// Returns the Multisig Library.
pub fn multisig_library() -> Library {
    MULTISIG_LIBRARY.clone()
}

/// Returns the Guarded Multisig Library.
pub fn guarded_multisig_library() -> Library {
    GUARDED_MULTISIG_LIBRARY.clone()
}

/// Returns the NoAuth Library.
pub fn no_auth_library() -> Library {
    NO_AUTH_LIBRARY.clone()
}

// STANDARD ACCOUNT COMPONENTS
// ================================================================================================

/// The enum holding the types of standard account components defined in the `miden-standards`
/// crate.
pub enum StandardAccountComponent {
    BasicWallet,
    FungibleTokenMetadata,
    BasicFungibleFaucet,
    NetworkFungibleFaucet,
    AuthSingleSig,
    AuthSingleSigAcl,
    AuthMultisig,
    AuthGuardedMultisig,
    AuthNoAuth,
}

impl StandardAccountComponent {
    /// Returns the iterator over digests of all procedures exported from the component.
    pub fn procedure_digests(&self) -> impl Iterator<Item = Word> {
        let library = match self {
            Self::BasicWallet => BASIC_WALLET_LIBRARY.as_ref(),
            Self::FungibleTokenMetadata => FUNGIBLE_TOKEN_METADATA_LIBRARY.as_ref(),
            Self::BasicFungibleFaucet => BASIC_FUNGIBLE_FAUCET_LIBRARY.as_ref(),
            Self::NetworkFungibleFaucet => NETWORK_FUNGIBLE_FAUCET_LIBRARY.as_ref(),
            Self::AuthSingleSig => SINGLESIG_LIBRARY.as_ref(),
            Self::AuthSingleSigAcl => SINGLESIG_ACL_LIBRARY.as_ref(),
            Self::AuthMultisig => MULTISIG_LIBRARY.as_ref(),
            Self::AuthGuardedMultisig => GUARDED_MULTISIG_LIBRARY.as_ref(),
            Self::AuthNoAuth => NO_AUTH_LIBRARY.as_ref(),
        };

        library
            .exports()
            .filter(|export| matches!(export, LibraryExport::Procedure(_)))
            .map(|proc_export| {
                library
                    .mast_forest()
                    .get_node_by_id(proc_export.unwrap_procedure().node)
                    .expect("export node not in the forest")
                    .digest()
            })
    }

    /// Checks whether procedures from the current component are present in the procedures map
    /// and if so it removes these procedures from this map and pushes the corresponding component
    /// interface to the component interface vector.
    fn extract_component(
        &self,
        procedures_set: &mut BTreeSet<AccountProcedureRoot>,
        component_interface_vec: &mut Vec<AccountComponentInterface>,
    ) {
        // Determine if this component should be extracted based on procedure matching
        if self.procedure_digests().all(|proc_digest| {
            procedures_set.contains(&AccountProcedureRoot::from_raw(proc_digest))
        }) {
            // Remove the procedure root of any matching procedure.
            self.procedure_digests().for_each(|component_procedure| {
                procedures_set.remove(&AccountProcedureRoot::from_raw(component_procedure));
            });

            // Create the appropriate component interface
            match self {
                Self::BasicWallet => {
                    component_interface_vec.push(AccountComponentInterface::BasicWallet)
                },
                Self::FungibleTokenMetadata => {
                    component_interface_vec.push(AccountComponentInterface::FungibleTokenMetadata)
                },
                Self::BasicFungibleFaucet => {
                    component_interface_vec.push(AccountComponentInterface::BasicFungibleFaucet)
                },
                Self::NetworkFungibleFaucet => {
                    component_interface_vec.push(AccountComponentInterface::NetworkFungibleFaucet)
                },
                Self::AuthSingleSig => {
                    component_interface_vec.push(AccountComponentInterface::AuthSingleSig)
                },
                Self::AuthSingleSigAcl => {
                    component_interface_vec.push(AccountComponentInterface::AuthSingleSigAcl)
                },
                Self::AuthMultisig => {
                    component_interface_vec.push(AccountComponentInterface::AuthMultisig)
                },
                Self::AuthGuardedMultisig => {
                    component_interface_vec.push(AccountComponentInterface::AuthGuardedMultisig)
                },
                Self::AuthNoAuth => {
                    component_interface_vec.push(AccountComponentInterface::AuthNoAuth)
                },
            }
        }
    }

    /// Gets all standard components which could be constructed from the provided procedures map
    /// and pushes them to the `component_interface_vec`.
    pub fn extract_standard_components(
        procedures_set: &mut BTreeSet<AccountProcedureRoot>,
        component_interface_vec: &mut Vec<AccountComponentInterface>,
    ) {
        Self::BasicWallet.extract_component(procedures_set, component_interface_vec);
        Self::FungibleTokenMetadata.extract_component(procedures_set, component_interface_vec);
        Self::BasicFungibleFaucet.extract_component(procedures_set, component_interface_vec);
        Self::NetworkFungibleFaucet.extract_component(procedures_set, component_interface_vec);
        Self::AuthSingleSig.extract_component(procedures_set, component_interface_vec);
        Self::AuthSingleSigAcl.extract_component(procedures_set, component_interface_vec);
        Self::AuthGuardedMultisig.extract_component(procedures_set, component_interface_vec);
        Self::AuthMultisig.extract_component(procedures_set, component_interface_vec);
        Self::AuthNoAuth.extract_component(procedures_set, component_interface_vec);
    }
}
