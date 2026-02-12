use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use miden_processor::MastNodeExt;
use miden_protocol::Word;
use miden_protocol::account::AccountProcedureRoot;
use miden_protocol::assembly::{Library, LibraryExport};
use miden_protocol::utils::Deserializable;
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

// AUTH LIBRARIES
// ================================================================================================

/// Initialize the ECDSA K256 Keccak library only once.
static ECDSA_K256_KECCAK_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/ecdsa_k256_keccak.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Ecdsa K256 Keccak library is well-formed")
});

// Initialize the ECDSA K256 Keccak ACL library only once.
static ECDSA_K256_KECCAK_ACL_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/ecdsa_k256_keccak_acl.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Ecdsa K256 Keccak ACL library is well-formed")
});

/// Initialize the ECDSA K256 Keccak Multisig library only once.
static ECDSA_K256_KECCAK_MULTISIG_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/ecdsa_k256_keccak_multisig.masl"
    ));
    Library::read_from_bytes(bytes)
        .expect("Shipped Multisig Ecdsa K256 Keccak library is well-formed")
});

// Initialize the Falcon 512 RPO library only once.
static FALCON_512_RPO_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/falcon_512_rpo.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Falcon 512 RPO library is well-formed")
});

// Initialize the Falcon 512 RPO ACL library only once.
static FALCON_512_RPO_ACL_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/falcon_512_rpo_acl.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Falcon 512 RPO ACL library is well-formed")
});

// Initialize the Multisig Falcon 512 RPO library only once.
static FALCON_512_RPO_MULTISIG_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/auth/falcon_512_rpo_multisig.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Multisig Falcon 512 RPO library is well-formed")
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

// METADATA LIBRARIES
// ================================================================================================

// Initialize the Storage Schema library only once.
static STORAGE_SCHEMA_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    let bytes = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/assets/account_components/metadata/schema_commitment.masl"
    ));
    Library::read_from_bytes(bytes).expect("Shipped Storage Schema library is well-formed")
});

/// Returns the Basic Wallet Library.
pub fn basic_wallet_library() -> Library {
    BASIC_WALLET_LIBRARY.clone()
}

/// Returns the Basic Fungible Faucet Library.
pub fn basic_fungible_faucet_library() -> Library {
    BASIC_FUNGIBLE_FAUCET_LIBRARY.clone()
}

/// Returns the Network Fungible Faucet Library.
pub fn network_fungible_faucet_library() -> Library {
    NETWORK_FUNGIBLE_FAUCET_LIBRARY.clone()
}

/// Returns the Storage Schema Library.
pub fn storage_schema_library() -> Library {
    STORAGE_SCHEMA_LIBRARY.clone()
}

/// Returns the ECDSA K256 Keccak Library.
pub fn ecdsa_k256_keccak_library() -> Library {
    ECDSA_K256_KECCAK_LIBRARY.clone()
}

/// Returns the ECDSA K256 Keccak ACL Library.
pub fn ecdsa_k256_keccak_acl_library() -> Library {
    ECDSA_K256_KECCAK_ACL_LIBRARY.clone()
}

/// Returns the ECDSA K256 Keccak Multisig Library.
pub fn ecdsa_k256_keccak_multisig_library() -> Library {
    ECDSA_K256_KECCAK_MULTISIG_LIBRARY.clone()
}

/// Returns the Falcon 512 RPO Library.
pub fn falcon_512_rpo_library() -> Library {
    FALCON_512_RPO_LIBRARY.clone()
}

/// Returns the Falcon 512 RPO ACL Library.
pub fn falcon_512_rpo_acl_library() -> Library {
    FALCON_512_RPO_ACL_LIBRARY.clone()
}

/// Returns the NoAuth Library.
pub fn no_auth_library() -> Library {
    NO_AUTH_LIBRARY.clone()
}

/// Returns the Falcon 512 RPO Multisig Library.
pub fn falcon_512_rpo_multisig_library() -> Library {
    FALCON_512_RPO_MULTISIG_LIBRARY.clone()
}

// STANDARD ACCOUNT COMPONENTS
// ================================================================================================

/// The enum holding the types of standard account components defined in the `miden-standards`
/// crate.
pub enum StandardAccountComponent {
    BasicWallet,
    BasicFungibleFaucet,
    NetworkFungibleFaucet,
    AuthEcdsaK256Keccak,
    AuthEcdsaK256KeccakAcl,
    AuthEcdsaK256KeccakMultisig,
    AuthFalcon512Rpo,
    AuthFalcon512RpoAcl,
    AuthFalcon512RpoMultisig,
    AuthNoAuth,
}

impl StandardAccountComponent {
    /// Returns the iterator over digests of all procedures exported from the component.
    pub fn procedure_digests(&self) -> impl Iterator<Item = Word> {
        let library = match self {
            Self::BasicWallet => BASIC_WALLET_LIBRARY.as_ref(),
            Self::BasicFungibleFaucet => BASIC_FUNGIBLE_FAUCET_LIBRARY.as_ref(),
            Self::NetworkFungibleFaucet => NETWORK_FUNGIBLE_FAUCET_LIBRARY.as_ref(),
            Self::AuthEcdsaK256Keccak => ECDSA_K256_KECCAK_LIBRARY.as_ref(),
            Self::AuthEcdsaK256KeccakAcl => ECDSA_K256_KECCAK_ACL_LIBRARY.as_ref(),
            Self::AuthEcdsaK256KeccakMultisig => ECDSA_K256_KECCAK_MULTISIG_LIBRARY.as_ref(),
            Self::AuthFalcon512Rpo => FALCON_512_RPO_LIBRARY.as_ref(),
            Self::AuthFalcon512RpoAcl => FALCON_512_RPO_ACL_LIBRARY.as_ref(),
            Self::AuthFalcon512RpoMultisig => FALCON_512_RPO_MULTISIG_LIBRARY.as_ref(),
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
                Self::BasicFungibleFaucet => {
                    component_interface_vec.push(AccountComponentInterface::BasicFungibleFaucet)
                },
                Self::NetworkFungibleFaucet => {
                    component_interface_vec.push(AccountComponentInterface::NetworkFungibleFaucet)
                },
                Self::AuthEcdsaK256Keccak => {
                    component_interface_vec.push(AccountComponentInterface::AuthEcdsaK256Keccak)
                },
                Self::AuthEcdsaK256KeccakAcl => {
                    component_interface_vec.push(AccountComponentInterface::AuthEcdsaK256KeccakAcl)
                },
                Self::AuthEcdsaK256KeccakMultisig => component_interface_vec
                    .push(AccountComponentInterface::AuthEcdsaK256KeccakMultisig),
                Self::AuthFalcon512Rpo => {
                    component_interface_vec.push(AccountComponentInterface::AuthFalcon512Rpo)
                },
                Self::AuthFalcon512RpoAcl => {
                    component_interface_vec.push(AccountComponentInterface::AuthFalcon512RpoAcl)
                },
                Self::AuthFalcon512RpoMultisig => component_interface_vec
                    .push(AccountComponentInterface::AuthFalcon512RpoMultisig),
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
        Self::BasicFungibleFaucet.extract_component(procedures_set, component_interface_vec);
        Self::NetworkFungibleFaucet.extract_component(procedures_set, component_interface_vec);
        Self::AuthEcdsaK256Keccak.extract_component(procedures_set, component_interface_vec);
        Self::AuthEcdsaK256KeccakAcl.extract_component(procedures_set, component_interface_vec);
        Self::AuthEcdsaK256KeccakMultisig
            .extract_component(procedures_set, component_interface_vec);
        Self::AuthFalcon512Rpo.extract_component(procedures_set, component_interface_vec);
        Self::AuthFalcon512RpoAcl.extract_component(procedures_set, component_interface_vec);
        Self::AuthFalcon512RpoMultisig.extract_component(procedures_set, component_interface_vec);
        Self::AuthNoAuth.extract_component(procedures_set, component_interface_vec);
    }
}
