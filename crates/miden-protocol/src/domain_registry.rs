use crate::Felt;

// PROTOCOL DOMAIN REGISTRY
// ================================================================================================

/// The domain separators of the protocol's domain-separated hashes.
///
/// The [Poseidon2 domain registry][registry] delegates the range 0x020000..0x30000 to the
/// protocol repository. That range is further divided into:
///
/// - Protocol: 0x020000..0x28000.
/// - Standards/Agglayer/USDCx: 0x28000..0x30000.
///
/// The MASM counterparts of these values must be kept in sync.
///
/// [registry]: https://github.com/0xMiden/crypto/pull/1026/changes#diff-94a8c9a4f6fab8a324480a417f30288a6afb93a41278e5299f00df3fd5f6e75b
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum ProtocolDomainRegistry {
    /// Domain of the [`AccountPatch`](crate::account::AccountPatch) commitment.
    AccountPatch = 0x02_0000,

    /// Domain of the [`AccountDelta`](crate::account::AccountDelta) commitment.
    AccountDelta = 0x02_0001,

    /// Domain of the [`AccountCodeUpgrade`](crate::account::AccountCodeUpgrade) advice map key.
    AccountCodeUpgradeAdvice = 0x02_0002,
}

impl ProtocolDomainRegistry {
    /// Returns the domain as a [`u32`].
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the domain as a [`Felt`].
    pub const fn as_felt(self) -> Felt {
        Felt::from_u32(self.as_u32())
    }
}
