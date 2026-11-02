use miden_protocol::Felt;

// STANDARDS DOMAIN REGISTRY
// ================================================================================================

/// The domain separators of the standards library's domain-separated hashes.
///
/// The [Poseidon2 domain registry][registry] delegates the range 0x020000..0x30000 to the
/// protocol repository, of which 0x028000..0x30000 is reserved for the standards, Agglayer and
/// USDCx libraries; see [`ProtocolDomainRegistry`](miden_protocol::ProtocolDomainRegistry) for
/// the protocol's share.
///
/// The MASM counterparts of these values must be kept in sync.
///
/// [registry]: https://github.com/0xMiden/crypto/blob/2156001768d4581f8957b9aa63a0c2d1d660b510/docs/registry/poseidon2-domains.toml
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum StandardsDomainRegistry {
    /// Domain of the message approvers sign to cancel a smart multisig proposal; see
    /// [`AuthMultisigSmart::cancel_signing_message`](crate::account::auth::AuthMultisigSmart::cancel_signing_message).
    MultisigSmartCancelProposal = 0x02_8000,
}

impl StandardsDomainRegistry {
    /// Returns the domain as a [`u32`].
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the domain as a [`Felt`].
    pub const fn as_felt(self) -> Felt {
        Felt::from_u32(self.as_u32())
    }
}
