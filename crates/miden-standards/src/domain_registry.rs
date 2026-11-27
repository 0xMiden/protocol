use miden_crypto::hash::eidos::domain::{DomainVersion, FeltSequence, namespace};

// STANDARDS DOMAIN REGISTRY
// ================================================================================================

miden_crypto::eidos_domain_registry! {
    /// Eidos domains maintained by the standards library.
    ///
    /// Within the `MIDEN_PROTOCOL` namespace, local IDs `0x8000..0x10000` are reserved for
    /// Standards, Agglayer, and USDCx domains. See
    /// [`ProtocolDomainRegistry`](miden_protocol::ProtocolDomainRegistry) for the protocol's share.
    ///
    /// The MASM selectors must match these domain tags.
    pub registry StandardsDomainRegistry {
        namespace: namespace::MIDEN_PROTOCOL;
        domains: {
            pub MULTISIG_SMART_CANCEL_PROPOSAL_DOMAIN: MultisigSmartCancelProposalDomain {
                local_id: 0x8000,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Smart multisig proposal cancellation signing messages.",
                schema: "param0 = 8 Felts; param1 = param2 = 0; \
                    transaction summary commitment followed by an empty word",
            }
            pub P2ID_ENCRYPTION_BATCH: P2idEncryptionBatchDomain {
                local_id: 0x8001,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Ordered batch of encrypted P2ID notes.",
                schema: "param0 = 12 * note count; param1 = param2 = 0; payload = ordered \
                    triples of note ID, public key commitment, and envelope commitment",
            }
        }
    }
}
