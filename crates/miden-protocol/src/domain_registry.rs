//! Protocol Eidos domain assignments.
//!
//! A domain tag packs an 8-bit namespace, a 16-bit local ID, and an 8-bit version. The domain ID
//! consists of the namespace and local ID, so it is the full tag shifted right by eight bits.
//! For example, the account-patch tag is `0x02000000` and its domain ID is `0x020000`.
//!
//! The initializer receives the full domain tag encoded as a Felt. The `*_SELECTOR` constants
//! expose that value for existing callers. A zero version byte in the tag delegates versioning to
//! the payload schema. Patch and delta payloads carry their layout version in the first element of
//! a nonempty preimage. Numbered domain tags carry their construction version in the tag itself.

use miden_core::Felt;
use miden_crypto::hash::eidos::domain::{
    DELEGATED_VERSIONING,
    DomainVersion,
    EidosDomain,
    FeltSequence,
    namespace,
};

// EIDOS DOMAINS
// ================================================================================================

miden_crypto::eidos_domain_registry! {
    /// Eidos domains maintained by the Miden protocol.
    ///
    /// Within the `MIDEN_PROTOCOL` namespace, local IDs `0x0000..0x8000` are reserved for
    /// protocol domains and `0x8000..0x10000` for Standards, Agglayer, and USDCx domains.
    ///
    /// Patch and delta commitments delegate versioning to their payload schemas. Non-empty
    /// payloads start with the layout version as one Felt; empty objects use an empty payload.
    /// The code-upgrade advice key uses a numbered hash construction over a code commitment.
    ///
    /// The domain tags used in MASM must match these assignments.
    pub registry ProtocolDomainRegistry {
        namespace: namespace::MIDEN_PROTOCOL;
        domains: {
            pub ACCOUNT_PATCH_COMMITMENT_DOMAIN: AccountPatchCommitmentDomain {
                local_id: 0,
                version: DELEGATED_VERSIONING,
                encoding: FeltSequence,
                description: "Account patch commitments.",
                schema: "param0 = Felt count; param1 = param2 = 0; \
                    first Felt = layout version for non-empty patches; \
                    empty patches = empty sequence; zero-pad partial or empty block",
            }
            pub ACCOUNT_DELTA_COMMITMENT_DOMAIN: AccountDeltaCommitmentDomain {
                local_id: 1,
                version: DELEGATED_VERSIONING,
                encoding: FeltSequence,
                description: "Account delta commitments.",
                schema: "param0 = Felt count; param1 = param2 = 0; \
                    first Felt = layout version for non-empty deltas; \
                    empty deltas = empty sequence; zero-pad partial or empty block",
            }
            pub ACCOUNT_CODE_UPGRADE_ADVICE_DOMAIN: AccountCodeUpgradeAdviceDomain {
                local_id: 2,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Account code upgrade advice-map keys.",
                schema: "param0 = 4 Felts; param1 = 0; param2 = 0; zero-pad the final block",
            }
            pub TRANSACTION_LOGS_COMMITMENT_DOMAIN: TransactionLogsCommitmentDomain {
                local_id: 3,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Ordered transaction log commitments.",
                schema: "param0 = Felt count; param1 = param2 = 0; \
                    log commitments in emission order; zero-pad the final block",
            }
            pub TRANSACTION_LOG_COMMITMENT_DOMAIN: TransactionLogCommitmentDomain {
                local_id: 4,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Individual transaction log commitments.",
                schema: "param0 = 8 Felts; param1 = param2 = 0; \
                    emitter suffix, emitter prefix, topic suffix, topic prefix, content commitment",
            }
            pub CODE_PATCH_COMMITMENT_DOMAIN: CodePatchCommitmentDomain {
                local_id: 5,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Code patch commitments.",
                schema: "param0 = 8 Felts; param1 = param2 = 0; \
                    created procedures commitment, dependencies commitment",
            }
            pub CODE_PATCH_CREATED_COMMITMENT_DOMAIN: CodePatchCreatedCommitmentDomain {
                local_id: 6,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Created code patch procedures.",
                schema: "param0 = Felt count; param1 = param2 = 0; \
                    procedure roots in kernel emission order; zero-pad the final block",
            }
            pub CODE_PATCH_DEPENDENCIES_COMMITMENT_DOMAIN: CodePatchDependenciesCommitmentDomain {
                local_id: 7,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Code patch dependencies.",
                schema: "param0 = Felt count; param1 = param2 = 0; \
                    dependency roots in kernel emission order; zero-pad the final block",
            }
        }
    }
}

/// Registered domain ID for account patch commitments.
pub const ACCOUNT_PATCH_COMMITMENT_DOMAIN_ID: u32 = AccountPatchCommitmentDomain::TAG.as_u32() >> 8;

/// Registered domain ID for account delta commitments.
pub const ACCOUNT_DELTA_COMMITMENT_DOMAIN_ID: u32 = AccountDeltaCommitmentDomain::TAG.as_u32() >> 8;

/// Account patch domain tag encoded as a field element.
pub const ACCOUNT_PATCH_COMMITMENT_SELECTOR: Felt = AccountPatchCommitmentDomain::TAG.as_felt();

/// Account delta domain tag encoded as a field element.
pub const ACCOUNT_DELTA_COMMITMENT_SELECTOR: Felt = AccountDeltaCommitmentDomain::TAG.as_felt();
