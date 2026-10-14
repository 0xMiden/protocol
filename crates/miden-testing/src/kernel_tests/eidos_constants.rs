use alloc::format;
use alloc::vec::Vec;

use miden_crypto::hash::eidos::Eidos;
use miden_crypto::hash::eidos::domain::EidosDomain;
use miden_crypto::hash::eidos::domains::GenericFeltSequenceDomain;
use miden_protocol::{
    ACCOUNT_DELTA_COMMITMENT_DOMAIN,
    ACCOUNT_PATCH_COMMITMENT_DOMAIN,
    AccountDeltaCommitmentDomain,
    AccountPatchCommitmentDomain,
    Felt,
};

const PROLOGUE: &str =
    include_str!("../../../miden-protocol/asm/kernels/transaction-core/src/prologue.masm");
const ACCOUNT: &str =
    include_str!("../../../miden-protocol/asm/kernels/transaction-core/src/account.masm");
const ACCOUNT_UPDATE: &str =
    include_str!("../../../miden-protocol/asm/kernels/transaction-core/src/account_update.masm");
const AUTH: &str = include_str!("../../../miden-standards/asm/standards/auth/mod.masm");
const BRIDGE_CONFIG: &str =
    include_str!("../../../miden-agglayer/asm/agglayer/bridge/bridge_config.masm");
const BRIDGE_IN: &str = include_str!("../../../miden-agglayer/asm/agglayer/bridge/bridge_in.masm");
const CLAIM: &str = include_str!("../../../miden-agglayer/asm/agglayer/notes/claim.masm");
const FAUCET_METADATA_CONFIG: &str =
    include_str!("../../../miden-standards/asm/standards/notes/faucet_metadata_config.masm");

#[test]
fn fixed_eidos_initial_chaining_words_match_rust() {
    let generic = GenericFeltSequenceDomain::TAG;
    let account_delta = AccountDeltaCommitmentDomain::TAG;
    let account_patch = AccountPatchCommitmentDomain::TAG;

    let cases = [
        (PROLOGUE, "EIDOS_INIT_CV_8", generic, 8),
        (PROLOGUE, "EIDOS_INIT_CV_16", generic, 16),
        (PROLOGUE, "EIDOS_INIT_CV_24", generic, 24),
        (PROLOGUE, "EIDOS_INIT_CV_40", generic, 40),
        (ACCOUNT, "EIDOS_INIT_CV_16", generic, 16),
        (AUTH, "TX_SUMMARY_INIT_CV", generic, 24),
        (BRIDGE_CONFIG, "TOKEN_ADDRESS_INIT_CV", generic, 6),
        (BRIDGE_IN, "CLAIM_NULLIFIER_INIT_CV", generic, 2),
        (CLAIM, "PROOF_DATA_INIT_CV", generic, 536),
        (CLAIM, "LEAF_DATA_INIT_CV", generic, 32),
        (FAUCET_METADATA_CONFIG, "STRING_INIT_CV", generic, 28),
        (ACCOUNT_UPDATE, "ACCOUNT_DELTA_INIT_CV_BASE", account_delta, 0),
        (ACCOUNT_UPDATE, "ACCOUNT_PATCH_INIT_CV_BASE", account_patch, 0),
    ];

    for (source, name, domain, num_elements) in cases {
        let actual = parse_word_constant(source, name);
        let expected = Eidos::init_chaining_word_with_tag(domain, [num_elements, 0, 0]);
        let expected = core::array::from_fn(|idx| expected[idx].as_canonical_u64());

        assert_eq!(actual, expected, "{name} does not match its framed input length");
    }
}

#[test]
fn fixed_eidos_empty_account_commitments_match_rust() {
    let cases = [
        (
            "EMPTY_ACCOUNT_DELTA_COMMITMENT",
            Eidos::hash_elements_in_domain::<Felt, _>(&[], ACCOUNT_DELTA_COMMITMENT_DOMAIN),
        ),
        (
            "EMPTY_ACCOUNT_PATCH_COMMITMENT",
            Eidos::hash_elements_in_domain::<Felt, _>(&[], ACCOUNT_PATCH_COMMITMENT_DOMAIN),
        ),
    ];

    for (name, expected) in cases {
        let actual = parse_word_constant(ACCOUNT_UPDATE, name);
        let expected = core::array::from_fn(|idx| expected[idx].as_canonical_u64());

        assert_eq!(actual, expected, "{name} does not match the canonical empty digest");
    }
}

fn parse_word_constant(source: &str, name: &str) -> [u64; 4] {
    let declaration = format!("const {name}");
    let (_, tail) = source
        .split_once(&declaration)
        .unwrap_or_else(|| panic!("missing MASM constant {name}"));
    let (_, tail) = tail
        .split_once('[')
        .unwrap_or_else(|| panic!("missing value for MASM constant {name}"));
    let (values, _) = tail
        .split_once(']')
        .unwrap_or_else(|| panic!("unterminated MASM constant {name}"));
    let values: Vec<u64> = values
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("invalid element in MASM constant {name}: {value}"))
        })
        .collect();

    values.try_into().unwrap_or_else(|values: Vec<u64>| {
        panic!("{name} must contain 4 elements, found {}", values.len())
    })
}
