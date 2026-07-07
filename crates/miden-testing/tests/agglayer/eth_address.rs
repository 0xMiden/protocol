//! Tests for `agglayer::common::eth_address::to_account_id`, focused on the `AccountId`
//! structural invariants the bridge-in claim relies on.
//!
//! The claim path decodes a deposit leaf's `destinationAddress` into a Miden `AccountId` via
//! `to_account_id` and routes bridged value to it by emitting a P2ID (native faucet) or MINT
//! (non-native faucet) output. If the decoded id is not a structurally valid `AccountId`, the
//! resulting output can never be consumed, permanently locking the assets. These tests pin the
//! two failure modes and the fix that closes the gap.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use miden_agglayer::errors::ERR_MSB_NONZERO;
use miden_agglayer::eth_types::{AddressConversionError, EthAddress, EthEmbeddedAccountId};
use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::errors::MasmError;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;

use super::test_utils::assert_execution_fails_with;

/// The exact message of `ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO` in
/// `crates/miden-protocol/asm/protocol_utils/src/account_id.masm`. `account_id::validate` panics
/// with this when the suffix's least-significant byte is non-zero. It has no exported Rust
/// constant, so we mirror the string here (matched by error code, see
/// [`MasmError::matches_execution_error`]).
const ERR_SUFFIX_LSB_NONZERO: MasmError =
    MasmError::from_static_str("least significant byte of the account ID suffix must be zero");

/// Builds a MASM script that pushes the 5 address limbs and runs `eth_address::to_account_id`.
///
/// `to_account_id` expects `[limb0, limb1, limb2, limb3, limb4]` with `limb0` on top, so the limbs
/// (returned by [`EthAddress::to_elements`] in ascending order) are pushed in reverse. On success
/// the stack holds `[suffix, prefix]`; `truncate_stack` lets a run that does *not* revert terminate
/// cleanly, so a missing revert is observable as a successful execution rather than a stack error.
fn to_account_id_script(addr: &EthAddress) -> String {
    let limbs: Vec<u64> = addr.to_elements().iter().map(|f| f.as_canonical_u64()).collect();
    format!(
        "use miden::core::sys
use agglayer::common::eth_address

begin
    push.{}.{}.{}.{}.{}
    exec.eth_address::to_account_id
    exec.sys::truncate_stack
end",
        limbs[4], limbs[3], limbs[2], limbs[1], limbs[0]
    )
}

/// Returns an embedded-form destination address whose decoded suffix violates the `AccountId`
/// "least-significant byte must be zero" invariant, along with its decoded `(suffix, prefix)` field
/// elements.
///
/// Built by encoding a valid `AccountId` as an embedded address and flipping the suffix's
/// least-significant byte from `0` to `1`. Version and suffix most-significant bit stay valid, so
/// `account_id::validate` fails specifically on the suffix least-significant-byte check.
fn crafted_invalid_embedded_address() -> (EthAddress, Felt, Felt) {
    let valid_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let mut bytes = EthEmbeddedAccountId::from_account_id(valid_id).to_bytes();

    // suffix = bytes[12..20] (big-endian), so byte 19 is its least-significant byte. A valid
    // AccountId always has this byte zero; set it to make the suffix structurally invalid.
    assert_eq!(bytes[19], 0, "a valid AccountId must have a zero suffix least-significant byte");
    bytes[19] = 1;

    let prefix_u64 = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
    let suffix_u64 = u64::from_be_bytes(bytes[12..20].try_into().unwrap());
    let prefix = Felt::try_from(prefix_u64).unwrap();
    let suffix = Felt::try_from(suffix_u64).unwrap();

    (EthAddress::new(bytes), suffix, prefix)
}

/// Case A (unclaimable): a committed destination address whose most-significant 4 bytes are
/// non-zero - i.e. a real, non-embedded Ethereum address - hard-traps in `to_account_id`. Because
/// the destination is committed into the deposit leaf, such a claim is deterministically
/// unclaimable. Behaviour is unchanged by the fix.
#[tokio::test]
async fn to_account_id_rejects_non_embedded_address() {
    // A real-looking EVM address: the top 4 bytes are non-zero, so it is not an embedded AccountId.
    let addr = EthAddress::from_hex("0xdeadbeefcafebabe0badf00d0011223344556677").unwrap();
    assert_execution_fails_with(&to_account_id_script(&addr), &ERR_MSB_NONZERO).await;
}

/// Evidence (fix-independent): the crafted destination used by
/// [`to_account_id_rejects_structurally_invalid_account_id`] really is an invalid `AccountId` - the
/// Rust reference conversion rejects it. This is what makes the missing MASM check a bug: the
/// on-chain path is strictly more permissive than the Rust reference.
#[test]
fn crafted_invalid_account_id_is_rejected_by_rust() {
    let (bad_addr, suffix, prefix) = crafted_invalid_embedded_address();

    // The Rust embedded-address conversion (used off-chain to build CLAIM notes) rejects it...
    assert_eq!(
        EthEmbeddedAccountId::try_from(bad_addr),
        Err(AddressConversionError::InvalidAccountId),
    );

    // ...precisely because the decoded (suffix, prefix) is not a structurally valid AccountId.
    assert!(AccountId::try_from_elements(suffix, prefix).is_err());
}

/// Case B (unspendable output) - the core bug.
///
/// A destination address that is embedded-form (top 4 bytes zero) but decodes into a structurally
/// invalid `AccountId` (here: suffix least-significant byte non-zero) must be rejected by
/// `to_account_id`. Before the fix, `to_account_id` accepts it and returns the invalid
/// `(suffix, prefix)`, which the claim would route into an unspendable P2ID/MINT output (this test
/// fails, reproducing the bug). After the fix, `to_account_id` validates the decoded id and reverts
/// with the suffix least-significant-byte error.
#[tokio::test]
async fn to_account_id_rejects_structurally_invalid_account_id() {
    let (bad_addr, _suffix, _prefix) = crafted_invalid_embedded_address();
    assert_execution_fails_with(&to_account_id_script(&bad_addr), &ERR_SUFFIX_LSB_NONZERO).await;
}
