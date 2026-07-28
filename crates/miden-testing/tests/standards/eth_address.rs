//! Tests for `AccountId` validation in `eth_address::to_account_id`.
//!
//! The bridge-in claim decodes a deposit's `destinationAddress` into the `AccountId` target of a
//! P2ID/MINT output. An invalid decoded id would produce an output that no account can consume.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use miden_protocol::Felt;
use miden_protocol::account::AccountId;
use miden_protocol::errors::protocol::ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO;
use miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE;
use miden_standards::errors::standards::ERR_MSB_NONZERO;
use miden_standards::interop::{AddressConversionError, EthAddress, EthEmbeddedAccountId};

use super::test_utils::assert_execution_fails_with;

/// Builds a script that pushes the 5 address limbs (`limb0` on top) and runs `to_account_id`.
///
/// `truncate_stack` lets a non-reverting run finish cleanly, so a missing revert surfaces as a
/// successful execution rather than a stack error.
fn to_account_id_script(addr: &EthAddress) -> String {
    let limbs: Vec<u64> = addr.to_elements().iter().map(|f| f.as_canonical_u64()).collect();
    format!(
        "use miden::core::sys
use miden::standards::interop::eth_address

begin
    push.{}.{}.{}.{}.{}
    exec.eth_address::to_account_id
    exec.sys::truncate_stack
end",
        limbs[4], limbs[3], limbs[2], limbs[1], limbs[0]
    )
}

/// Returns an embedded-form address that decodes into a structurally invalid `AccountId` (suffix
/// least-significant byte non-zero), plus its decoded `(suffix, prefix)`. Built from a valid
/// `AccountId` with only the suffix LSB flipped, so `account_id::validate_structure` fails on that
/// check.
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

/// Case A: a non-embedded destination (non-zero most-significant 4 bytes) is rejected by
/// `to_account_id`. Unchanged by the fix.
#[tokio::test]
async fn to_account_id_rejects_non_embedded_address() {
    // A real-looking EVM address: the top 4 bytes are non-zero, so it is not an embedded AccountId.
    let addr = EthAddress::from_hex("0xdeadbeefcafebabe0badf00d0011223344556677").unwrap();
    assert_execution_fails_with(&to_account_id_script(&addr), &ERR_MSB_NONZERO).await;
}

/// Evidence that the crafted destination really is an invalid `AccountId`: the Rust reference
/// conversion rejects it, so the on-chain path accepting it is a genuine gap.
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

/// Case B: an embedded destination that decodes into a structurally invalid `AccountId` must be
/// rejected, reverting with the suffix least-significant-byte error.
#[tokio::test]
async fn to_account_id_rejects_structurally_invalid_account_id() {
    let (bad_addr, _suffix, _prefix) = crafted_invalid_embedded_address();
    assert_execution_fails_with(
        &to_account_id_script(&bad_addr),
        &ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO,
    )
    .await;
}
