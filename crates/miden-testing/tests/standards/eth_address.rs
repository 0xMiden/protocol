//! Tests for `AccountId` validation in `eth_address::to_account_id`, and for the bytes32-embedded
//! variant `eth_address::bytes32_to_account_id`.
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
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_standards::errors::standards::{ERR_BYTES32_PADDING_NONZERO, ERR_MSB_NONZERO};
use miden_standards::interop::{AddressConversionError, EthAddress, EthEmbeddedAccountId};

use super::test_utils::{assert_execution_fails_with, execute_masm_script};

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

/// Builds a script that pushes the 8 bytes32 limbs (`limb0` on top) and runs
/// `bytes32_to_account_id`.
fn bytes32_to_account_id_script(bytes: &[u8; 32]) -> String {
    let limbs: Vec<u64> = bytes_to_packed_u32_elements(bytes)
        .iter()
        .map(|f| f.as_canonical_u64())
        .collect();
    format!(
        "use miden::core::sys
use miden::standards::interop::eth_address

begin
    push.{}.{}.{}.{}.{}.{}.{}.{}
    exec.eth_address::bytes32_to_account_id
    exec.sys::truncate_stack
end",
        limbs[7], limbs[6], limbs[5], limbs[4], limbs[3], limbs[2], limbs[1], limbs[0]
    )
}

/// Returns a valid embedded-form address (as trailing 20 bytes) left-padded into a bytes32.
fn valid_embedded_bytes32() -> ([u8; 20], [u8; 32]) {
    let valid_id = AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap();
    let embedded = EthEmbeddedAccountId::from_account_id(valid_id);
    (embedded.to_bytes(), embedded.to_bytes32())
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

/// A bytes32 with 12 zero leading bytes and a valid embedded `AccountId` converts to the same
/// `[suffix, prefix]` as `to_account_id` applied to the trailing 20 bytes.
#[tokio::test]
async fn bytes32_to_account_id_matches_to_account_id_on_trailing_bytes() {
    let (addr_bytes, bytes32) = valid_embedded_bytes32();

    let bytes32_output = execute_masm_script(&bytes32_to_account_id_script(&bytes32))
        .await
        .expect("bytes32_to_account_id should accept a zero-padded embedded address");
    let addr_output = execute_masm_script(&to_account_id_script(&EthAddress::new(addr_bytes)))
        .await
        .expect("to_account_id should accept a valid embedded address");

    // Both paths must yield the same [suffix, prefix] (stack top is suffix).
    assert_eq!(bytes32_output.stack[0..2], addr_output.stack[0..2]);

    // The decoded id must round-trip to the original AccountId.
    let recovered =
        AccountId::try_from_elements(bytes32_output.stack[0], bytes32_output.stack[1]).unwrap();
    assert_eq!(
        recovered,
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE).unwrap()
    );
}

/// Non-zero padding in any of the three leading limbs of the bytes32 is rejected with the
/// dedicated padding error.
#[tokio::test]
async fn bytes32_to_account_id_rejects_nonzero_padding() {
    let (_addr_bytes, bytes32) = valid_embedded_bytes32();

    // One representative byte per padding limb: limb0 = bytes[0..4], limb1 = bytes[4..8],
    // limb2 = bytes[8..12].
    for corrupted_byte in [0, 5, 11] {
        let mut bad = bytes32;
        bad[corrupted_byte] = 0xff;
        assert_execution_fails_with(
            &bytes32_to_account_id_script(&bad),
            &ERR_BYTES32_PADDING_NONZERO,
        )
        .await;
    }
}

/// Rust mirror: `EthAddress::try_from::<[u8; 32]>` accepts a zero-padded bytes32 and rejects
/// non-zero padding in any padding limb.
#[test]
fn try_from_bytes32_accepts_and_rejects() {
    let (addr_bytes, bytes32) = valid_embedded_bytes32();

    // Accept: the trailing 20 bytes come back unchanged.
    let addr = EthAddress::try_from(bytes32).unwrap();
    assert_eq!(addr, EthAddress::new(addr_bytes));

    // Reject: a non-zero byte anywhere in the 12-byte padding.
    for corrupted_byte in [0, 5, 11] {
        let mut bad = bytes32;
        bad[corrupted_byte] = 0x01;
        assert_eq!(EthAddress::try_from(bad), Err(AddressConversionError::NonZeroBytes32Padding),);
    }
}
