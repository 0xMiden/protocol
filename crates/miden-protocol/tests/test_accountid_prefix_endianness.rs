//! Test to verify AccountIdPrefix serialization endianness consistency

use miden_protocol::account::{AccountIdPrefix, AccountIdVersion};
use miden_protocol::utils::serde::{Deserializable, Serializable};

#[test]
fn test_accountid_prefix_endianness_roundtrip() {
    // Create a test AccountIdPrefix from known bytes
    let bytes: [u8; 8] = [170, 0, 0, 0, 0, 0, 188, 32];

    let prefix =
        AccountIdPrefix::read_from_bytes(&bytes).expect("failed to deserialize AccountIdPrefix");

    // Serialize back
    let serialized = prefix.to_bytes();

    // Verify roundtrip
    assert_eq!(
        bytes,
        serialized.as_slice(),
        "Roundtrip failed: serialized bytes don't match original"
    );
}

#[test]
fn test_accountid_prefix_version_extraction() {
    // Test that version byte is extracted correctly from various prefixes
    let test_cases = vec![
        ([170, 0, 0, 0, 0, 0, 188, 32], "Faucet ID"),
        ([188, 0, 0, 0, 0, 0, 202, 48], "Non-fungible faucet"),
    ];

    for (bytes, description) in test_cases {
        let prefix = AccountIdPrefix::read_from_bytes(&bytes)
            .unwrap_or_else(|err| panic!("Version extraction failed for {description}: {err}"));

        // Version should always be 0 for V0
        assert_eq!(
            prefix.version(),
            AccountIdVersion::Version0,
            "Expected Version0 for {description}"
        );
    }
}
