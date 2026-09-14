// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts5/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts5/utils/cryptography/MessageHashUtils.sol";

contract Eip712TestVectors is Test {
    bytes32 private constant DOMAIN_TYPE_HASH = keccak256("EIP712Domain(string name,string version)");
    bytes32 private constant TRANSACTION_TYPE_HASH = keccak256("MidenTransaction(bytes32 txSummaryHash)");
    bytes32 private constant TX_SUMMARY_HASH = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
    bytes32 private constant CHANGED_TX_SUMMARY_HASH =
        0x0100000000000000000000000000000000000000000000000000000000000000;
    uint256 private constant SIGNER_PRIVATE_KEY = 1;
    uint256 private constant DIFFERENT_SIGNER_PRIVATE_KEY = 2;

    function test_generateEip712TransactionSummaryVector() public {
        bytes32 domainSeparator = _domainSeparator("Miden Transaction", "1");
        bytes32 structHash = _structHash(TX_SUMMARY_HASH);
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        address expectedSigner = vm.addr(SIGNER_PRIVATE_KEY);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PRIVATE_KEY, digest);

        assertTrue(_isExpectedSigner(digest, v, r, s, expectedSigner));
        assertFalse(
            _isExpectedSigner(
                MessageHashUtils.toTypedDataHash(_domainSeparator("Another App", "1"), structHash),
                v,
                r,
                s,
                expectedSigner
            )
        );
        assertFalse(
            _isExpectedSigner(
                MessageHashUtils.toTypedDataHash(_domainSeparator("Miden Transaction", "2"), structHash),
                v,
                r,
                s,
                expectedSigner
            )
        );
        assertFalse(
            _isExpectedSigner(
                MessageHashUtils.toTypedDataHash(domainSeparator, _structHash(CHANGED_TX_SUMMARY_HASH)),
                v,
                r,
                s,
                expectedSigner
            )
        );
        assertFalse(_isExpectedSigner(digest, v, r, s, vm.addr(DIFFERENT_SIGNER_PRIVATE_KEY)));
        assertFalse(_isExpectedSigner(digest, v, bytes32(uint256(r) ^ 1), s, expectedSigner));

        string memory objectKey = "root";
        vm.serializeString(objectKey, "domain_name", "Miden Transaction");
        vm.serializeString(objectKey, "domain_version", "1");
        vm.serializeBytes32(objectKey, "tx_summary_hash", TX_SUMMARY_HASH);
        vm.serializeBytes32(objectKey, "changed_tx_summary_hash", CHANGED_TX_SUMMARY_HASH);
        vm.serializeBytes32(objectKey, "domain_separator", domainSeparator);
        vm.serializeBytes32(objectKey, "struct_hash", structHash);
        vm.serializeBytes32(objectKey, "digest", digest);
        vm.serializeBytes(
            objectKey, "public_key", hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        vm.serializeBytes(
            objectKey, "different_public_key", hex"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        );
        vm.serializeAddress(objectKey, "expected_signer", expectedSigner);
        vm.serializeAddress(objectKey, "different_expected_signer", vm.addr(DIFFERENT_SIGNER_PRIVATE_KEY));
        vm.serializeUint(objectKey, "signature_v", v);
        vm.serializeBytes32(objectKey, "signature_r", r);
        string memory json = vm.serializeBytes32(objectKey, "signature_s", s);

        vm.writeJson(json, "../../miden-testing/tests/standards/test-vectors/eip712_transaction_summary.json");
    }

    function _domainSeparator(string memory name, string memory version) private pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version))));
    }

    function _structHash(bytes32 txSummaryHash) private pure returns (bytes32) {
        return keccak256(abi.encode(TRANSACTION_TYPE_HASH, txSummaryHash));
    }

    function _isExpectedSigner(bytes32 digest, uint8 v, bytes32 r, bytes32 s, address expectedSigner)
        private
        pure
        returns (bool)
    {
        (address recovered, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, v, r, s);
        return error == ECDSA.RecoverError.NoError && recovered == expectedSigner;
    }
}
