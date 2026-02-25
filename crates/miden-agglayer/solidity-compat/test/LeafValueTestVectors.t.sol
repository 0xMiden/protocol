// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractV2.sol";

/**
 * @title LeafValueTestVectors
 * @notice Test contract that generates test vectors for verifying compatibility
 *         between Solidity's getLeafValue and Miden's keccak hash implementation.
 *
 * Run with: forge test -vv --match-contract LeafValueTestVectors
 *
 * The output can be compared against the Rust get_leaf_value implementation.
 */
contract LeafValueTestVectors is Test, DepositContractV2 {
    /**
     * @notice Generates leaf value test vectors and saves to JSON file.
     *         Uses real transaction data from Lumia explorer:
     *         https://explorer.lumia.org/tx/0xe64254ff002b3d46b46af077fa24c6ef5b54d950759d70d6d9a693b1d36de188
     *
     *         Output file: test-vectors/leaf_value_vectors.json
     */
    function test_generateLeafValueVectors() public {
        // Test vector from real Lumia bridge transaction
        uint8 leafType = 0; // 0 for ERC20/ETH transfer
        uint32 originNetwork = 0;
        address originTokenAddress = 0xD9343a049D5DBd89CD19DC6BcA8c48fB3a0a42a7;
        uint32 destinationNetwork = 7;
        address destinationAddress = 0xD9b20Fe633b609B01081aD0428e81f8Dd604F5C5;
        uint256 amount = 2000000000000000000; // 2e18

        // Original metadata from the transaction (ABI encoded: name, symbol, decimals)
        bytes memory metadata =
            hex"000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000b4c756d696120546f6b656e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054c554d4941000000000000000000000000000000000000000000000000000000";
        bytes32 metadataHash = keccak256(metadata);

        // Compute the leaf value using the official DepositContractV2 implementation
        bytes32 leafValue = getLeafValue(
            leafType, originNetwork, originTokenAddress, destinationNetwork, destinationAddress, amount, metadataHash
        );

        // Serialize to JSON
        string memory obj = "root";
        vm.serializeUint(obj, "leaf_type", leafType);
        vm.serializeUint(obj, "origin_network", originNetwork);
        vm.serializeAddress(obj, "origin_token_address", originTokenAddress);
        vm.serializeUint(obj, "destination_network", destinationNetwork);
        vm.serializeAddress(obj, "destination_address", destinationAddress);
        vm.serializeUint(obj, "amount", amount);
        vm.serializeBytes32(obj, "metadata_hash", metadataHash);
        string memory json = vm.serializeBytes32(obj, "leaf_value", leafValue);

        // Save to file
        string memory outputPath = "test-vectors/leaf_value_vectors.json";
        vm.writeJson(json, outputPath);
    }
}
