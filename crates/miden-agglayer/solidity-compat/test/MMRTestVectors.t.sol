// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractV2.sol";

/**
 * @title MMRTestVectors
 * @notice Test contract that generates test vectors for verifying compatibility
 *         between Solidity's DepositContractBase and Miden's MMR Frontier implementation.
 *
 *         Leaves are constructed via getLeafValue using the same hardcoded fields that
 *         bridge_out.masm uses (leafType=0, originNetwork=64, originTokenAddress=fixed random value,
 *         metadataHash=0), parametrised by amount (i+1) and deterministic per-leaf
 *         destination network/address values derived from a fixed seed.
 *
 * Run with: forge test -vv --match-contract MMRTestVectors
 *
 * The output can be compared against the Rust KeccakMmrFrontier32 implementation
 * in crates/miden-testing/tests/agglayer/mmr_frontier.rs
 */
contract MMRTestVectors is Test, DepositContractV2 {
    // Constants matching bridge_out.masm hardcoded values
    uint8 constant LEAF_TYPE = 0;
    uint32 constant ORIGIN_NETWORK = 64;
    address constant ORIGIN_TOKEN_ADDR = 0x7a6fC3e8b57c6D1924F1A9d0E2b3c4D5e6F70891;
    bytes32 constant METADATA_HASH = bytes32(0);

    // Fixed seed for deterministic "random" destination vectors.
    // Keeping this constant ensures everyone regenerates the exact same JSON vectors.
    uint256 constant VECTOR_SEED = uint256(keccak256("miden::agglayer::mmr_frontier_vectors::v2"));

    /**
     * @notice Builds a leaf hash identical to what bridge_out.masm would produce for the
     *         given amount.
     */
    function _createLeaf(uint256 amount, uint32 destinationNetwork, address destinationAddress)
        internal
        pure
        returns (bytes32)
    {
        return getLeafValue(
            LEAF_TYPE, ORIGIN_NETWORK, ORIGIN_TOKEN_ADDR, destinationNetwork, destinationAddress, amount, METADATA_HASH
        );
    }

    function _destinationNetworkAt(uint256 idx) internal pure returns (uint32) {
        return uint32(uint256(keccak256(abi.encodePacked(VECTOR_SEED, bytes1(0x01), idx))));
    }

    function _destinationAddressAt(uint256 idx) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(VECTOR_SEED, bytes1(0x02), idx)))));
    }

    /**
     * @notice Generates the canonical zeros and saves to JSON file.
     *         ZERO_0 = 0x0...0 (32 zero bytes)
     *         ZERO_n = keccak256(ZERO_{n-1} || ZERO_{n-1})
     *
     *         Output file: test-vectors/canonical_zeros.json
     */
    function test_generateCanonicalZeros() public {
        bytes32[] memory zeros = new bytes32[](32);

        bytes32 z = bytes32(0);
        for (uint256 i = 0; i < 32; i++) {
            zeros[i] = z;
            z = keccak256(abi.encodePacked(z, z));
        }

        // Foundry serializes bytes32[] to a JSON array automatically
        string memory json = vm.serializeBytes32("root", "canonical_zeros", zeros);

        // Save to file
        string memory outputPath = "test-vectors/canonical_zeros.json";
        vm.writeJson(json, outputPath);
        console.log("Saved canonical zeros to:", outputPath);
    }

    /**
     * @notice Generates MMR frontier vectors (leaf-root pairs) and saves to JSON file.
     *         Each leaf is created via _createLeaf(i+1, network[i], address[i]) so that:
     *         - amounts are 1..32
     *         - destination networks/addresses are deterministic per index from VECTOR_SEED
     *
     *         The destination vectors are also written to JSON so the Rust bridge_out test
     *         can construct matching B2AGG notes.
     *
     *         Output file: test-vectors/mmr_frontier_vectors.json
     */
    function test_generateVectors() public {
        bytes32[] memory leaves = new bytes32[](32);
        bytes32[] memory roots = new bytes32[](32);
        uint256[] memory counts = new uint256[](32);
        uint256[] memory amounts = new uint256[](32);
        uint256[] memory destinationNetworks = new uint256[](32);
        address[] memory destinationAddresses = new address[](32);

        for (uint256 i = 0; i < 32; i++) {
            uint256 amount = i + 1;
            uint32 destinationNetwork = _destinationNetworkAt(i);
            address destinationAddress = _destinationAddressAt(i);
            bytes32 leaf = _createLeaf(amount, destinationNetwork, destinationAddress);
            _addLeaf(leaf);

            leaves[i] = leaf;
            roots[i] = getRoot();
            counts[i] = depositCount;
            amounts[i] = amount;
            destinationNetworks[i] = destinationNetwork;
            destinationAddresses[i] = destinationAddress;
        }

        // Serialize parallel arrays to JSON
        string memory obj = "root";
        vm.serializeBytes32(obj, "leaves", leaves);
        vm.serializeBytes32(obj, "roots", roots);
        vm.serializeUint(obj, "counts", counts);
        vm.serializeUint(obj, "amounts", amounts);
        vm.serializeUint(obj, "destination_networks", destinationNetworks);
        vm.serializeAddress(obj, "origin_token_address", ORIGIN_TOKEN_ADDR);
        string memory json = vm.serializeAddress(obj, "destination_addresses", destinationAddresses);

        // Save to file
        string memory outputPath = "test-vectors/mmr_frontier_vectors.json";
        vm.writeJson(json, outputPath);
        console.log("Saved MMR frontier vectors to:", outputPath);
    }
}
