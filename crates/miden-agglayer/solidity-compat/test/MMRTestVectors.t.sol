// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractBase.sol";

/**
 * @title MMRTestVectors
 * @notice Test contract that generates test vectors for verifying compatibility
 *         between Solidity's DepositContractBase and Miden's MMR Frontier implementation.
 * 
 * Run with: forge test -vv --match-contract MMRTestVectors
 * 
 * The output can be compared against the Rust KeccakMmrFrontier32 implementation
 * in crates/miden-testing/tests/agglayer/mmr_frontier.rs
 */
contract MMRTestVectors is Test, DepositContractBase {
    
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
     *         Uses parallel arrays instead of array of objects for cleaner serialization.
     *         Output file: test-vectors/mmr_frontier_vectors.json
     */
    function test_generateVectors() public {
        bytes32[] memory leaves = new bytes32[](32);
        bytes32[] memory roots = new bytes32[](32);
        uint256[] memory counts = new uint256[](32);

        for (uint256 i = 0; i < 32; i++) {
            bytes32 leaf = bytes32(i);
            _addLeaf(leaf);

            leaves[i] = leaf;
            roots[i] = getRoot();
            counts[i] = depositCount;
        }

        // Serialize parallel arrays to JSON
        string memory obj = "root";
        vm.serializeBytes32(obj, "leaves", leaves);
        vm.serializeBytes32(obj, "roots", roots);
        string memory json = vm.serializeUint(obj, "counts", counts);

        // Save to file
        string memory outputPath = "test-vectors/mmr_frontier_vectors.json";
        vm.writeJson(json, outputPath);
        console.log("Saved MMR frontier vectors to:", outputPath);
    }
}
