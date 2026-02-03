// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractBase.sol";

/**
 * @title SMTMerkleProofVectors
 * @notice Test contract that generates test vectors for Merkle proofs verification.
 * 
 * Run with: forge test -vv --match-contract SMTMerkleProofVectors
 * 
 * The output can be used during the bridge-in tests in
 * crates/miden-testing/tests/agglayer/bridge_in.rs
 */
contract SMTMerkleProofVectors is Test, DepositContractBase {

    /**
     * @notice Generates vectors of leaves, roots and merkle paths and saves them to the JSON.
     *         Notice that each value in the leaves/roots array corresponds to 32 values in the 
     *         merkle paths array.
     */
    function test_generateVerificationProofData() public {
        bytes32[] memory leaves = new bytes32[](32);
        bytes32[] memory roots = new bytes32[](32);
        bytes32[] memory merkle_paths = new bytes32[](1024); 

        for (uint256 i = 0; i < 32; i++) {
            // use bytes32(i + 1) as leaf here just to avoid the zero leaf
            bytes32 leaf = bytes32(i + 1);

            // Merkle path in the _branch array with index `i` actually corresponds to the leaf and
            // root with index `i - 1` (because the merkle path is computed based not on the index
            // of the last leaf, but on the overall number of leaves), so we first update the
            // merkle_paths array and only after that actually add a leaf. Luckily the empty SMT
            // has the _branch array instantiated with zeros, which is what we need.
            for (uint256 j = 0; j < 32; j++) {
                merkle_paths[i * 32 + j] = _branch[j];
            }

            _addLeaf(leaf);

            leaves[i] = leaf;
            roots[i] = getRoot();

            // perform the sanity check to make sure that the generated data is valid
            this.verifyMerkleProof(leaves[i], _branch, uint32(i), roots[i]);
        }

        // Serialize parallel arrays to JSON
        string memory obj = "root";
        vm.serializeBytes32(obj, "leaves", leaves);
        vm.serializeBytes32(obj, "roots", roots);
        string memory json = vm.serializeBytes32(obj, "merkle_paths", merkle_paths);

        // Save to file
        string memory outputPath = "test-vectors/merkle_proof_vectors.json";
        vm.writeJson(json, outputPath);
        console.log("Saved Merkle path vectors to:", outputPath);
    }
}