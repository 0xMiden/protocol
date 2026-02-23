// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "./DepositContractTestHelpers.sol";

/**
 * @title SMTMerkleProofVectors
 * @notice Test contract that generates test vectors for Merkle proofs verification.
 *
 * Run with: forge test -vv --match-contract SMTMerkleProofVectors
 *
 * The output can be used during the bridge-in tests in
 * crates/miden-testing/tests/agglayer/bridge_in.rs
 */
contract SMTMerkleProofVectors is Test, DepositContractTestHelpers {
    /**
     * @notice Generates vectors of leaves, roots and merkle paths and saves them to the JSON.
     *         Notice that each value in the leaves/roots array corresponds to 32 values in the
     *         merkle paths array.
     */
    function test_generateVerificationProofData() public {
        bytes32[] memory leaves = new bytes32[](32);
        bytes32[] memory roots = new bytes32[](32);
        bytes32[] memory merkle_paths = new bytes32[](1024);

        // This array represents a merkle path during each iteration.
        // This is a workaround which allows to provide the merkle path to verifyMerkleProof
        // since the merkle_paths array cannot be sliced.
        bytes32[32] memory current_path;

        bytes32[32] memory canonicalZeros = _computeCanonicalZeros();

        // generate leaves, roots, and merkle_paths arrays
        for (uint256 i = 0; i < 32; i++) {
            // use bytes32(i + 1) as leaf here just to avoid the zero leaf
            bytes32 leaf = bytes32(i + 1);

            // Merkle path in the _branch array during the `i`th iteration actually corresponds to
            // the leaf and root with indexes `i - 1` (because the merkle path is computed based on
            // the overall number of leaves in the SMT instead of the index of the last leaf), so we
            // first update the merkle_paths array and only after that actually add a leaf and
            // recompute the _branch.
            current_path = _generateLocalProof(i, canonicalZeros);
            for (uint256 j = 0; j < 32; j++) {
                merkle_paths[i * 32 + j] = current_path[j];
            }

            _addLeaf(leaf);

            leaves[i] = leaf;
            roots[i] = getRoot();

            // perform the sanity check to make sure that the generated data is valid
            assert(this.verifyMerkleProof(leaves[i], current_path, uint32(i), roots[i]));
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
