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
        bytes32[] memory canonical_zeros = new bytes32[](32);

        // This array represent a merkle path during each iteration.
        // This is a work around which allows to provide the merkle path to the verifyMerkleProof
        // function, since the merkle_paths array cannot be sliced.
        bytes32[32] memory current_path;
        
        // generate canonical zeros array
        bytes32 z = bytes32(0);
        for (uint256 i = 0; i < 32; i++) {
            canonical_zeros[i] = z;
            z = keccak256(abi.encodePacked(z, z));
        }

        // generate leaves, roots, and merkle_paths arrays
        for (uint256 i = 0; i < 32; i++) {
            // use bytes32(i + 1) as leaf here just to avoid the zero leaf
            bytes32 leaf = bytes32(i + 1);

            // Merkle path in the _branch array during the `i`th iteration actually corresponds to
            // the leaf and root with indexes `i - 1` (because the merkle path is computed based on
            // the overall number of leaves in the SMT instead of the index of the last leaf), so we
            // first update the merkle_paths array and only after that actually add a leaf and
            // recompute the _branch.
            //
            // Merkle paths in the _branch array contain plain zeros for the nodes which were not 
            // updated during the leaf insertion. To get the proper Merkle path we should use 
            // canonical zeros instead.
            for (uint256 j = 0; j < 32; j++) {
                if (i >> j & 1 == 1) {
                    merkle_paths[i * 32 + j] = _branch[j];
                    current_path[j] = _branch[j];
                } else {
                    merkle_paths[i * 32 + j] = canonical_zeros[j];
                    current_path[j] = canonical_zeros[j];
                }
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
