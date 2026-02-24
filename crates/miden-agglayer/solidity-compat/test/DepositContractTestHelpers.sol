// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@agglayer/v2/lib/DepositContractBase.sol";

/**
 * @title DepositContractTestHelpers
 * @notice Shared helpers for Sparse Merkle Tree test vector generation.
 *         Inherited by SMTMerkleProofVectors and ClaimAssetTestVectorsLocalTx.
 */
abstract contract DepositContractTestHelpers is DepositContractBase {
    /**
     * @notice Computes the canonical zero hashes for the Sparse Merkle Tree.
     * @dev Each level i has zero hash: keccak256(zero[i-1], zero[i-1])
     * @return canonicalZeros Array of 32 zero hashes, one per tree level
     */
    function _computeCanonicalZeros() internal pure returns (bytes32[32] memory canonicalZeros) {
        bytes32 current = bytes32(0);
        for (uint256 i = 0; i < 32; i++) {
            canonicalZeros[i] = current;
            current = keccak256(abi.encodePacked(current, current));
        }
    }

    /**
     * @notice Generates the SMT proof for a given leaf index using the current _branch state.
     * @dev For each level i:
     *      - If bit i of leafIndex is 1: use _branch[i] (sibling on left)
     *      - If bit i of leafIndex is 0: use canonicalZeros[i] (sibling on right)
     * @param leafIndex The 0-indexed position of the leaf in the tree
     * @param canonicalZeros The precomputed canonical zero hashes
     * @return smtProof The 32-element Merkle proof array
     */
    function _generateLocalProof(uint256 leafIndex, bytes32[32] memory canonicalZeros)
        internal
        view
        returns (bytes32[32] memory smtProof)
    {
        for (uint256 i = 0; i < 32; i++) {
            if ((leafIndex >> i) & 1 == 1) {
                smtProof[i] = _branch[i];
            } else {
                smtProof[i] = canonicalZeros[i];
            }
        }
    }
}
