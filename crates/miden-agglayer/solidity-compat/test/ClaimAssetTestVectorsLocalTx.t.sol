// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractV2.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";

/**
 * @title ClaimAssetTestVectorsLocalTx
 * @notice Test contract that generates test vectors for an L1 bridgeAsset transaction.
 *         This simulates calling bridgeAsset() on the PolygonZkEVMBridgeV2 contract
 *         and captures all relevant data including VALID Merkle proofs.
 *
 * Run with: forge test -vv --match-contract ClaimAssetTestVectorsLocalTx
 *
 * The output can be used to verify Miden's ability to process L1 bridge transactions.
 */
contract ClaimAssetTestVectorsLocalTx is Test, DepositContractV2 {
    /**
     * @notice Generates bridge asset test vectors with VALID Merkle proofs.
     *         Simulates a user calling bridgeAsset() to bridge tokens from L1 to Miden.
     *
     *         Output file: test-vectors/bridge_asset_vectors.json
     */
    function test_generateClaimAssetVectorsLocalTx() public {
        string memory obj = "root";

        // ====== BRIDGE TRANSACTION PARAMETERS ======

        uint8 leafType = 0;
        uint32 originNetwork = 0;
        address originTokenAddress = 0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF;
        uint32 destinationNetwork = 20;
        address destinationAddress = 0x00000000AA0000000000bb000000cc000000Dd00;
        uint256 amount = 1000000000000000;

        bytes memory metadata = abi.encode("Test Token", "TEST", uint8(18));
        bytes32 metadataHash = keccak256(metadata);

        // ====== COMPUTE LEAF VALUE AND ADD TO TREE ======

        bytes32 leafValue = getLeafValue(
            leafType, originNetwork, originTokenAddress, destinationNetwork, destinationAddress, amount, metadataHash
        );

        // Add the leaf to the deposit tree to generate valid Merkle proof
        _addLeaf(leafValue);

        // Get the deposit count (leaf index) - depositCount is uint256 in DepositContractBase
        uint256 depositCountValue = uint256(depositCount);

        // Get the local exit root (root of the deposit tree)
        bytes32 localExitRoot = getRoot();

        // ====== GENERATE MERKLE PROOF ======

        // Generate canonical zeros for the Merkle proof
        bytes32[32] memory canonicalZeros = _computeCanonicalZeros();

        // Build the Merkle proof from _branch array and canonical zeros
        // The leaf index is depositCountValue - 1 (0-indexed)
        uint256 leafIndex = depositCountValue - 1;
        bytes32[32] memory smtProofLocal = _generateLocalProof(leafIndex, canonicalZeros);

        // For mainnet deposits, the rollup proof is all zeros
        bytes32[32] memory smtProofRollup;
        for (uint256 i = 0; i < 32; i++) {
            smtProofRollup[i] = bytes32(0);
        }

        // ====== COMPUTE EXIT ROOTS ======

        // For a simulated L1 bridge transaction:
        // - mainnetExitRoot is the local exit root from the deposit tree
        // - rollupExitRoot is simulated (deterministic for reproducibility)
        bytes32 mainnetExitRoot = localExitRoot;
        bytes32 rollupExitRoot = keccak256(abi.encodePacked("rollup_exit_root_simulated"));

        // Compute global exit root
        bytes32 globalExitRoot = GlobalExitRootLib.calculateGlobalExitRoot(mainnetExitRoot, rollupExitRoot);

        // ====== VERIFY MERKLE PROOF ======

        // Verify that the generated proof is valid
        require(
            this.verifyMerkleProof(leafValue, smtProofLocal, uint32(leafIndex), mainnetExitRoot),
            "Generated Merkle proof is invalid!"
        );

        // ====== COMPUTE GLOBAL INDEX ======

        // Global index for mainnet deposits: (1 << 64) | leafIndex
        // Note: leafIndex is 0-based (depositCount - 1), matching how the bridge contract
        // extracts it via uint32(globalIndex) in _verifyLeaf()
        uint256 globalIndex = (uint256(1) << 64) | uint256(leafIndex);

        // ====== SERIALIZE SMT PROOFS ======
        _serializeProofs(obj, smtProofLocal, smtProofRollup);

        // Scoped block 2: Serialize transaction parameters
        {
            vm.serializeUint(obj, "leaf_type", leafType);
            vm.serializeUint(obj, "origin_network", originNetwork);
            vm.serializeAddress(obj, "origin_token_address", originTokenAddress);
            vm.serializeUint(obj, "destination_network", destinationNetwork);
            vm.serializeAddress(obj, "destination_address", destinationAddress);
            vm.serializeUint(obj, "amount", amount);
            vm.serializeBytes(obj, "metadata", metadata);
            vm.serializeBytes32(obj, "metadata_hash", metadataHash);
            vm.serializeBytes32(obj, "leaf_value", leafValue);
        }

        // Scoped block 3: Serialize state, exit roots, and finalize
        {
            vm.serializeUint(obj, "deposit_count", depositCountValue);
            vm.serializeBytes32(obj, "global_index", bytes32(globalIndex));
            vm.serializeBytes32(obj, "local_exit_root", localExitRoot);
            vm.serializeBytes32(obj, "mainnet_exit_root", mainnetExitRoot);
            vm.serializeBytes32(obj, "rollup_exit_root", rollupExitRoot);
            vm.serializeBytes32(obj, "global_exit_root", globalExitRoot);

            string memory json = vm.serializeString(
                obj, "description", "L1 bridgeAsset transaction test vectors with valid Merkle proofs"
            );

            string memory outputPath = "test-vectors/claim_asset_vectors_local_tx.json";
            vm.writeJson(json, outputPath);

            console.log("Generated claim asset local tx test vectors with valid Merkle proofs");
            console.log("Output file:", outputPath);
            console.log("Leaf index:", leafIndex);
            console.log("Deposit count:", depositCountValue);
        }
    }

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
     * @notice Generates the SMT proof for the local exit root.
     * @dev For each level i:
     *      - If bit i of leafIndex is 1: use _branch[i] (sibling on left)
     *      - If bit i of leafIndex is 0: use canonicalZeros[i] (sibling on right)
     * @param leafIndex The 0-indexed position of the leaf in the tree
     * @param canonicalZeros The precomputed canonical zero hashes
     * @return smtProofLocal The 32-element Merkle proof array
     */
    function _generateLocalProof(uint256 leafIndex, bytes32[32] memory canonicalZeros)
        internal
        view
        returns (bytes32[32] memory smtProofLocal)
    {
        for (uint256 i = 0; i < 32; i++) {
            // Check if bit i of leafIndex is set
            if ((leafIndex >> i) & 1 == 1) {
                // Bit is 1: sibling is on the left, use _branch[i]
                smtProofLocal[i] = _branch[i];
            } else {
                // Bit is 0: sibling is on the right (or doesn't exist), use zero hash
                smtProofLocal[i] = canonicalZeros[i];
            }
        }
    }

    /**
     * @notice Helper function to serialize SMT proofs (avoids stack too deep)
     * @param obj The JSON object key
     * @param smtProofLocal The local exit root proof
     * @param smtProofRollup The rollup exit root proof
     */
    function _serializeProofs(string memory obj, bytes32[32] memory smtProofLocal, bytes32[32] memory smtProofRollup)
        internal
    {
        bytes32[] memory smtProofLocalDyn = new bytes32[](32);
        bytes32[] memory smtProofRollupDyn = new bytes32[](32);
        for (uint256 i = 0; i < 32; i++) {
            smtProofLocalDyn[i] = smtProofLocal[i];
            smtProofRollupDyn[i] = smtProofRollup[i];
        }

        vm.serializeBytes32(obj, "smt_proof_local_exit_root", smtProofLocalDyn);
        vm.serializeBytes32(obj, "smt_proof_rollup_exit_root", smtProofRollupDyn);
    }
}
