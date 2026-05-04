// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/lib/DepositContractV2.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";
import "@agglayer/interfaces/IBasePolygonZkEVMGlobalExitRoot.sol";
import "./DepositContractTestHelpers.sol";

contract MockGlobalExitRootManagerRollup is IBasePolygonZkEVMGlobalExitRoot {
    mapping(bytes32 => uint256) public override globalExitRootMap;

    function updateExitRoot(bytes32) external override {}

    function setGlobalExitRoot(bytes32 globalExitRoot) external {
        globalExitRootMap[globalExitRoot] = block.number;
    }
}

/**
 * @title RollupExitTree
 * @notice Simulates the rollup exit tree from PolygonRollupManager.
 *         Each registered rollup has a fixed slot (rollupID - 1). The tree is a depth-32
 *         Merkle tree where unregistered positions contain zero leaves.
 *         See PolygonRollupManager.getRollupExitRoot() for the production implementation.
 */
contract RollupExitTree is DepositContractBase, DepositContractTestHelpers {
    /// @notice Place a local exit root at a specific rollup index (= rollupID - 1).
    ///         Earlier positions are filled with zero leaves (unregistered rollups).
    function setLocalExitRootAt(bytes32 localExitRoot, uint256 rollupIndex) external {
        for (uint256 i = 0; i < rollupIndex; i++) {
            _addLeaf(bytes32(0));
        }
        _addLeaf(localExitRoot);
    }

    function generateProof(uint256 leafIndex) external view returns (bytes32[32] memory) {
        bytes32[32] memory canonicalZeros = _computeCanonicalZeros();
        return _generateLocalProof(leafIndex, canonicalZeros);
    }
}

/**
 * @title ClaimAssetTestVectorsRollupTx
 * @notice Test contract that generates test vectors for a rollup deposit (mainnet_flag=0).
 *         This simulates a deposit on a rollup chain whose local exit root is then included
 *         in the rollup exit tree, requiring two-level Merkle proof verification.
 *
 *         Uses non-zero leafIndex and indexRollup to exercise byte-ordering paths.
 *
 * Run with: forge test -vv --match-contract ClaimAssetTestVectorsRollupTx
 *
 * The output can be used to verify Miden's ability to process rollup bridge transactions.
 */
contract ClaimAssetTestVectorsRollupTx is Test, DepositContractV2, DepositContractTestHelpers {
    /**
     * @notice Generates rollup deposit test vectors with valid two-level Merkle proofs.
     *
     *         Output file: test-vectors/claim_asset_vectors_l2_tx.json
     */
    function test_generateClaimAssetVectorsRollupTx() public {
        string memory obj = "root";

        // ====== BRIDGE TRANSACTION PARAMETERS ======

        uint8 leafType = 0;
        uint32 originNetwork = 3; // rollup network ID
        address originTokenAddress = 0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF;
        uint32 destinationNetwork = 77;
        // Destination address with zero MSB (embeds a Miden AccountId)
        address destinationAddress = 0x00000000AA0000000000bb000000cc000000Dd00;
        uint256 amount = 100000000000000000000;

        bytes memory metadata = abi.encode("Test Token", "TEST", uint8(18));
        bytes32 metadataHash = keccak256(metadata);

        // ====== STEP 1: BUILD THE ROLLUP'S LOCAL EXIT TREE ======
        // Add dummy leaves before the target to get a non-zero leafIndex,
        // exercising byte-swap paths in the MASM verification.

        bytes32 leafValue = getLeafValue(
            leafType, originNetwork, originTokenAddress, destinationNetwork, destinationAddress, amount, metadataHash
        );

        // Add 2 dummy deposits before the real one -> leafIndex = 2
        _addLeaf(keccak256("dummy_deposit_0"));
        _addLeaf(keccak256("dummy_deposit_1"));
        _addLeaf(leafValue);

        uint256 leafIndex = depositCount - 1; // = 2
        bytes32 localExitRoot = getRoot();

        // Generate the local exit root proof (leaf -> localExitRoot)
        bytes32[32] memory canonicalZeros = _computeCanonicalZeros();
        bytes32[32] memory smtProofLocal = _generateLocalProof(leafIndex, canonicalZeros);

        // Verify local proof is valid
        require(
            this.verifyMerkleProof(leafValue, smtProofLocal, uint32(leafIndex), localExitRoot),
            "Local Merkle proof is invalid!"
        );

        // ====== STEP 2: BUILD THE ROLLUP EXIT TREE ======
        // The rollup exit tree is a sparse Merkle tree where each rollup has a fixed slot
        // at position (rollupID - 1). We place our localExitRoot at indexRollup = 5
        // (simulating rollupID = 6, with 5 earlier rollups having no bridge activity).

        RollupExitTree rollupTree = new RollupExitTree();

        uint256 indexRollup = 5;
        rollupTree.setLocalExitRootAt(localExitRoot, indexRollup);

        bytes32 rollupExitRoot = rollupTree.getRoot();

        // Generate the rollup exit root proof (localExitRoot -> rollupExitRoot)
        bytes32[32] memory smtProofRollup = rollupTree.generateProof(indexRollup);

        // Verify rollup proof is valid
        require(
            rollupTree.verifyMerkleProof(localExitRoot, smtProofRollup, uint32(indexRollup), rollupExitRoot),
            "Rollup Merkle proof is invalid!"
        );

        // ====== STEP 3: VERIFY TWO-LEVEL PROOF (matching Solidity _verifyLeaf rollup path) ======
        // For rollup deposits, verification is:
        //   1. calculateRoot(leafValue, smtProofLocal, leafIndex) == localExitRoot
        //   2. verifyMerkleProof(localExitRoot, smtProofRollup, indexRollup, rollupExitRoot)

        bytes32 computedLocalRoot = this.calculateRoot(leafValue, smtProofLocal, uint32(leafIndex));
        require(computedLocalRoot == localExitRoot, "Two-level step 1 failed: computed local root mismatch");
        require(
            this.verifyMerkleProof(computedLocalRoot, smtProofRollup, uint32(indexRollup), rollupExitRoot),
            "Two-level step 2 failed: rollup proof verification failed"
        );

        // ====== STEP 4: COMPUTE EXIT ROOTS AND GLOBAL INDEX ======

        // For a rollup deposit, mainnetExitRoot is arbitrary (simulated)
        bytes32 mainnetExitRoot = keccak256(abi.encodePacked("mainnet_exit_root_simulated"));

        // Compute global exit root
        bytes32 globalExitRoot = GlobalExitRootLib.calculateGlobalExitRoot(mainnetExitRoot, rollupExitRoot);

        // Global index for rollup deposits: (indexRollup << 32) | leafIndex (no mainnet flag bit)
        uint256 globalIndex = (uint256(indexRollup) << 32) | uint256(leafIndex);

        // ====== STEP 5: COMPUTE CLAIMED GLOBAL INDEX HASH CHAIN ======
        // Use the actual BridgeL2SovereignChain to compute the authoritative value.

        MockGlobalExitRootManagerRollup gerManager = new MockGlobalExitRootManagerRollup();
        gerManager.setGlobalExitRoot(globalExitRoot);
        globalExitRootManager = IBasePolygonZkEVMGlobalExitRoot(address(gerManager));

        // Use a non-zero network ID to match sovereign-chain requirements
        networkID = 10;

        // Call _verifyLeafBridge to update claimedGlobalIndexHashChain
        this.verifyLeafBridgeHarness(
            smtProofLocal,
            smtProofRollup,
            globalIndex,
            mainnetExitRoot,
            rollupExitRoot,
            leafType,
            originNetwork,
            originTokenAddress,
            destinationNetwork,
            destinationAddress,
            amount,
            metadataHash
        );

        bytes32 claimedHashChain = claimedGlobalIndexHashChain;

        // ====== SERIALIZE TO JSON ======
        _serializeProofs(obj, smtProofLocal, smtProofRollup);

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

        {
            vm.serializeUint(obj, "deposit_count", uint256(depositCount));
            vm.serializeBytes32(obj, "global_index", bytes32(globalIndex));
            vm.serializeBytes32(obj, "claimed_global_index_hash_chain", claimedHashChain);
            vm.serializeBytes32(obj, "local_exit_root", localExitRoot);
            vm.serializeBytes32(obj, "mainnet_exit_root", mainnetExitRoot);
            vm.serializeBytes32(obj, "rollup_exit_root", rollupExitRoot);
            vm.serializeBytes32(obj, "global_exit_root", globalExitRoot);

            string memory json = vm.serializeString(
                obj, "description", "Rollup deposit test vectors with valid two-level Merkle proofs (non-zero indices)"
            );

            string memory outputPath = "test-vectors/claim_asset_vectors_l2_tx.json";
            vm.writeJson(json, outputPath);

            console.log("Generated rollup deposit test vectors with valid two-level Merkle proofs");
            console.log("Output file:", outputPath);
            console.log("Leaf index:", leafIndex);
            console.log("Rollup index:", indexRollup);
        }
    }

    /**
     * @notice Helper function to serialize SMT proofs (avoids stack too deep)
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
