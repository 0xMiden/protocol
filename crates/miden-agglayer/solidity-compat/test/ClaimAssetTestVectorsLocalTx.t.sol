// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";
import "@agglayer/interfaces/IBasePolygonZkEVMGlobalExitRoot.sol";
import "./DepositContractTestHelpers.sol";

contract MockGlobalExitRootManagerLocal is IBasePolygonZkEVMGlobalExitRoot {
    mapping(bytes32 => uint256) public override globalExitRootMap;

    function updateExitRoot(bytes32) external override {}

    function setGlobalExitRoot(bytes32 globalExitRoot) external {
        globalExitRootMap[globalExitRoot] = block.number;
    }
}

/**
 * @title ClaimAssetTestVectorsLocalTx
 * @notice Test contract that generates test vectors for an L1 bridgeAsset transaction.
 *         This simulates calling bridgeAsset() on the PolygonZkEVMBridgeV2 contract
 *         and captures all relevant data including VALID Merkle proofs.
 *         Uses BridgeL2SovereignChain to get the authoritative claimedGlobalIndexHashChain.
 *
 * Run with: forge test -vv --match-contract ClaimAssetTestVectorsLocalTx
 *
 * The output can be used to verify Miden's ability to process L1 bridge transactions.
 */
contract ClaimAssetTestVectorsLocalTx is Test, DepositContractTestHelpers {
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
        uint256 amount = 100000000000000000000;

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

        // ====== COMPUTE CLAIMED GLOBAL INDEX HASH CHAIN ======
        // Use the actual BridgeL2SovereignChain to compute the authoritative value

        // Set up the global exit root manager
        MockGlobalExitRootManagerLocal gerManager = new MockGlobalExitRootManagerLocal();
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

        // Read the updated claimedGlobalIndexHashChain
        bytes32 claimedHashChain = claimedGlobalIndexHashChain;

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
            vm.serializeBytes32(obj, "claimed_global_index_hash_chain", claimedHashChain);
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
