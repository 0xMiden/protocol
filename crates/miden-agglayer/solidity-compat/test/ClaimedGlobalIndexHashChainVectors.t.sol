// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/v2/sovereignChains/BridgeL2SovereignChain.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";
import "@agglayer/interfaces/IBasePolygonZkEVMGlobalExitRoot.sol";

contract MockGlobalExitRootManager is IBasePolygonZkEVMGlobalExitRoot {
    mapping(bytes32 => uint256) public override globalExitRootMap;

    function updateExitRoot(bytes32) external override {}

    function setGlobalExitRoot(bytes32 globalExitRoot) external {
        globalExitRootMap[globalExitRoot] = block.number;
    }
}

/**
 * @title ClaimedGlobalIndexHashChainVectors
 * @notice Generates a test vector for claimedGlobalIndexHashChain using _verifyLeafBridge.
 *
 * Run with: forge test -vv --match-test test_generateClaimedGlobalIndexHashChainVectors
 */
contract ClaimedGlobalIndexHashChainVectors is Test, BridgeL2SovereignChain {
    function test_generateClaimedGlobalIndexHashChainVectors() public {
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
            leafType,
            originNetwork,
            originTokenAddress,
            destinationNetwork,
            destinationAddress,
            amount,
            metadataHash
        );

        _addLeaf(leafValue);
        uint256 leafIndex = depositCount - 1;
        bytes32 localExitRoot = getRoot();

        // ====== GENERATE MERKLE PROOF ======
        bytes32[32] memory canonicalZeros = _computeCanonicalZeros();
        bytes32[32] memory smtProofLocalExitRoot =
            _generateLocalProof(leafIndex, canonicalZeros);
        bytes32[32] memory smtProofRollupExitRoot;

        // ====== COMPUTE EXIT ROOTS ======
        bytes32 mainnetExitRoot = localExitRoot;
        bytes32 rollupExitRoot = keccak256(abi.encodePacked("rollup_exit_root_simulated"));
        bytes32 globalExitRoot = GlobalExitRootLib.calculateGlobalExitRoot(
            mainnetExitRoot,
            rollupExitRoot
        );

        // ====== SET GLOBAL EXIT ROOT MANAGER ======
        MockGlobalExitRootManager gerManager = new MockGlobalExitRootManager();
        gerManager.setGlobalExitRoot(globalExitRoot);
        globalExitRootManager = IBasePolygonZkEVMGlobalExitRoot(address(gerManager));

        // Use a non-zero network ID to match sovereign-chain requirements
        networkID = 10;

        // ====== COMPUTE GLOBAL INDEX ======
        uint256 globalIndex = (uint256(1) << 64) | uint256(leafIndex);

        // ====== COMPUTE CLAIMED GLOBAL INDEX HASH CHAIN ======
        _verifyLeafBridge(
            smtProofLocalExitRoot,
            smtProofRollupExitRoot,
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

        // ====== SERIALIZE OUTPUT ======
        vm.serializeBytes32(obj, "global_index", bytes32(globalIndex));
        vm.serializeBytes32(obj, "leaf_value", leafValue);
        vm.serializeBytes32(obj, "claimed_global_index_hash_chain", claimedHashChain);
        string memory json = vm.serializeString(
            obj,
            "description",
            "Claimed global index hash chain vector from BridgeL2SovereignChain"
        );

        vm.writeJson(json, "test-vectors/claimed_global_index_hash_chain.json");
    }

    // ============================================================================================
    // Helpers (copied from DepositContractTestHelpers)
    // ============================================================================================

    function _computeCanonicalZeros() internal pure returns (bytes32[32] memory canonicalZeros) {
        bytes32 current = bytes32(0);
        for (uint256 i = 0; i < 32; i++) {
            canonicalZeros[i] = current;
            current = keccak256(abi.encodePacked(current, current));
        }
    }

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
