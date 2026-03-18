// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";
import "@agglayer/interfaces/IBasePolygonZkEVMGlobalExitRoot.sol";
import "./DepositContractTestHelpers.sol";

contract MockGlobalExitRootManagerReal is IBasePolygonZkEVMGlobalExitRoot {
    mapping(bytes32 => uint256) public override globalExitRootMap;

    function updateExitRoot(bytes32) external override {}

    function setGlobalExitRoot(bytes32 globalExitRoot) external {
        globalExitRootMap[globalExitRoot] = block.number;
    }
}

/**
 * @title ClaimAssetTestVectorsRealTx
 * @notice Test contract that generates comprehensive test vectors for verifying
 *         compatibility between Solidity's claimAsset and Miden's implementation.
 *         Uses BridgeL2SovereignChain to get the authoritative claimedGlobalIndexHashChain.
 *
 *         Generates vectors for both LeafData and ProofData from a real transaction.
 *
 * Run with: forge test -vv --match-contract ClaimAssetTestVectorsRealTx
 *
 * The output can be compared against the Rust ClaimNoteStorage implementation.
 */
contract ClaimAssetTestVectorsRealTx is Test, DepositContractTestHelpers {
    /**
     * @notice Generates claim asset test vectors from real Katana transaction and saves to JSON.
     *         Uses real transaction data from Katana explorer:
     *         https://katanascan.com/tx/0x685f6437c4a54f5d6c59ea33de74fe51bc2401fea65dc3d72a976def859309bf
     *
     *         Output file: test-vectors/claim_asset_vectors.json
     */
    function test_generateClaimAssetVectors() public {
        string memory obj = "root";

        // ====== PROOF DATA ======
        bytes32[32] memory smtProofLocalExitRoot;
        bytes32[32] memory smtProofRollupExitRoot;
        uint256 globalIndex;
        bytes32 mainnetExitRoot;
        bytes32 rollupExitRoot;
        bytes32 globalExitRoot;

        // Scoped block keeps stack usage under Solidity limits.
        {
            // SMT proof for local exit root (32 nodes)
            smtProofLocalExitRoot = [
                bytes32(0x0000000000000000000000000000000000000000000000000000000000000000),
                bytes32(0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5),
                bytes32(0xb4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30),
                bytes32(0xe37d456460231cf80063f57ee83a02f70d810c568b3bfb71156d52445f7a885a),
                bytes32(0xe58769b32a1beaf1ea27375a44095a0d1fb664ce2dd358e7fcbfb78c26a19344),
                bytes32(0x0eb01ebfc9ed27500cd4dfc979272d1f0913cc9f66540d7e8005811109e1cf2d),
                bytes32(0x887c22bd8750d34016ac3c66b5ff102dacdd73f6b014e710b51e8022af9a1968),
                bytes32(0x3236bf576fca1adf85917ec7888c4b89cce988564b6028f7d66807763aaa7b04),
                bytes32(0x9867cc5f7f196b93bae1e27e6320742445d290f2263827498b54fec539f756af),
                bytes32(0x054ba828046324ff4794fce22adefb23b3ce749cd4df75ade2dc9f41dd327c31),
                bytes32(0x4e9220076c344bf223c7e7cb2d47c9f0096c48def6a9056e41568de4f01d2716),
                bytes32(0xca6369acd49a7515892f5936227037cc978a75853409b20f1145f1d44ceb7622),
                bytes32(0x5a925caf7bfdf31344037ba5b42657130d049f7cb9e87877317e79fce2543a0c),
                bytes32(0xc1df82d9c4b87413eae2ef048f94b4d3554cea73d92b0f7af96e0271c691e2bb),
                bytes32(0x5c67add7c6caf302256adedf7ab114da0acfe870d449a3a489f781d659e8becc),
                bytes32(0x4111a1a05cc06ad682bb0f213170d7d57049920d20fc4e0f7556a21b283a7e2a),
                bytes32(0x77a0f8b0e0b4e5a57f5e381b3892bb41a0bcdbfdf3c7d591fae02081159b594d),
                bytes32(0x361122b4b1d18ab577f2aeb6632c690713456a66a5670649ceb2c0a31e43ab46),
                bytes32(0x5a2dce0a8a7f68bb74560f8f71837c2c2ebbcbf7fffb42ae1896f13f7c7479a0),
                bytes32(0xb46a28b6f55540f89444f63de0378e3d121be09e06cc9ded1c20e65876d36aa0),
                bytes32(0xc65e9645644786b620e2dd2ad648ddfcbf4a7e5b1a3a4ecfe7f64667a3f0b7e2),
                bytes32(0xf4418588ed35a2458cffeb39b93d26f18d2ab13bdce6aee58e7b99359ec2dfd9),
                bytes32(0x5a9c16dc00d6ef18b7933a6f8dc65ccb55667138776f7dea101070dc8796e377),
                bytes32(0x4df84f40ae0c8229d0d6069e5c8f39a7c299677a09d367fc7b05e3bc380ee652),
                bytes32(0xcdc72595f74c7b1043d0e1ffbab734648c838dfb0527d971b602bc216c9619ef),
                bytes32(0x0abf5ac974a1ed57f4050aa510dd9c74f508277b39d7973bb2dfccc5eeb0618d),
                bytes32(0xb8cd74046ff337f0a7bf2c8e03e10f642c1886798d71806ab1e888d9e5ee87d0),
                bytes32(0x838c5655cb21c6cb83313b5a631175dff4963772cce9108188b34ac87c81c41e),
                bytes32(0x662ee4dd2dd7b2bc707961b1e646c4047669dcb6584f0d8d770daf5d7e7deb2e),
                bytes32(0x388ab20e2573d171a88108e79d820e98f26c0b84aa8b2f4aa4968dbb818ea322),
                bytes32(0x93237c50ba75ee485f4c22adf2f741400bdf8d6a9cc7df7ecae576221665d735),
                bytes32(0x8448818bb4ae4562849e949e17ac16e0be16688e156b5cf15e098c627c0056a9)
            ];

            // SMT proof for rollup exit root (32 nodes - all zeros for this rollup claim).
            for (uint256 i = 0; i < 32; i++) {
                smtProofRollupExitRoot[i] = bytes32(0);
            }

            // Global index (uint256) - encodes rollup_id and deposit_count.
            globalIndex = 18446744073709788808;

            // Exit roots
            mainnetExitRoot = 0x31d3268d3a0145d65482b336935fa07dab0822f7dccd865f361d2bf122c4905c;
            rollupExitRoot = 0x8452a95fd710163c5fa8ca2b2fe720d8781f0222bb9e82c2a442ec986c374858;

            // Compute global exit root: keccak256(mainnetExitRoot || rollupExitRoot)
            globalExitRoot = GlobalExitRootLib.calculateGlobalExitRoot(mainnetExitRoot, rollupExitRoot);

            // forge-std JSON serialization supports `bytes32[]` but not `bytes32[32]`.
            bytes32[] memory smtProofLocalExitRootDyn = new bytes32[](32);
            bytes32[] memory smtProofRollupExitRootDyn = new bytes32[](32);
            for (uint256 i = 0; i < 32; i++) {
                smtProofLocalExitRootDyn[i] = smtProofLocalExitRoot[i];
                smtProofRollupExitRootDyn[i] = smtProofRollupExitRoot[i];
            }

            vm.serializeBytes32(obj, "smt_proof_local_exit_root", smtProofLocalExitRootDyn);
            vm.serializeBytes32(obj, "smt_proof_rollup_exit_root", smtProofRollupExitRootDyn);
            vm.serializeBytes32(obj, "global_index", bytes32(globalIndex));
            vm.serializeBytes32(obj, "mainnet_exit_root", mainnetExitRoot);
            vm.serializeBytes32(obj, "rollup_exit_root", rollupExitRoot);
            vm.serializeBytes32(obj, "global_exit_root", globalExitRoot);
        }

        // ====== LEAF DATA ======
        // Scoped block keeps stack usage under Solidity limits.
        {
            uint8 leafType = 0; // 0 for ERC20/ETH transfer
            uint32 originNetwork = 0;
            address originTokenAddress = 0x2DC70fb75b88d2eB4715bc06E1595E6D97c34DFF;
            uint32 destinationNetwork = 20;
            address destinationAddress = 0x00000000b0E79c68cafC54802726C6F102Cca300;
            uint256 amount = 100000000000000; // 1e14 (0.0001 vbETH)

            // Original metadata from the transaction (ABI encoded: name, symbol, decimals)
            // name = "Vault Bridge ETH", symbol = "vbETH", decimals = 18
            bytes memory metadata =
                hex"000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000105661756c7420427269646765204554480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000057662455448000000000000000000000000000000000000000000000000000000";
            bytes32 metadataHash = keccak256(metadata);

            // Compute the leaf value using the official DepositContractV2 implementation
            bytes32 leafValue = getLeafValue(
                leafType,
                originNetwork,
                originTokenAddress,
                destinationNetwork,
                destinationAddress,
                amount,
                metadataHash
            );

            // ====== COMPUTE CLAIMED GLOBAL INDEX HASH CHAIN ======
            // Use the actual BridgeL2SovereignChain to compute the authoritative value

            // Set up the global exit root manager
            MockGlobalExitRootManagerReal gerManager = new MockGlobalExitRootManagerReal();
            gerManager.setGlobalExitRoot(globalExitRoot);
            globalExitRootManager = IBasePolygonZkEVMGlobalExitRoot(address(gerManager));

            // Use a non-zero network ID to match sovereign-chain requirements
            networkID = 10;

            // Call _verifyLeafBridge to update claimedGlobalIndexHashChain
            this.verifyLeafBridgeHarness(
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

            // Read the updated claimedGlobalIndexHashChain
            bytes32 claimedHashChain = claimedGlobalIndexHashChain;

            vm.serializeUint(obj, "leaf_type", leafType);
            vm.serializeUint(obj, "origin_network", originNetwork);
            vm.serializeAddress(obj, "origin_token_address", originTokenAddress);
            vm.serializeUint(obj, "destination_network", destinationNetwork);
            vm.serializeAddress(obj, "destination_address", destinationAddress);
            vm.serializeUint(obj, "amount", amount);
            vm.serializeBytes32(obj, "metadata_hash", metadataHash);
            vm.serializeBytes32(obj, "leaf_value", leafValue);
            string memory json = vm.serializeBytes32(obj, "claimed_global_index_hash_chain", claimedHashChain);

            // Save to file
            string memory outputPath = "test-vectors/claim_asset_vectors_real_tx.json";
            vm.writeJson(json, outputPath);
        }
    }
}
