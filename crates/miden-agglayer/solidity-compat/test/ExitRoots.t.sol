// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@agglayer/lib/GlobalExitRootLib.sol";

/**
 * @title ExitRootsTestVectors
 * @notice Test contract that generates global exit root test vectors from
 *         mainnet-rollup exit root pairs.
 * 
 * Run with: forge test -vv --match-contract ExitRootsTestVectors
 * 
 * The output can be compared against Rust implementations that compute
 * the global exit root as keccak256(mainnetExitRoot || rollupExitRoot).
 */
contract ExitRootsTestVectors is Test {
    
    /**
     * @notice Generates global exit root vectors from mainnet-rollup pairs
     *         and saves to JSON file.
     *
     *         Output file: test-vectors/exit_roots.json
     */
    function test_generateExitRootVectors() public {
        // Input: pairs of (mainnetExitRoot, rollupExitRoot) from mainnet transactions
        // Source transaction hashes from https://explorer.lumia.org/:
        //   TX 1: 0xe1a20811d757c48eba534f63041f58cd39eec762bfb6e4496dccf4e675fd5619
        //   TX 2: 0xe64254ff002b3d46b46af077fa24c6ef5b54d950759d70d6d9a693b1d36de188
        bytes32[] memory mainnetExitRoots = new bytes32[](2);
        bytes32[] memory rollupExitRoots = new bytes32[](2);
        
        // Pair 1 (TX: 0xe1a20811d757c48eba534f63041f58cd39eec762bfb6e4496dccf4e675fd5619)
        mainnetExitRoots[0] = bytes32(0x98c911b6dcface93fd0bb490d09390f2f7f9fcf36fc208cbb36528a229298326);
        rollupExitRoots[0] = bytes32(0x6a2533a24cc2a3feecf5c09b6a270bbb24a5e2ce02c18c0e26cd54c3dddc2d70);
        
        // Pair 2 (TX: 0xe64254ff002b3d46b46af077fa24c6ef5b54d950759d70d6d9a693b1d36de188)
        mainnetExitRoots[1] = bytes32(0xbb71d991caf89fe64878259a61ae8d0b4310c176e66d90fd2370b02573e80c90);
        rollupExitRoots[1] = bytes32(0xd9b546933b59acd388dc0c6520cbf2d4dbb9bac66f74f167ba70f221d82a440c);
        
        // Compute global exit roots
        bytes32[] memory globalExitRoots = new bytes32[](mainnetExitRoots.length);
        for (uint256 i = 0; i < mainnetExitRoots.length; i++) {
            globalExitRoots[i] = GlobalExitRootLib.calculateGlobalExitRoot(
                mainnetExitRoots[i],
                rollupExitRoots[i]
            );
        }

        // Serialize parallel arrays to JSON
        string memory obj = "root";
        vm.serializeBytes32(obj, "mainnet_exit_roots", mainnetExitRoots);
        vm.serializeBytes32(obj, "rollup_exit_roots", rollupExitRoots);
        string memory json = vm.serializeBytes32(obj, "global_exit_roots", globalExitRoots);

        // Save to file
        string memory outputPath = "test-vectors/exit_roots.json";
        vm.writeJson(json, outputPath);
        console.log("Saved exit root vectors to:", outputPath);
    }
}
