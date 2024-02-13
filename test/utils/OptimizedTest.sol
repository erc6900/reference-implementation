// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../../src/plugins/TokenReceiverPlugin.sol";

/// @dev This contract provides functions to deploy optimized (via IR) precompiled contracts. By compiling just
/// the source contracts (excluding the test suite) via IR, and using the resulting bytecode within the tests
/// (built without IR), we can avoid the significant overhead of compiling the entire test suite via IR.
///
/// To use the optimized precompiled contracts, the project must first be built with the "optimized-build" profile
/// to populate the artifacts in the `out-optimized` directory. Then use the "optimized-test" or
/// "optimized-test-deep" profile to run the tests.
///
/// To bypass this behavior for coverage or debugging, use the "default" profile.
abstract contract OptimizedTest is Test {
    function _isOptimizedTest() internal returns (bool) {
        string memory profile = vm.envOr("FOUNDRY_PROFILE", string("default"));
        return _isStringEq(profile, "optimized-test-deep") || _isStringEq(profile, "optimized-test");
    }

    function _isStringEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function _deployUpgradeableModularAccount(IEntryPoint entryPoint)
        internal
        returns (UpgradeableModularAccount)
    {
        return _isOptimizedTest()
            ? UpgradeableModularAccount(
                payable(
                    deployCode(
                        "out-optimized/UpgradeableModularAccount.sol/UpgradeableModularAccount.json",
                        abi.encode(entryPoint)
                    )
                )
            )
            : new UpgradeableModularAccount(entryPoint);
    }

    function _deploySingleOwnerPlugin() internal returns (SingleOwnerPlugin) {
        return _isOptimizedTest()
            ? SingleOwnerPlugin(deployCode("out-optimized/SingleOwnerPlugin.sol/SingleOwnerPlugin.json"))
            : new SingleOwnerPlugin();
    }

    function _deployTokenReceiverPlugin() internal returns (TokenReceiverPlugin) {
        return _isOptimizedTest()
            ? TokenReceiverPlugin(deployCode("out-optimized/TokenReceiverPlugin.sol/TokenReceiverPlugin.json"))
            : new TokenReceiverPlugin();
    }
}
