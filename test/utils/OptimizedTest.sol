// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../../src/plugins/TokenReceiverPlugin.sol";
import {VersionRegistry} from "../../src/plugins/VersionRegistry.sol";
import {IVersionRegistry} from "../../src/interfaces/IVersionRegistry.sol";

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
    address internal constant BASE_PLUGIN_REGISTRY = 0x3Ce0Cbb4B0A4accCc21fC7a208d9b661d7039258;
    bytes4 private constant REGISTER_PLUGIN_SELECTOR = bytes4(keccak256(bytes('registerPlugin(address)')));

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
        SingleOwnerPlugin singleOwnerPlugin;
        VersionRegistry _versionRegistry = new VersionRegistry();
        vm.etch(BASE_PLUGIN_REGISTRY, address(_versionRegistry).code);

        if (_isOptimizedTest()) {
            singleOwnerPlugin =
                SingleOwnerPlugin(deployCode("out-optimized/SingleOwnerPlugin.sol/SingleOwnerPlugin.json"));
        } else {
            singleOwnerPlugin = new SingleOwnerPlugin();
        }

        address versionRegistry = singleOwnerPlugin.pluginManifest().versionRegistry;
        versionRegistry.call(abi.encodeWithSelector(REGISTER_PLUGIN_SELECTOR, address(singleOwnerPlugin), 1, 0, 0));

        return singleOwnerPlugin;
    }

    function _deployTokenReceiverPlugin() internal returns (TokenReceiverPlugin) {
        TokenReceiverPlugin tokenReceiverPlugin;

        if (_isOptimizedTest()) {
            tokenReceiverPlugin =
                TokenReceiverPlugin(deployCode("out-optimized/TokenReceiverPlugin.sol/TokenReceiverPlugin.json"));
        } else {
            tokenReceiverPlugin = new TokenReceiverPlugin();
        }

        address versionRegistry = tokenReceiverPlugin.pluginManifest().versionRegistry;
        versionRegistry.call(abi.encodeWithSelector(REGISTER_PLUGIN_SELECTOR, address(tokenReceiverPlugin), 1, 0, 0));

        return tokenReceiverPlugin;
    }
}
