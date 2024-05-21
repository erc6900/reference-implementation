// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";

import {BadHookMagicValue_ValidationFunction_Plugin} from "../mocks/plugins/ManifestValidityMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ManifestValidityTest is AccountTestBase {
    function setUp() public {
        _transferOwnershipToTest();
    }

    // Tests that the plugin manager rejects a plugin with a validation function set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_Validation() public {
        BadHookMagicValue_ValidationFunction_Plugin plugin = new BadHookMagicValue_ValidationFunction_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.prank(address(entryPoint));
        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }
}
