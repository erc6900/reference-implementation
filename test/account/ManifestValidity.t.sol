// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";

import {
    BadValidationMagicValue_PreValidationHook_Plugin,
    BadValidationMagicValue_PreExecHook_Plugin,
    BadValidationMagicValue_PostExecHook_Plugin,
    BadHookMagicValue_UserOpValidationFunction_Plugin,
    BadHookMagicValue_RuntimeValidationFunction_Plugin,
    BadHookMagicValue_PostExecHook_Plugin
} from "../mocks/plugins/ManifestValidityMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ManifestValidityTest is AccountTestBase {
    function setUp() public {
        _transferOwnershipToTest();
    }

    // Tests that the plugin manager rejects a plugin with a pre-runtime validation hook set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreValidationHook() public {
        BadValidationMagicValue_PreValidationHook_Plugin plugin =
            new BadValidationMagicValue_PreValidationHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-execution hook set to "validation always allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreExecHook() public {
        BadValidationMagicValue_PreExecHook_Plugin plugin = new BadValidationMagicValue_PreExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a post-execution hook set to "validation always allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PostExecHook() public {
        BadValidationMagicValue_PostExecHook_Plugin plugin = new BadValidationMagicValue_PostExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a user op validationFunction set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_UserOpValidation() public {
        BadHookMagicValue_UserOpValidationFunction_Plugin plugin =
            new BadHookMagicValue_UserOpValidationFunction_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a runtime validationFunction set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_RuntimeValidationFunction() public {
        BadHookMagicValue_RuntimeValidationFunction_Plugin plugin =
            new BadHookMagicValue_RuntimeValidationFunction_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a post-execution hook set to "hook always deny"
    function test_ManifestValidity_invalid_HookAlwaysDeny_PostExecHook() public {
        BadHookMagicValue_PostExecHook_Plugin plugin = new BadHookMagicValue_PostExecHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account1.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }
}
