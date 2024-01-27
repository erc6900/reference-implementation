// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {
    BadValidationMagicValue_UserOp_Plugin,
    BadValidationMagicValue_PreRuntimeValidationHook_Plugin,
    BadValidationMagicValue_PreUserOpValidationHook_Plugin,
    BadValidationMagicValue_PreExecHook_Plugin,
    BadValidationMagicValue_PostExecHook_Plugin,
    BadHookMagicValue_UserOpValidationFunction_Plugin,
    BadHookMagicValue_RuntimeValidationFunction_Plugin,
    BadHookMagicValue_PostExecHook_Plugin
} from "../mocks/plugins/ManifestValidityMocks.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract ManifestValidityTest is OptimizedTest {
    EntryPoint public entryPoint; // Just to be able to construct the factory
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;

    UpgradeableModularAccount public account;

    function setUp() public {
        entryPoint = new EntryPoint();
        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        // Create an account with "this" as the owner, so we can execute along the runtime path with regular
        // solidity semantics
        account = factory.createAccount(address(this), 0);
    }

    // Tests that the plugin manager rejects a plugin with a user op validationFunction set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_UserOpValidationFunction() public {
        BadValidationMagicValue_UserOp_Plugin plugin = new BadValidationMagicValue_UserOp_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-runtime validation hook set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreRuntimeValidationHook() public {
        BadValidationMagicValue_PreRuntimeValidationHook_Plugin plugin =
            new BadValidationMagicValue_PreRuntimeValidationHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests that the plugin manager rejects a plugin with a pre-user op validation hook set to "validation always
    // allow"
    function test_ManifestValidity_invalid_ValidationAlwaysAllow_PreUserOpValidationHook() public {
        BadValidationMagicValue_PreUserOpValidationHook_Plugin plugin =
            new BadValidationMagicValue_PreUserOpValidationHook_Plugin();

        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        account.installPlugin({
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
        account.installPlugin({
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
        account.installPlugin({
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
        account.installPlugin({
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
        account.installPlugin({
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
        account.installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }
}
