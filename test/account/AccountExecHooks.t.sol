// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {
    IPlugin,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExecutionHook,
    ManifestFunction,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {MockPlugin} from "../mocks/MockPlugin.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountExecHooksTest is AccountTestBase {
    MockPlugin public mockPlugin1;
    MockPlugin public mockPlugin2;
    bytes32 public manifestHash1;
    bytes32 public manifestHash2;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _BOTH_HOOKS_FUNCTION_ID_3 = 3;

    PluginManifest public m1;
    PluginManifest public m2;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        _transferOwnershipToTest();

        m1.executionFunctions.push(_EXEC_SELECTOR);

        m1.validationFunctions.push(
            ManifestAssociatedFunction({
                executionSelector: _EXEC_SELECTOR,
                associatedFunction: ManifestFunction({
                    functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                    functionId: 0,
                    dependencyIndex: 0
                })
            })
        );
    }

    function test_preExecHook_install() public {
        _installPlugin1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                isPreHook: true,
                isPostHook: false
            })
        );
    }

    /// @dev Plugin 1 hook pair: [1, null]
    ///      Expected execution: [1, null]
    function test_preExecHook_run() public {
        test_preExecHook_install();

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_preExecHook_uninstall() public {
        test_preExecHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_execHookPair_install() public {
        _installPlugin1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                functionId: _BOTH_HOOKS_FUNCTION_ID_3,
                isPreHook: true,
                isPostHook: true
            })
        );
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_execHookPair_run() public {
        test_execHookPair_install();

        vm.expectEmit(true, true, true, true);
        // pre hook call
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _BOTH_HOOKS_FUNCTION_ID_3,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );
        vm.expectEmit(true, true, true, true);
        // exec call
        emit ReceivedCall(abi.encodePacked(_EXEC_SELECTOR), 0);
        vm.expectEmit(true, true, true, true);
        // post hook call
        emit ReceivedCall(
            abi.encodeCall(IPlugin.postExecutionHook, (_BOTH_HOOKS_FUNCTION_ID_3, "")),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_execHookPair_uninstall() public {
        test_execHookPair_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_postOnlyExecHook_install() public {
        _installPlugin1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                isPreHook: false,
                isPostHook: true
            })
        );
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_run() public {
        test_postOnlyExecHook_install();

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_postOnlyExecHook_uninstall() public {
        test_postOnlyExecHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_overlappingPreValidationHooks_install() public {
        // Install the first plugin.
        _installPlugin1WithPreValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        // Expect the call to fail due to the "always deny" pre hook.
        vm.breakpoint("a");
        (bool success, bytes memory retData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(retData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        // Install a second plugin that applies the same pre hook on the same selector.
        _installPlugin2WithPreValidationHook(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
                functionId: 0,
                dependencyIndex: 0
            })
        );

        // Still expect the call to fail.
        (success, retData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(retData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        vm.stopPrank();
    }

    function test_overlappingPreValidationHooks_uninstall() public {
        test_overlappingPreValidationHooks_install();

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre validation hook of "always deny" to still exist.
        (bool success, bytes memory retData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(retData, abi.encodeWithSelector(UpgradeableModularAccount.AlwaysDenyRule.selector));

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // // Execution selector should no longer exist.
        (success, retData) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(
            retData,
            abi.encodeWithSelector(UpgradeableModularAccount.UnrecognizedFunction.selector, _EXEC_SELECTOR)
        );
    }

    function _installPlugin1WithHooks(ManifestExecutionHook memory execHooks) internal {
        m1.executionHooks.push(execHooks);
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, new FunctionReference[](0));

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function _installPlugin1WithPreValidationHook(bytes4 selector, ManifestFunction memory preValidationHook)
        internal
    {
        m1.preValidationHooks.push(
            ManifestAssociatedFunction({executionSelector: selector, associatedFunction: preValidationHook})
        );

        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, new FunctionReference[](0));

        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function _installPlugin2WithPreValidationHook(bytes4 selector, ManifestFunction memory preValidationHook)
        internal
    {
        m2.preValidationHooks.push(
            ManifestAssociatedFunction({executionSelector: selector, associatedFunction: preValidationHook})
        );

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin2), manifestHash2, new FunctionReference[](0));

        account1.installPlugin({
            plugin: address(mockPlugin2),
            manifestHash: manifestHash2,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""));
    }
}
