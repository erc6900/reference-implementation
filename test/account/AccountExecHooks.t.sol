// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {
    IPlugin,
    ManifestExecutionHook,
    ManifestExecutionFunction,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {IExecutionHook} from "../../src/interfaces/IExecutionHook.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {MockPlugin} from "../mocks/MockPlugin.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountExecHooksTest is AccountTestBase {
    MockPlugin public mockPlugin1;
    bytes32 public manifestHash1;
    bytes32 public manifestHash2;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _BOTH_HOOKS_FUNCTION_ID_3 = 3;

    PluginManifest internal _m1;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        _transferOwnershipToTest();

        _m1.executionFunctions.push(
            ManifestExecutionFunction({
                executionSelector: _EXEC_SELECTOR,
                isPublic: true,
                allowDefaultValidation: false
            })
        );
    }

    function test_preExecHook_install() public {
        _installPlugin1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                isPreHook: true,
                isPostHook: false,
                requireUOContext: false
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
                IExecutionHook.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                abi.encodePacked(
                    address(this), // caller
                    uint256(0), // msg.value in call to account
                    abi.encodeWithSelector(_EXEC_SELECTOR)
                )
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
                isPostHook: true,
                requireUOContext: false
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
                IExecutionHook.preExecutionHook.selector,
                _BOTH_HOOKS_FUNCTION_ID_3,
                abi.encodePacked(
                    address(this), // caller
                    uint256(0), // msg.value in call to account
                    abi.encodeWithSelector(_EXEC_SELECTOR)
                )
            ),
            0 // msg value in call to plugin
        );
        vm.expectEmit(true, true, true, true);
        // exec call
        emit ReceivedCall(abi.encodePacked(_EXEC_SELECTOR), 0);
        vm.expectEmit(true, true, true, true);
        // post hook call
        emit ReceivedCall(
            abi.encodeCall(IExecutionHook.postExecutionHook, (_BOTH_HOOKS_FUNCTION_ID_3, "")),
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
                isPostHook: true,
                requireUOContext: false
            })
        );
    }

    /// @dev Plugin 1 hook pair: [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyExecHook_run() public {
        test_postOnlyExecHook_install();

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IExecutionHook.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_postOnlyExecHook_uninstall() public {
        test_postOnlyExecHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_requireUOContextHook() public {
        _installPlugin1WithHooks(
            ManifestExecutionHook({
                executionSelector: _EXEC_SELECTOR,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                isPreHook: false,
                isPostHook: true,
                requireUOContext: true
            })
        );

        (bool success, bytes memory errMsg) = address(account1).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
        assertEq(errMsg.length, 4);
        assertEq(bytes4(errMsg), UpgradeableModularAccount.RequireUserOperationContext.selector);
    }

    function _installPlugin1WithHooks(ManifestExecutionHook memory execHooks) internal {
        _m1.executionHooks.push(execHooks);
        mockPlugin1 = new MockPlugin(_m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(mockPlugin1), manifestHash1, new FunctionReference[](0));

        vm.prank(address(entryPoint));
        account1.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInstallData: bytes(""),
            dependencies: new FunctionReference[](0)
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        vm.prank(address(entryPoint));
        account1.uninstallPlugin(address(plugin), bytes(""), bytes(""));
    }
}
