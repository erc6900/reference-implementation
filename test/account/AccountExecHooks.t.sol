// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {
    IPlugin,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExecutionHook,
    ManifestFunction,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {FunctionReference} from "../../src/libraries/FunctionReferenceLib.sol";

import {MockPlugin} from "../mocks/MockPlugin.sol";
import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract AccountExecHooksTest is OptimizedTest {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;

    UpgradeableModularAccount public account;

    MockPlugin public mockPlugin1;
    bytes32 public manifestHash1;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_3 = 3;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_4 = 4;

    PluginManifest public m1;

    /// @dev Note that we strip hookApplyData from InjectedHooks in this event for gas savings
    event PluginInstalled(
        address indexed plugin,
        bytes32 manifestHash,
        FunctionReference[] dependencies,
        IPluginManager.InjectedHook[] injectedHooks
    );
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = new EntryPoint();
        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        // Create an account with "this" as the owner, so we can execute along the runtime path with regular
        // solidity semantics
        account = factory.createAccount(address(this), 0);

        m1.executionFunctions.push(_EXEC_SELECTOR);

        m1.runtimeValidationFunctions.push(
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
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
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

        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_preExecHook_uninstall() public {
        test_preExecHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_execHookPair_install() public {
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
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
                _PRE_HOOK_FUNCTION_ID_1,
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
            abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_execHookPair_uninstall() public {
        test_execHookPair_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_postOnlyExecHook_install() public {
        _installPlugin1WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
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

        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_postOnlyExecHook_uninstall() public {
        test_postOnlyExecHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function _installPlugin1WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook
    ) internal returns (MockPlugin) {
        m1.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));
        mockPlugin1 = new MockPlugin(m1);
        manifestHash1 = keccak256(abi.encode(mockPlugin1.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin1), manifestHash1, new FunctionReference[](0), new IPluginManager.InjectedHook[](0)
        );

        account.installPlugin({
            plugin: address(mockPlugin1),
            manifestHash: manifestHash1,
            pluginInitData: bytes(""),
            dependencies: new FunctionReference[](0),
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        return mockPlugin1;
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account.uninstallPlugin(address(plugin), bytes(""), bytes(""), new bytes[](0));
    }
}
