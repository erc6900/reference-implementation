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
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";

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
    MockPlugin public mockPlugin2;
    bytes32 public manifestHash1;
    bytes32 public manifestHash2;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(uint32(1));
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_1 = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_2 = 2;
    uint8 internal constant _PRE_HOOK_FUNCTION_ID_3 = 3;
    uint8 internal constant _POST_HOOK_FUNCTION_ID_4 = 4;

    PluginManifest public m1;
    PluginManifest public m2;

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

    function test_overlappingExecHookPairs_install() public {
        // Install the first plugin.
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

        // Install a second plugin that applies the first plugin's hook pair to the same selector.
        FunctionReference[] memory dependencies = new FunctionReference[](2);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _PRE_HOOK_FUNCTION_ID_1);
        dependencies[1] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 1
            }),
            dependencies
        );

        vm.stopPrank();
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingExecHookPairs_run() public {
        test_overlappingExecHookPairs_install();

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            1
        );

        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_overlappingExecHookPairs_uninstall() public {
        test_overlappingExecHookPairs_install();

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            1
        );
        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
    }

    function test_overlappingExecHookPairsOnPost_install() public {
        // Install the first plugin.
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

        // Install the second plugin.
        FunctionReference[] memory dependencies = new FunctionReference[](1);
        dependencies[0] = FunctionReferenceLib.pack(address(mockPlugin1), _POST_HOOK_FUNCTION_ID_2);
        _installPlugin2WithHooks(
            _EXEC_SELECTOR,
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_3,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.DEPENDENCY,
                functionId: 0,
                dependencyIndex: 0
            }),
            dependencies
        );
    }

    /// @dev Plugin 1 hook pair: [1, 2]
    ///      Plugin 2 hook pair: [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingExecHookPairsOnPost_run() public {
        test_overlappingExecHookPairsOnPost_install();

        // Expect each pre hook to be called once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin2),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_3,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            2
        );

        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);
    }

    function test_overlappingExecHookPairsOnPost_uninstall() public {
        test_overlappingExecHookPairsOnPost_install();

        // Uninstall the second plugin.
        _uninstallPlugin(mockPlugin2);

        // Expect the pre/post hooks to still exist after uninstalling a plugin with a duplicate hook.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(this), // caller
                0, // msg.value in call to account
                abi.encodeWithSelector(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            1
        );
        (bool success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertTrue(success);

        // Uninstall the first plugin.
        _uninstallPlugin(mockPlugin1);

        // Execution selector should no longer exist.
        (success,) = address(account).call(abi.encodeWithSelector(_EXEC_SELECTOR));
        assertFalse(success);
    }

    function _installPlugin1WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook
    ) internal {
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
    }

    function _installPlugin2WithHooks(
        bytes4 selector,
        ManifestFunction memory preHook,
        ManifestFunction memory postHook,
        FunctionReference[] memory dependencies
    ) internal {
        if (preHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }
        if (postHook.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            m2.dependencyInterfaceIds.push(type(IPlugin).interfaceId);
        }

        m2.executionHooks.push(ManifestExecutionHook(selector, preHook, postHook));

        mockPlugin2 = new MockPlugin(m2);
        manifestHash2 = keccak256(abi.encode(mockPlugin2.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onInstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(
            address(mockPlugin2), manifestHash2, dependencies, new IPluginManager.InjectedHook[](0)
        );

        account.installPlugin({
            plugin: address(mockPlugin2),
            manifestHash: manifestHash2,
            pluginInitData: bytes(""),
            dependencies: dependencies,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
    }

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account.uninstallPlugin(address(plugin), bytes(""), bytes(""), new bytes[](0));
    }
}
