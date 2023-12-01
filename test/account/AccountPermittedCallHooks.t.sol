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

contract AccountPermittedCallHooksTest is OptimizedTest {
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

        m1.permittedExecutionSelectors.push(_EXEC_SELECTOR);
    }

    function test_prePermittedCallHook_install() public {
        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0})
        );
    }

    /// @dev Plugin hook pair(s): [1, null]
    ///      Expected execution: [1, null]
    function test_prePermittedCallHook_run() public {
        test_prePermittedCallHook_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            0 // msg value in call to plugin
        );

        account.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    function test_prePermittedCallHook_uninstall() public {
        test_prePermittedCallHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_permittedCallHookPair_install() public {
        _installPlugin1WithHooks(
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

    /// @dev Plugin hook pair(s): [1, 2]
    ///      Expected execution: [1, 2]
    function test_permittedCallHookPair_run() public {
        test_permittedCallHookPair_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        // pre hook call
        emit ReceivedCall(
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
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

        account.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    function test_permittedCallHookPair_uninstall() public {
        test_permittedCallHookPair_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_postOnlyPermittedCallHook_install() public {
        _installPlugin1WithHooks(
            ManifestFunction({functionType: ManifestAssociatedFunctionType.NONE, functionId: 0, dependencyIndex: 0}),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );
    }

    /// @dev Plugin hook pair(s): [null, 2]
    ///      Expected execution: [null, 2]
    function test_postOnlyPermittedCallHook_run() public {
        test_postOnlyPermittedCallHook_install();

        vm.startPrank(address(mockPlugin1));

        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(
            abi.encodeCall(IPlugin.postExecutionHook, (_POST_HOOK_FUNCTION_ID_2, "")),
            0 // msg value in call to plugin
        );

        account.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    function test_postOnlyPermittedCallHook_uninstall() public {
        test_postOnlyPermittedCallHook_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_overlappingPermittedCallHookPairs_install() public {
        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
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

    /// @dev Plugin hook pair(s): [1, 2], [1, 2]
    ///      Expected execution: [1, 2]
    function test_overlappingPermittedCallHookPairs_run() public {
        test_overlappingPermittedCallHookPairs_install();

        vm.startPrank(address(mockPlugin1));

        // Expect the pre hook to be called just once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called just once, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            1
        );

        account.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    function test_overlappingPermittedCallHookPairs_uninstall() public {
        test_overlappingPermittedCallHookPairs_install();

        _uninstallPlugin(mockPlugin1);
    }

    function test_overlappingPermittedCallHookPairsOnPost_install() public {
        _installPlugin1WithHooks(
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_1,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _PRE_HOOK_FUNCTION_ID_3,
                dependencyIndex: 0
            }),
            ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _POST_HOOK_FUNCTION_ID_2,
                dependencyIndex: 0
            })
        );
    }

    /// @dev Plugin hook pair(s): [1, 2], [3, 2]
    ///      Expected execution: [1, 2], [3, 2]
    function test_overlappingPermittedCallHookPairsOnPost_run() public {
        test_overlappingPermittedCallHookPairsOnPost_install();

        vm.startPrank(address(mockPlugin1));

        // Expect each pre hook to be called once.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_3,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(
                IPlugin.preExecutionHook.selector,
                _PRE_HOOK_FUNCTION_ID_1,
                address(mockPlugin1), // caller
                0, // msg.value in call to account
                abi.encodePacked(_EXEC_SELECTOR)
            ),
            1
        );

        // Expect the post hook to be called twice, with the expected data.
        vm.expectCall(
            address(mockPlugin1),
            abi.encodeWithSelector(IPlugin.postExecutionHook.selector, _POST_HOOK_FUNCTION_ID_2, ""),
            2
        );

        account.executeFromPlugin(abi.encodePacked(_EXEC_SELECTOR));

        vm.stopPrank();
    }

    function test_overlappingPermittedCallHookPairsOnPost_uninstall() public {
        test_overlappingPermittedCallHookPairsOnPost_install();

        _uninstallPlugin(mockPlugin1);
    }

    function _installPlugin1WithHooks(ManifestFunction memory preHook1, ManifestFunction memory postHook1)
        internal
    {
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook1, postHook1));
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

    function _installPlugin1WithHooks(
        ManifestFunction memory preHook1,
        ManifestFunction memory postHook1,
        ManifestFunction memory preHook2,
        ManifestFunction memory postHook2
    ) internal {
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook1, postHook1));
        m1.permittedCallHooks.push(ManifestExecutionHook(_EXEC_SELECTOR, preHook2, postHook2));
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

    function _uninstallPlugin(MockPlugin plugin) internal {
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodeCall(IPlugin.onUninstall, (bytes(""))), 0);
        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);

        account.uninstallPlugin(address(plugin), bytes(""), bytes(""), new bytes[](0));
    }
}
