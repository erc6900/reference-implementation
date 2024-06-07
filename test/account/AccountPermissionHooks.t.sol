// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

// import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
// import {BaseAccount} from "@eth-infinitism/account-abstraction/core/BaseAccount.sol";
// import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {
    IPlugin,
    ManifestPermissionHook,
    ManifestExecutionFunction,
    ManifestAssociatedFunction,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
// import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {MockPlugin} from "../mocks/MockPlugin.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountPermissionHooksTest is AccountTestBase {
    MockPlugin public mockPlugin1;
    bytes32 public manifestHash1;
    bytes32 public manifestHash2;

    bytes4 internal constant _EXEC_SELECTOR = bytes4(0xffffffff);
    ManifestAssociatedFunction public validation;
    FunctionReference public validationFunction;
    uint8 internal constant _PRE_HOOK_FUNCTION_ID = 1;
    uint8 internal constant _POST_HOOK_FUNCTION_ID = 2;
    uint8 internal constant _BOTH_HOOKS_FUNCTION_ID = 3;
    uint8 internal constant _VALIDATION_FUNCTION_ID = 4;

    PluginManifest internal _m1;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    // emitted by MockPlugin
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        _transferOwnershipToTest();

        validation = ManifestAssociatedFunction({
            executionSelector: _EXEC_SELECTOR,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: _VALIDATION_FUNCTION_ID,
                dependencyIndex: 0
            })
        });

        validationFunction = FunctionReferenceLib.pack(address(this), _VALIDATION_FUNCTION_ID);
    }

    function test_preExecHook_install() public {
        _installPlugin1WithHooks(
            ManifestPermissionHook({
                validationFunction: validationFunction,
                functionId: _PRE_HOOK_FUNCTION_ID,
                isPreHook: true,
                isPostHook: false,
                requireUOContext: false
            })
        );
    }

    // /// @dev Plugin 1 hook pair: [1, null]
    // ///      Expected execution: [1, null]
    // function test_preExecHook_run() public {
    //     test_preExecHook_install();

    //     bytes memory callData = abi.encode(_EXEC_SELECTOR);

    //     vm.expectEmit(true, true, true, true);
    //     emit ReceivedCall(
    //         abi.encodeWithSelector(
    //             IExecutionHook.preExecutionHook.selector,
    //             _PRE_HOOK_FUNCTION_ID,
    //             abi.encodePacked(
    //                 address(this), // caller
    //                 uint256(0), // msg.value in call to account
    //                 callData
    //             )
    //         ),
    //         0 // msg value in call to plugin
    //     );

    //     console.logBytes(
    //         abi.encodeWithSelector(
    //             IExecutionHook.preExecutionHook.selector,
    //             _PRE_HOOK_FUNCTION_ID,
    //             abi.encodePacked(
    //                 address(this), // caller
    //                 uint256(0), // msg.value in call to account
    //                 callData
    //             )
    //         )
    //     );

    //     (bool success,) = address(account1).call(callData);
    //     assertTrue(success);
    // }

    function test_execHookPair_install() public {
        _installPlugin1WithHooks(
            ManifestPermissionHook({
                validationFunction: validationFunction,
                functionId: _BOTH_HOOKS_FUNCTION_ID,
                isPreHook: true,
                isPostHook: true,
                requireUOContext: false
            })
        );
    }

    // /// @dev Plugin 1 hook pair: [1, 2]
    // ///      Expected execution: [1, 2]
    // function test_execHookPair_run() public {
    //     test_execHookPair_install();

    //     bytes memory callData = abi.encode(_EXEC_SELECTOR);

    //     vm.expectEmit(true, true, true, true);
    //     // pre hook call
    //     emit ReceivedCall(
    //         abi.encodeWithSelector(
    //             IExecutionHook.preExecutionHook.selector,
    //             _BOTH_HOOKS_FUNCTION_ID,
    //             abi.encodePacked(
    //                 address(this), // caller
    //                 uint256(0), // msg.value in call to account
    //                 callData
    //             )
    //         ),
    //         0 // msg value in call to plugin
    //     );
    //     vm.expectEmit(true, true, true, true);
    //     // post hook call
    //     emit ReceivedCall(
    //         abi.encodeCall(IExecutionHook.postExecutionHook, (_BOTH_HOOKS_FUNCTION_ID, "")),
    //         0 // msg value in call to plugin
    //     );

    //     (bool success,) = address(account1).call(callData);
    //     console.log("success");
    //     console.log(success);
    //     assertTrue(success);
    // }

    function test_postOnlyExecHook_install() public {
        _installPlugin1WithHooks(
            ManifestPermissionHook({
                validationFunction: validationFunction,
                functionId: _POST_HOOK_FUNCTION_ID,
                isPreHook: false,
                isPostHook: true,
                requireUOContext: false
            })
        );
    }

    // /// @dev Plugin 1 hook pair: [null, 2]
    // ///      Expected execution: [null, 2]
    // function test_postOnlyExecHook_run() public {
    //     test_postOnlyExecHook_install();

    //     vm.expectEmit(true, true, true, true);
    //     emit ReceivedCall(
    //         abi.encodeCall(IExecutionHook.postExecutionHook, (_POST_HOOK_FUNCTION_ID, "")),
    //         0 // msg value in call to plugin
    //     );

    //     (bool success,) = address(account1).call(abi.encode(_EXEC_SELECTOR));
    //     assertTrue(success);
    // }

    // function test_requireUOContextHook() public {
    //     _installPlugin1WithHooks(
    //         ManifestPermissionHook({
    //             validationFunction: validationFunction,
    //             functionId: _POST_HOOK_FUNCTION_ID,
    //             isPreHook: false,
    //             isPostHook: true,
    //             requireUOContext: true
    //         })
    //     );

    //     // Call should fail during validation!
    //     PackedUserOperation memory uo = PackedUserOperation({
    //         sender: address(this),
    //         nonce: 0,
    //         initCode: bytes(""),
    //         callData: abi.encode(_EXEC_SELECTOR),
    //         accountGasLimits: 0,
    //         preVerificationGas: 0,
    //         gasFees: 0,
    //         paymasterAndData: bytes(""),
    //         signature: bytes("")
    //     });

    //     vm.prank(address(entryPoint));
    //     (bool success, bytes memory errMsg) =
    //         address(account1).call(abi.encodeCall(BaseAccount.validateUserOp, (uo, bytes32(0), 0)));
    //     assertFalse(success);
    //     assertEq(bytes4(errMsg), IEntryPoint.FailedOpWithRevert.selector);
    // }

    function _installPlugin1WithHooks(ManifestPermissionHook memory permissionHooks) internal {
        _m1.executionFunctions.push(
            ManifestExecutionFunction({
                executionSelector: _EXEC_SELECTOR,
                isPublic: false,
                allowSharedValidation: false
            })
        );
        _m1.validationFunctions.push(validation);
        _m1.permissionHooks.push(permissionHooks);
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
}
