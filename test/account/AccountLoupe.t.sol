// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {IAccountLoupe, ExecutionHook} from "../../src/interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";

import {ComprehensivePlugin} from "../mocks/plugins/ComprehensivePlugin.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountLoupeTest is AccountTestBase {
    ComprehensivePlugin public comprehensivePlugin;

    FunctionReference public ownerValidation;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        _transferOwnershipToTest();

        comprehensivePlugin = new ComprehensivePlugin();

        bytes32 manifestHash = keccak256(abi.encode(comprehensivePlugin.pluginManifest()));
        account1.installPlugin(address(comprehensivePlugin), manifestHash, "", new FunctionReference[](0));

        ownerValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER_OR_SELF)
        );
    }

    function test_pluginLoupe_getInstalledPlugins_initial() public {
        address[] memory plugins = account1.getInstalledPlugins();

        assertEq(plugins.length, 2);

        assertEq(plugins[0], address(singleOwnerPlugin));
        assertEq(plugins[1], address(comprehensivePlugin));
    }

    function test_pluginLoupe_getExecutionFunctionConfig_native() public {
        bytes4[] memory selectorsToCheck = new bytes4[](5);
        FunctionReference[] memory expectedValidations = new FunctionReference[](5);

        selectorsToCheck[0] = IStandardExecutor.execute.selector;
        expectedValidations[0] = ownerValidation;

        selectorsToCheck[1] = IStandardExecutor.executeBatch.selector;
        expectedValidations[1] = ownerValidation;

        selectorsToCheck[2] = UUPSUpgradeable.upgradeToAndCall.selector;
        expectedValidations[2] = ownerValidation;

        selectorsToCheck[3] = IPluginManager.installPlugin.selector;
        expectedValidations[3] = ownerValidation;

        selectorsToCheck[4] = IPluginManager.uninstallPlugin.selector;
        expectedValidations[4] = ownerValidation;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, address(account1));
            assertEq(
                FunctionReference.unwrap(config.validationFunction),
                FunctionReference.unwrap(expectedValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionFunctionConfig_plugin() public {
        bytes4[] memory selectorsToCheck = new bytes4[](1);
        address[] memory expectedPluginAddress = new address[](1);
        FunctionReference[] memory expectedValidations = new FunctionReference[](1);

        selectorsToCheck[0] = comprehensivePlugin.foo.selector;
        expectedPluginAddress[0] = address(comprehensivePlugin);
        expectedValidations[0] = FunctionReferenceLib.pack(
            address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.VALIDATION)
        );

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, expectedPluginAddress[i]);
            assertEq(
                FunctionReference.unwrap(config.validationFunction),
                FunctionReference.unwrap(expectedValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionHooks() public {
        ExecutionHook[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);
        ExecutionHook[3] memory expectedHooks = [
            ExecutionHook({
                hookFunction: FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.BOTH_EXECUTION_HOOKS)
                ),
                isPreHook: true,
                isPostHook: true
            }),
            ExecutionHook({
                hookFunction: FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
                ),
                isPreHook: true,
                isPostHook: false
            }),
            ExecutionHook({
                hookFunction: FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
                ),
                isPreHook: false,
                isPostHook: true
            })
        ];

        assertEq(hooks.length, 3);
        for (uint256 i = 0; i < hooks.length; i++) {
            assertEq(
                FunctionReference.unwrap(hooks[i].hookFunction),
                FunctionReference.unwrap(expectedHooks[i].hookFunction)
            );
            assertEq(hooks[i].isPreHook, expectedHooks[i].isPreHook);
            assertEq(hooks[i].isPostHook, expectedHooks[i].isPostHook);
        }
    }

    function test_pluginLoupe_getValidationHooks() public {
        FunctionReference[] memory hooks = account1.getPreValidationHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 2);
        assertEq(
            FunctionReference.unwrap(hooks[0]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_VALIDATION_HOOK_1)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[1]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_VALIDATION_HOOK_2)
                )
            )
        );
    }
}
