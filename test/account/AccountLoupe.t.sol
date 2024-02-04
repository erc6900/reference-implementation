// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {
    ManifestAssociatedFunctionType,
    ManifestExecutionHook,
    ManifestFunction,
    PluginManifest
} from "../../src/interfaces/IPlugin.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {ComprehensivePlugin} from "../mocks/plugins/ComprehensivePlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract AccountLoupeTest is OptimizedTest {
    EntryPoint public entryPoint;
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;
    ComprehensivePlugin public comprehensivePlugin;

    UpgradeableModularAccount public account1;

    FunctionReference public ownerUserOpValidation;
    FunctionReference public ownerRuntimeValidation;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        entryPoint = new EntryPoint();

        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);
        comprehensivePlugin = new ComprehensivePlugin();

        account1 = factory.createAccount(address(this), 0);

        bytes32 manifestHash = keccak256(abi.encode(comprehensivePlugin.pluginManifest()));
        account1.installPlugin(address(comprehensivePlugin), manifestHash, "", new FunctionReference[](0));

        ownerUserOpValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        ownerRuntimeValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
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
        FunctionReference[] memory expectedUserOpValidations = new FunctionReference[](5);
        FunctionReference[] memory expectedRuntimeValidations = new FunctionReference[](5);

        selectorsToCheck[0] = IStandardExecutor.execute.selector;
        expectedUserOpValidations[0] = ownerUserOpValidation;
        expectedRuntimeValidations[0] = ownerRuntimeValidation;

        selectorsToCheck[1] = IStandardExecutor.executeBatch.selector;
        expectedUserOpValidations[1] = ownerUserOpValidation;
        expectedRuntimeValidations[1] = ownerRuntimeValidation;

        selectorsToCheck[2] = UUPSUpgradeable.upgradeToAndCall.selector;
        expectedUserOpValidations[2] = ownerUserOpValidation;
        expectedRuntimeValidations[2] = ownerRuntimeValidation;

        selectorsToCheck[3] = IPluginManager.installPlugin.selector;
        expectedUserOpValidations[3] = ownerUserOpValidation;
        expectedRuntimeValidations[3] = ownerRuntimeValidation;

        selectorsToCheck[4] = IPluginManager.uninstallPlugin.selector;
        expectedUserOpValidations[4] = ownerUserOpValidation;
        expectedRuntimeValidations[4] = ownerRuntimeValidation;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, address(account1));
            assertEq(
                FunctionReference.unwrap(config.userOpValidationFunction),
                FunctionReference.unwrap(expectedUserOpValidations[i])
            );
            assertEq(
                FunctionReference.unwrap(config.runtimeValidationFunction),
                FunctionReference.unwrap(expectedRuntimeValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionFunctionConfig_plugin() public {
        bytes4[] memory selectorsToCheck = new bytes4[](2);
        address[] memory expectedPluginAddress = new address[](2);
        FunctionReference[] memory expectedUserOpValidations = new FunctionReference[](2);
        FunctionReference[] memory expectedRuntimeValidations = new FunctionReference[](2);

        selectorsToCheck[0] = comprehensivePlugin.foo.selector;
        expectedPluginAddress[0] = address(comprehensivePlugin);
        expectedUserOpValidations[0] = FunctionReferenceLib.pack(
            address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.USER_OP_VALIDATION)
        );
        expectedRuntimeValidations[0] = FunctionReferenceLib.pack(
            address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.RUNTIME_VALIDATION)
        );

        selectorsToCheck[1] = singleOwnerPlugin.transferOwnership.selector;
        expectedPluginAddress[1] = address(singleOwnerPlugin);
        expectedUserOpValidations[1] = ownerUserOpValidation;
        expectedRuntimeValidations[1] = ownerRuntimeValidation;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            IAccountLoupe.ExecutionFunctionConfig memory config =
                account1.getExecutionFunctionConfig(selectorsToCheck[i]);

            assertEq(config.plugin, expectedPluginAddress[i]);
            assertEq(
                FunctionReference.unwrap(config.userOpValidationFunction),
                FunctionReference.unwrap(expectedUserOpValidations[i])
            );
            assertEq(
                FunctionReference.unwrap(config.runtimeValidationFunction),
                FunctionReference.unwrap(expectedRuntimeValidations[i])
            );
        }
    }

    function test_pluginLoupe_getExecutionHooks() public {
        IAccountLoupe.ExecutionHooks[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 1);
        assertEq(
            FunctionReference.unwrap(hooks[0].preExecHook),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[0].postExecHook),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
                )
            )
        );
    }

    function test_pluginLoupe_getHooks_multiple() public {
        // Add a second set of execution hooks to the account, and validate that it can return all hooks applied
        // over the function.

        PluginManifest memory mockPluginManifest;

        mockPluginManifest.executionHooks = new ManifestExecutionHook[](1);
        mockPluginManifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: ComprehensivePlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        MockPlugin mockPlugin = new MockPlugin(mockPluginManifest);
        bytes32 manifestHash = keccak256(abi.encode(mockPlugin.pluginManifest()));

        account1.installPlugin(address(mockPlugin), manifestHash, "", new FunctionReference[](0));

        // Assert that the returned execution hooks are what is expected

        IAccountLoupe.ExecutionHooks[] memory hooks = account1.getExecutionHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 2);
        assertEq(
            FunctionReference.unwrap(hooks[0].preExecHook),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.PRE_EXECUTION_HOOK)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[0].postExecHook),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin), uint8(ComprehensivePlugin.FunctionId.POST_EXECUTION_HOOK)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[1].preExecHook),
            FunctionReference.unwrap(FunctionReferenceLib.pack(address(mockPlugin), uint8(0)))
        );
        assertEq(
            FunctionReference.unwrap(hooks[1].postExecHook),
            FunctionReference.unwrap(FunctionReferenceLib.pack(address(mockPlugin), uint8(0)))
        );
    }

    function test_pluginLoupe_getPreUserOpValidationHooks() public {
        (FunctionReference[] memory hooks,) = account1.getPreValidationHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 2);
        assertEq(
            FunctionReference.unwrap(hooks[0]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[1]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)
                )
            )
        );
    }

    function test_pluginLoupe_getPreRuntimeValidationHooks() public {
        (, FunctionReference[] memory hooks) = account1.getPreValidationHooks(comprehensivePlugin.foo.selector);

        assertEq(hooks.length, 2);
        assertEq(
            FunctionReference.unwrap(hooks[0]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1)
                )
            )
        );
        assertEq(
            FunctionReference.unwrap(hooks[1]),
            FunctionReference.unwrap(
                FunctionReferenceLib.pack(
                    address(comprehensivePlugin),
                    uint8(ComprehensivePlugin.FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2)
                )
            )
        );
    }
}
