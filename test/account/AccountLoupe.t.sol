// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {HookConfigLib} from "../../src/helpers/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ExecutionDataView, ExecutionHook, ValidationDataView} from "../../src/interfaces/IAccountLoupe.sol";
import {HookConfig, IModuleManager} from "../../src/interfaces/IModuleManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";

import {ComprehensiveModule} from "../mocks/modules/ComprehensiveModule.sol";
import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract AccountLoupeTest is CustomValidationTestBase {
    ComprehensiveModule public comprehensiveModule;

    event ReceivedCall(bytes msgData, uint256 msgValue);

    ModuleEntity public comprehensiveModuleValidation;

    function setUp() public {
        comprehensiveModule = new ComprehensiveModule();
        comprehensiveModuleValidation =
            ModuleEntityLib.pack(address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.VALIDATION));

        _customValidationSetup();

        vm.startPrank(address(entryPoint));
        account1.installExecution(address(comprehensiveModule), comprehensiveModule.executionManifest(), "");
        vm.stopPrank();
    }

    function test_moduleLoupe_getExecutionData_native() public {
        bytes4[] memory selectorsToCheck = new bytes4[](5);

        selectorsToCheck[0] = IStandardExecutor.execute.selector;

        selectorsToCheck[1] = IStandardExecutor.executeBatch.selector;

        selectorsToCheck[2] = UUPSUpgradeable.upgradeToAndCall.selector;

        selectorsToCheck[3] = IModuleManager.installExecution.selector;

        selectorsToCheck[4] = IModuleManager.uninstallExecution.selector;

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            ExecutionDataView memory data = account1.getExecutionData(selectorsToCheck[i]);
            assertEq(data.module, address(account1));
            assertTrue(data.allowGlobalValidation);
            assertFalse(data.isPublic);
        }
    }

    function test_moduleLoupe_getExecutionData_module() public {
        bytes4[] memory selectorsToCheck = new bytes4[](1);
        address[] memory expectedModuleAddress = new address[](1);

        selectorsToCheck[0] = comprehensiveModule.foo.selector;
        expectedModuleAddress[0] = address(comprehensiveModule);

        for (uint256 i = 0; i < selectorsToCheck.length; i++) {
            ExecutionDataView memory data = account1.getExecutionData(selectorsToCheck[i]);
            assertEq(data.module, expectedModuleAddress[i]);
            assertFalse(data.allowGlobalValidation);
            assertFalse(data.isPublic);

            HookConfig[3] memory expectedHooks = [
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.BOTH_EXECUTION_HOOKS)
                    ),
                    true,
                    true
                ),
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_EXECUTION_HOOK)
                    ),
                    true,
                    false
                ),
                HookConfigLib.packExecHook(
                    ModuleEntityLib.pack(
                        address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.POST_EXECUTION_HOOK)
                    ),
                    false,
                    true
                )
            ];

            assertEq(data.executionHooks.length, 3);
            for (uint256 j = 0; j < data.executionHooks.length; j++) {
                assertEq(data.executionHooks[j], bytes32(HookConfig.unwrap(expectedHooks[j])));
            }
        }
    }

    function test_moduleLoupe_getValidationData() public {
        ValidationDataView memory data = account1.getValidationData(comprehensiveModuleValidation);
        bytes32[] memory selectors = data.selectors;

        assertTrue(data.isGlobal);
        assertTrue(data.isSignatureValidation);
        assertEq(data.preValidationHooks.length, 2);
        assertEq(
            ModuleEntity.unwrap(data.preValidationHooks[0]),
            ModuleEntity.unwrap(
                ModuleEntityLib.pack(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_1)
                )
            )
        );
        assertEq(
            ModuleEntity.unwrap(data.preValidationHooks[1]),
            ModuleEntity.unwrap(
                ModuleEntityLib.pack(
                    address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_2)
                )
            )
        );

        assertEq(data.permissionHooks.length, 0);
        assertEq(selectors.length, 1);
        assertEq(selectors[0], bytes32(comprehensiveModule.foo.selector));
    }

    // Test config

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (ModuleEntity, bool, bool, bytes4[] memory, bytes memory, bytes[] memory)
    {
        bytes[] memory hooks = new bytes[](2);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_1)
            )
        );
        hooks[1] = abi.encodePacked(
            HookConfigLib.packValidationHook(
                address(comprehensiveModule), uint32(ComprehensiveModule.EntityId.PRE_VALIDATION_HOOK_2)
            )
        );

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = comprehensiveModule.foo.selector;

        return (comprehensiveModuleValidation, true, true, selectors, bytes(""), hooks);
    }
}
