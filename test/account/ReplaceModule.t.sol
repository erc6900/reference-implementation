// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";

import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {ExecutionManifest, ManifestExecutionFunction} from "../../src/interfaces/IExecution.sol";
import {IModuleManager, ModuleEntity} from "../../src/interfaces/IModuleManager.sol";
import {Call, IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {SingleSignerValidation} from "../../src/modules/validation/SingleSignerValidation.sol";
import {MockModule} from "../mocks/MockModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

interface TestModule {
    function testFunction() external;
}

contract UpgradeModuleTest is AccountTestBase {
    // From MockModule
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function test_upgradeModuleExecutionFunction() public {
        ExecutionManifest memory m;
        ManifestExecutionFunction[] memory executionFunctions = new ManifestExecutionFunction[](1);
        executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: TestModule.testFunction.selector,
            isPublic: true,
            allowGlobalValidation: true
        });
        m.executionFunctions = executionFunctions;

        MockModule moduleV1 = new MockModule(m);
        MockModule moduleV2 = new MockModule(m);
        vm.startPrank(address(entryPoint));
        account1.installExecution(address(moduleV1), moduleV1.executionManifest(), "");

        // test installed
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodePacked(TestModule.testFunction.selector), 0);
        TestModule(address(account1)).testFunction();

        // upgrade module by batching uninstall + install calls
        vm.startPrank(owner1);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModuleManager.uninstallExecution, (address(moduleV1), moduleV1.executionManifest(), "")
            )
        });
        calls[1] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModuleManager.installExecution, (address(moduleV2), moduleV2.executionManifest(), "")
            )
        });
        account1.executeWithAuthorization(
            abi.encodeCall(account1.executeBatch, (calls)),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );

        // test installed, test if old module still installed
        assertEq(account1.getExecutionFunctionHandler(TestModule.testFunction.selector), address(moduleV2));
        vm.expectEmit(true, true, true, true);
        emit ReceivedCall(abi.encodePacked(TestModule.testFunction.selector), 0);
        TestModule(address(account1)).testFunction();
    }

    function test_upgradeModuleValidationFunction() public {
        // Test using existing global validation
        bytes memory callData = abi.encode(keccak256("test_upgradeModuleValidationFunction"));
        SingleSignerValidation validation2 = new SingleSignerValidation();
        ModuleEntity currModuleEntity =
            ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID);
        ModuleEntity newModuleEntity =
            ModuleEntityLib.pack(address(validation2), TEST_DEFAULT_VALIDATION_ENTITY_ID + 1);

        vm.startPrank(owner1);
        vm.expectEmit(true, true, true, true);
        emit ReceivedTestCall(callData, 1);
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(this), 1, callData)),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );

        // upgrade module by batching uninstall + install calls
        bytes[] memory emptyBytesArr = new bytes[](0);
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModuleManager.uninstallValidation,
                (currModuleEntity, abi.encode(TEST_DEFAULT_VALIDATION_ENTITY_ID), emptyBytesArr)
            )
        });
        calls[1] = Call({
            target: address(account1),
            value: 0,
            data: abi.encodeCall(
                IModuleManager.installValidation,
                (
                    ValidationConfigLib.pack(newModuleEntity, true, true),
                    new bytes4[](0),
                    abi.encode(TEST_DEFAULT_VALIDATION_ENTITY_ID + 1, owner1),
                    new bytes[](0)
                )
            )
        });
        account1.executeWithAuthorization(
            abi.encodeCall(account1.executeBatch, (calls)),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );

        // Test if old validation still works, expect fail
        vm.expectRevert(
            abi.encodePacked(
                UpgradeableModularAccount.ValidationFunctionMissing.selector,
                abi.encode(IStandardExecutor.execute.selector)
            )
        );
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(this), 1, callData)),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );

        // Test if new validation works
        vm.expectEmit(true, true, true, true);
        emit ReceivedTestCall(callData, 1);
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(this), 1, callData)),
            _encodeSignature(
                ModuleEntityLib.pack(address(validation2), TEST_DEFAULT_VALIDATION_ENTITY_ID + 1),
                GLOBAL_VALIDATION,
                ""
            )
        );
    }

    event ReceivedTestCall(bytes, uint256);

    fallback() external payable {
        emit ReceivedTestCall(msg.data, msg.value);
    }

    receive() external payable {
        emit ReceivedTestCall("", msg.value);
    }
}
