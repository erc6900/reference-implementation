// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {ModuleEntity, ValidationConfig} from "../../src/interfaces/IModuleManager.sol";

contract ValidationConfigLibTest is Test {
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;

    // Tests the packing and unpacking of a validation config with a randomized state

    function testFuzz_validationConfig_packingUnderlying(
        address module,
        uint32 entityId,
        bool isGlobal,
        bool isSignatureValidation
    ) public {
        ValidationConfig validationConfig = ValidationConfigLib.pack(module, entityId, isGlobal, isSignatureValidation);

        // Test unpacking underlying
        (address module2, uint32 entityId2, bool isGlobal2, bool isSignatureValidation2) =
            validationConfig.unpackUnderlying();

        assertEq(module, module2, "module mismatch");
        assertEq(entityId, entityId2, "entityId mismatch");
        assertEq(isGlobal, isGlobal2, "isGlobal mismatch");
        assertEq(isSignatureValidation, isSignatureValidation2, "isSignatureValidation mismatch");

        // Test unpacking to ModuleEntity

        ModuleEntity expectedModuleEntity = ModuleEntityLib.pack(module, entityId);

        (ModuleEntity validationFunction, bool isGlobal3, bool isSignatureValidation3) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(expectedModuleEntity),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, isGlobal3, "isGlobal mismatch");
        assertEq(isSignatureValidation, isSignatureValidation3, "isSignatureValidation mismatch");

        // Test individual view functions

        assertEq(validationConfig.module(), module, "module mismatch");
        assertEq(validationConfig.entityId(), entityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(expectedModuleEntity),
            "moduleEntity mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
    }

    function testFuzz_validationConfig_packingModuleEntity(
        ModuleEntity validationFunction,
        bool isGlobal,
        bool isSignatureValidation
    ) public {
        ValidationConfig validationConfig =
            ValidationConfigLib.pack(validationFunction, isGlobal, isSignatureValidation);

        // Test unpacking underlying

        (address expectedModule, uint32 expectedEntityId) = validationFunction.unpack();

        (address module, uint32 entityId, bool isGlobal2, bool isSignatureValidation2) =
            validationConfig.unpackUnderlying();

        assertEq(expectedModule, module, "module mismatch");
        assertEq(expectedEntityId, entityId, "entityId mismatch");
        assertEq(isGlobal, isGlobal2, "isGlobal mismatch");
        assertEq(isSignatureValidation, isSignatureValidation2, "isSignatureValidation mismatch");

        // Test unpacking to ModuleEntity

        (ModuleEntity validationFunction2, bool isGlobal3, bool isSignatureValidation3) = validationConfig.unpack();

        assertEq(
            ModuleEntity.unwrap(validationFunction),
            ModuleEntity.unwrap(validationFunction2),
            "validationFunction mismatch"
        );
        assertEq(isGlobal, isGlobal3, "isGlobal mismatch");
        assertEq(isSignatureValidation, isSignatureValidation3, "isSignatureValidation mismatch");

        // Test individual view functions

        assertEq(validationConfig.module(), expectedModule, "module mismatch");
        assertEq(validationConfig.entityId(), expectedEntityId, "entityId mismatch");
        assertEq(
            ModuleEntity.unwrap(validationConfig.moduleEntity()),
            ModuleEntity.unwrap(validationFunction),
            "validationFunction mismatch"
        );
        assertEq(validationConfig.isGlobal(), isGlobal, "isGlobal mismatch");
        assertEq(validationConfig.isSignatureValidation(), isSignatureValidation, "isSignatureValidation mismatch");
    }
}
