// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {HookConfig, ModuleEntity} from "../interfaces/IModuleManager.sol";

// Represents data associated with a specifc function selector.
struct ExecutionDataView {
    // The module that implements this execution function.
    // If this is a native function, the address must remain address(0).
    address module;
    // Whether or not the function needs runtime validation, or can be called by anyone. The function can still be
    // state changing if this flag is set to true.
    // Note that even if this is set to true, user op validation will still be required, otherwise anyone could
    // drain the account of native tokens by wasting gas.
    bool isPublic;
    // Whether or not a global validation function may be used to validate this function.
    bool allowGlobalValidation;
    // The execution hooks for this function selector.
    HookConfig[] executionHooks;
}

struct ValidationDataView {
    // Whether or not this validation can be used as a global validation function.
    bool isGlobal;
    // Whether or not this validation is a signature validator.
    bool isSignatureValidation;
    // The pre validation hooks for this validation function.
    ModuleEntity[] preValidationHooks;
    // Permission hooks for this validation function.
    HookConfig[] permissionHooks;
    // The set of selectors that may be validated by this validation function.
    bytes4[] selectors;
}

interface IAccountLoupe {
    /// @notice Get the execution data for a selector.
    /// @dev If the selector is a native function, the module address will be the address of the account.
    /// @param selector The selector to get the data for.
    /// @return ExecutionData The module address for this selector.
    function getExecutionData(bytes4 selector) external view returns (ExecutionDataView memory);

    /// @notice Get the validation data for a validation.
    /// @dev If the selector is a native function, the module address will be the address of the account.
    /// @param validationFunction The validationFunction to get the data for.
    /// @return ValidationData The module address for this selector.
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        returns (ValidationDataView memory);
}
