// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {FunctionReference} from "../interfaces/IPluginManager.sol";

/// @notice Pre and post hooks for a given selector.
/// @dev It's possible for one of either `preExecHook` or `postExecHook` to be empty.
struct ExecutionHook {
    FunctionReference hookFunction;
    bool isPreHook;
    bool isPostHook;
    bool requireUOContext;
}

interface IAccountLoupe {
    /// @notice Get the plugin address for a selector.
    /// @dev If the selector is a native function, the plugin address will be the address of the account.
    /// @param selector The selector to get the configuration for.
    /// @return plugin The plugin address for this selector.
    function getExecutionFunctionHandler(bytes4 selector) external view returns (address plugin);

    /// @notice Get the validation functions for a selector.
    /// @param selector The selector to get the validation functions for.
    /// @return The validation functions for this selector.
    function getValidations(bytes4 selector) external view returns (FunctionReference[] memory);

    /// @notice Get the pre and post execution hooks for a selector.
    /// @param selector The selector to get the hooks for.
    /// @return The pre and post execution hooks for this selector.
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHook[] memory);

    /// @notice Get the pre and post execution hooks for a validation function.
    /// @param validationFunction The validation function to get the hooks for.
    /// @return The pre and post execution hooks for this validation function.
    function getPermissionHooks(FunctionReference validationFunction)
        external
        view
        returns (ExecutionHook[] memory);

    /// @notice Get the pre user op and runtime validation hooks associated with a selector.
    /// @param validationFunction The validation function to get the hooks for.
    /// @return preValidationHooks The pre validation hooks for this selector.
    function getPreValidationHooks(FunctionReference validationFunction)
        external
        view
        returns (FunctionReference[] memory preValidationHooks);

    /// @notice Get an array of all installed plugins.
    /// @return The addresses of all installed plugins.
    function getInstalledPlugins() external view returns (address[] memory);
}
