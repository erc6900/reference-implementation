// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";

interface IAccountLoupe {
    /// @notice Config for an execution function, given a selector
    struct ExecutionFunctionConfig {
        address plugin;
        FunctionReference userOpValidationFunction;
        FunctionReference runtimeValidationFunction;
    }

    /// @notice Pre and post hooks for a given selector
    /// @dev It's possible for one of either `preExecHook` or `postExecHook` to be empty
    struct ExecutionHooks {
        FunctionReference preExecHook;
        FunctionReference postExecHook;
    }

    /// @notice Gets the validation functions and plugin address for a selector
    /// @dev If the selector is a native function, the plugin address will be the address of the account
    /// @param selector The selector to get the configuration for
    /// @return The configuration for this selector
    function getExecutionFunctionConfig(bytes4 selector) external view returns (ExecutionFunctionConfig memory);

    /// @notice Gets the pre and post execution hooks for a selector
    /// @param selector The selector to get the hooks for
    /// @return The pre and post execution hooks for this selector
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory);

    /// @notice Gets the pre and post permitted call hooks applied for a plugin calling this selector
    /// @param callingPlugin The plugin that is calling the selector
    /// @param selector The selector the plugin is calling
    /// @return The pre and post permitted call hooks for this selector
    function getPermittedCallHooks(address callingPlugin, bytes4 selector)
        external
        view
        returns (ExecutionHooks[] memory);

    /// @notice Gets the pre user op and runtime validation hooks associated with a selector
    /// @param selector The selector to get the hooks for
    /// @return preUserOpValidationHooks The pre user op validation hooks for this selector
    /// @return preRuntimeValidationHooks The pre runtime validation hooks for this selector
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            FunctionReference[] memory preUserOpValidationHooks,
            FunctionReference[] memory preRuntimeValidationHooks
        );

    /// @notice Gets an array of all installed plugins
    /// @return The addresses of all installed plugins
    function getInstalledPlugins() external view returns (address[] memory);
}
