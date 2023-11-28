// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";

interface IAccountLoupe {
    // Config for a Plugin Execution function
    struct ExecutionFunctionConfig {
        address plugin;
        FunctionReference userOpValidationFunction;
        FunctionReference runtimeValidationFunction;
    }

    struct ExecutionHooks {
        FunctionReference preExecHook;
        FunctionReference postExecHook;
    }

    function getExecutionFunctionConfig(bytes4 selector) external view returns (ExecutionFunctionConfig memory);

    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory);

    function getPermittedCallHooks(address callingPlugin, bytes4 selector)
        external
        view
        returns (ExecutionHooks[] memory);

    function getPreUserOpValidationHooks(bytes4 selector) external view returns (FunctionReference[] memory);

    function getPreRuntimeValidationHooks(bytes4 selector) external view returns (FunctionReference[] memory);

    function getInstalledPlugins() external view returns (address[] memory);
}
