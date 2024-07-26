// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {IModule} from "./IModule.sol";

struct ManifestExecutionFunction {
    // TODO(erc6900 spec): These fields can be packed into a single word
    // The selector to install
    bytes4 executionSelector;
    // If true, the function won't need runtime validation, and can be called by anyone.
    bool isPublic;
    // If true, the function can be validated by a global validation function.
    bool allowGlobalValidation;
}

struct ManifestExecutionHook {
    // TODO(erc6900 spec): These fields can be packed into a single word
    bytes4 executionSelector;
    uint32 entityId;
    bool isPreHook;
    bool isPostHook;
}

/// @dev A struct describing how the module should be installed on a modular account.
struct ExecutionManifest {
    // Execution functions defined in this module to be installed on the MSCA.
    ManifestExecutionFunction[] executionFunctions;
    ManifestExecutionHook[] executionHooks;
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IModule's interface ID.
    bytes4[] interfaceIds;
}

interface IExecution is IModule {
    /// @notice Describe the contents and intended configuration of the module.
    /// @dev This manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the module.
    function executionManifest() external pure returns (ExecutionManifest memory);
}
