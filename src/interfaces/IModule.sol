// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

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

struct SelectorPermission {
    bytes4 functionSelector;
    string permissionDescription;
}

/// @dev A struct holding fields to describe the module in a purely view context. Intended for front end clients.
struct ModuleMetadata {
    // A human-readable name of the module.
    string name;
    // The version of the module, following the semantic versioning scheme.
    string version;
    // The author field SHOULD be a username representing the identity of the user or organization
    // that created this module.
    string author;
    // String desciptions of the relative sensitivity of specific functions. The selectors MUST be selectors for
    // functions implemented by this module.
    SelectorPermission[] permissionDescriptors;
    // A list of all ERC-7715 permission strings that the module could possibly use
    string[] permissionRequest;
}

/// @dev A struct describing how the module should be installed on a modular account.
struct ModuleManifest {
    // Execution functions defined in this module to be installed on the MSCA.
    ManifestExecutionFunction[] executionFunctions;
    ManifestExecutionHook[] executionHooks;
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IModule's interface ID.
    bytes4[] interfaceIds;
}

interface IModule is IERC165 {
    /// @notice Initialize module data for the modular account.
    /// @dev Called by the modular account during `installModule`.
    /// @param data Optional bytes array to be decoded and used by the module to setup initial module data for the
    /// modular account.
    function onInstall(bytes calldata data) external;

    /// @notice Clear module data for the modular account.
    /// @dev Called by the modular account during `uninstallModule`.
    /// @param data Optional bytes array to be decoded and used by the module to clear module data for the modular
    /// account.
    function onUninstall(bytes calldata data) external;

    /// @notice Describe the contents and intended configuration of the module.
    /// @dev This manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the module.
    function moduleManifest() external pure returns (ModuleManifest memory);

    /// @notice Describe the metadata of the module.
    /// @dev This metadata MUST stay constant over time.
    /// @return A metadata struct describing the module.
    function moduleMetadata() external pure returns (ModuleMetadata memory);
}
