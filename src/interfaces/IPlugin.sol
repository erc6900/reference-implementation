// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

struct ManifestExecutionFunction {
    // TODO(erc6900 spec): These fields can be packed into a single word
    // The selector to install
    bytes4 executionSelector;
    // If true, the function won't need runtime validation, and can be called by anyone.
    bool isPublic;
    // If true, the function can be validated by a default validation function.
    bool allowDefaultValidation;
}

// todo: do we need these at all? Or do we fully switch to `installValidation`?
struct ManifestValidation {
    uint8 functionId;
    bool isDefault;
    bool isSignatureValidation;
    bytes4[] selectors;
}

struct ManifestExecutionHook {
    // TODO(erc6900 spec): These fields can be packed into a single word
    bytes4 executionSelector;
    uint8 functionId;
    bool isPreHook;
    bool isPostHook;
}

struct SelectorPermission {
    bytes4 functionSelector;
    string permissionDescription;
}

/// @dev A struct holding fields to describe the plugin in a purely view context. Intended for front end clients.
struct PluginMetadata {
    // A human-readable name of the plugin.
    string name;
    // The version of the plugin, following the semantic versioning scheme.
    string version;
    // The author field SHOULD be a username representing the identity of the user or organization
    // that created this plugin.
    string author;
    // String desciptions of the relative sensitivity of specific functions. The selectors MUST be selectors for
    // functions implemented by this plugin.
    SelectorPermission[] permissionDescriptors;
    // A list of all ERC-7715 permission strings that the plugin could possibly use
    string[] permissionRequest;
}

/// @dev A struct describing how the plugin should be installed on a modular account.
struct PluginManifest {
    // Execution functions defined in this plugin to be installed on the MSCA.
    ManifestExecutionFunction[] executionFunctions;
    ManifestValidation[] validationFunctions;
    ManifestExecutionHook[] executionHooks;
    // List of ERC-165 interface IDs to add to account to support introspection checks. This MUST NOT include
    // IPlugin's interface ID.
    bytes4[] interfaceIds;
}

interface IPlugin is IERC165 {
    /// @notice Initialize plugin data for the modular account.
    /// @dev Called by the modular account during `installPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to setup initial plugin data for the
    /// modular account.
    function onInstall(bytes calldata data) external;

    /// @notice Clear plugin data for the modular account.
    /// @dev Called by the modular account during `uninstallPlugin`.
    /// @param data Optional bytes array to be decoded and used by the plugin to clear plugin data for the modular
    /// account.
    function onUninstall(bytes calldata data) external;

    /// @notice Describe the contents and intended configuration of the plugin.
    /// @dev This manifest MUST stay constant over time.
    /// @return A manifest describing the contents and intended configuration of the plugin.
    function pluginManifest() external pure returns (PluginManifest memory);

    /// @notice Describe the metadata of the plugin.
    /// @dev This metadata MUST stay constant over time.
    /// @return A metadata struct describing the plugin.
    function pluginMetadata() external pure returns (PluginMetadata memory);
}
