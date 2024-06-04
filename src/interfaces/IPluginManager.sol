// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

type FunctionReference is bytes21;

interface IPluginManager {
    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);

    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);

    /// @notice Install a plugin to the modular account.
    /// @param plugin The plugin to install.
    /// @param manifestHash The hash of the plugin manifest.
    /// @param pluginInstallData Optional data to be decoded and used by the plugin to setup initial plugin data
    /// for the modular account.
    /// @param dependencies The dependencies of the plugin, as described in the manifest. Each FunctionReference
    /// MUST be composed of an installed plugin's address and a function ID of its validation function.
    function installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes calldata pluginInstallData,
        FunctionReference[] calldata dependencies
    ) external;

    /// @notice Temporary install function - pending a different user-supplied install config & manifest validation
    /// path.
    /// Installs a validation function across a set of execution selectors, and optionally mark it as a default
    /// validation.
    /// TODO: remove or update.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationFunction The validation function to install.
    /// @param shared Whether the validation function is shared across all selectors in the default pool.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the plugin to setup initial plugin state.
    function installValidation(
        FunctionReference validationFunction,
        bool shared,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes calldata preValidationHooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// TODO: remove or update.
    /// @param validationFunction The validation function to uninstall.
    /// @param selectors The selectors to uninstall the validation function for.
    /// @param uninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// account.
    function uninstallValidation(
        FunctionReference validationFunction,
        bytes4[] calldata selectors,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData
    ) external;

    /// @notice Uninstall a plugin from the modular account.
    /// @param plugin The plugin to uninstall.
    /// @param config An optional, implementation-specific field that accounts may use to ensure consistency
    /// guarantees.
    /// @param pluginUninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// modular account.
    function uninstallPlugin(address plugin, bytes calldata config, bytes calldata pluginUninstallData) external;
}
