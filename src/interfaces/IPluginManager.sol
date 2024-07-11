// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

type PackedPluginEntity is bytes24;

type ValidationConfig is bytes26;

interface IPluginManager {
    event PluginInstalled(address indexed plugin, bytes32 manifestHash);

    event PluginUninstalled(address indexed plugin, bool indexed onUninstallSucceeded);

    /// @notice Install a plugin to the modular account.
    /// @param plugin The plugin to install.
    /// @param manifestHash The hash of the plugin manifest.
    /// @param pluginInstallData Optional data to be decoded and used by the plugin to setup initial plugin data
    /// for the modular account.
    function installPlugin(address plugin, bytes32 manifestHash, bytes calldata pluginInstallData) external;

    /// @notice Temporary install function - pending a different user-supplied install config & manifest validation
    /// path.
    /// Installs a validation function across a set of execution selectors, and optionally mark it as a global
    /// validation.
    /// TODO: remove or update.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the plugin to setup initial plugin state.
    /// @param preValidationHooks Optional pre-validation hooks to install for the validation function.
    /// @param permissionHooks Optional permission hooks to install for the validation function.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes calldata preValidationHooks,
        bytes calldata permissionHooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// TODO: remove or update.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// account.
    /// @param preValidationHookUninstallData Optional data to be decoded and used by the plugin to clear account
    /// data
    /// @param permissionHookUninstallData Optional data to be decoded and used by the plugin to clear account data
    function uninstallValidation(
        PackedPluginEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external;

    /// @notice Uninstall a plugin from the modular account.
    /// @param plugin The plugin to uninstall.
    /// @param config An optional, implementation-specific field that accounts may use to ensure consistency
    /// guarantees.
    /// @param pluginUninstallData Optional data to be decoded and used by the plugin to clear plugin data for the
    /// modular account.
    function uninstallPlugin(address plugin, bytes calldata config, bytes calldata pluginUninstallData) external;
}
