// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {ModuleManifest} from "./IModule.sol";

type ModuleEntity is bytes24;

type ValidationConfig is bytes26;

interface IModuleManager {
    event ModuleInstalled(address indexed module);

    event ModuleUninstalled(address indexed module, bool indexed onUninstallSucceeded);

    /// @notice Install a module to the modular account.
    /// @param module The module to install.
    /// @param manifest the manifest describing functions to install
    /// @param moduleInstallData Optional data to be decoded and used by the module to setup initial module data
    /// for the modular account.
    function installModule(address module, ModuleManifest calldata manifest, bytes calldata moduleInstallData)
        external;

    /// @notice Temporary install function - pending a different user-supplied install config & manifest validation
    /// path.
    /// Installs a validation function across a set of execution selectors, and optionally mark it as a global
    /// validation.
    /// TODO: remove or update.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the module to setup initial module state.
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
    /// @param uninstallData Optional data to be decoded and used by the module to clear module data for the
    /// account.
    /// @param preValidationHookUninstallData Optional data to be decoded and used by the module to clear account
    /// data
    /// @param permissionHookUninstallData Optional data to be decoded and used by the module to clear account data
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) external;

    /// @notice Uninstall a module from the modular account.
    /// @param module The module to uninstall.
    /// @param manifest the manifest describing functions to uninstall.
    /// @param moduleUninstallData Optional data to be decoded and used by the module to clear module data for the
    /// modular account.
    function uninstallModule(address module, ModuleManifest calldata manifest, bytes calldata moduleUninstallData)
        external;
}
