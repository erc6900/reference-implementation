// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {ExecutionManifest} from "./IExecutionModule.sol";

type ModuleEntity is bytes24;

type ValidationConfig is bytes26;

type HookConfig is bytes26;

interface IModuleManager {
    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    event ValidationInstalled(address indexed module, uint32 indexed entityId);
    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    /// @notice Install a module to the modular account.
    /// @param module The module to install.
    /// @param manifest the manifest describing functions to install
    /// @param moduleInstallData Optional data to be decoded and used by the module to setup initial module data
    /// for the modular account.
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external;

    /// @notice Temporary install function - pending a different user-supplied install config & manifest validation
    /// path.
    /// Installs a validation function across a set of execution selectors, and optionally mark it as a global
    /// validation.
    /// TODO: remove or update.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the module to setup initial module state.
    /// @param hooks Optional hooks to install, associated with the validation function. These may be
    /// pre-validation hooks or execution hooks. The expected format is a bytes26 HookConfig, followed by the
    /// install data, if any.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// TODO: remove or update.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be decoded and used by the module to clear module data for the
    /// account.
    /// @param hookUninstallData Optional data to be used by hooks for cleanup. If any are provided, the array must
    /// be of a length equal to existing pre-validation hooks plus permission hooks. Hooks are indexed by
    /// pre-validation hook order first, then permission hooks.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external;

    /// @notice Uninstall a module from the modular account.
    /// @param module The module to uninstall.
    /// @param manifest the manifest describing functions to uninstall.
    /// @param moduleUninstallData Optional data to be decoded and used by the module to clear module data for the
    /// modular account.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleUninstallData
    ) external;
}
