// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {ExecutionManifest} from "./IExecutionModule.sol";

type ModuleEntity is bytes24;

type ValidationConfig is bytes26;

type HookConfig is bytes26;

struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

interface IModularAccount {
    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    event ValidationInstalled(address indexed module, uint32 indexed entityId);
    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    /// @notice Standard execute method.
    /// @param target The target address for the account to call.
    /// @param value The value to send with the call.
    /// @param data The calldata for the call.
    /// @return The return data from the call.
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a module, the call SHOULD revert. If any of the calls revert, the entire batch MUST
    /// revert.
    /// @param calls The array of calls.
    /// @return An array containing the return data from the calls.
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory);

    /// @notice Execute a call using a specified runtime validation.
    /// @param data The calldata to send to the account.
    /// @param authorization The authorization data to use for the call. The first 24 bytes specifies which runtime
    /// validation to use, and the rest is sent as a parameter to runtime validation.
    function executeWithAuthorization(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory);

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

    /// @notice Installs a validation function across a set of execution selectors, and optionally mark it as a
    /// global validation.
    /// @dev This does not validate anything against the manifest - the caller must ensure validity.
    /// @param validationConfig The validation function to install, along with configuration flags.
    /// @param selectors The selectors to install the validation function for.
    /// @param installData Optional data to be decoded and used by the module to setup initial module state.
    /// @param hooks Optional hooks to install, associated with the validation function. These may be
    /// pre validation hooks or execution hooks. The expected format is a bytes26 HookConfig, followed by the
    /// install data, if any.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external;

    /// @notice Uninstall a validation function from a set of execution selectors.
    /// @param validationFunction The validation function to uninstall.
    /// @param uninstallData Optional data to be decoded and used by the module to clear module data for the
    /// account.
    /// @param hookUninstallData Optional data to be used by hooks for cleanup. If any are provided, the array must
    /// be of a length equal to existing pre validation hooks plus permission hooks. Hooks are indexed by
    /// pre validation hook order first, then permission hooks.
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

    /// @notice Return a unique identifier for the account implementation.
    /// @dev This function MUST return a string in the format "vendor.account.semver". The vendor and account
    /// names MUST NOT contain a period character.
    /// @return The account ID.
    function accountId() external view returns (string memory);
}
