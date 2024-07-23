// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";
import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {IModule, ManifestExecutionHook, ManifestValidation, ModuleManifest} from "../interfaces/IModule.sol";
import {IModuleManager, ModuleEntity} from "../interfaces/IModuleManager.sol";
import {AccountStorage, SelectorData, getAccountStorage, toSetValue} from "./AccountStorage.sol";

abstract contract ModuleManagerInternals is IModuleManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ModuleEntityLib for ModuleEntity;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullModule();
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ModuleInterfaceNotSupported(address module);
    error ModuleNotInstalled(address module);
    error ValidationFunctionAlreadySet(bytes4 selector, ModuleEntity validationFunction);

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, bool isPublic, bool allowGlobalValidation, address module)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (_selectorData.module != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        // Make sure incoming execution function does not collide with any native functions (data are stored on the
        // account implementation contract)
        if (KnownSelectors.isNativeFunction(selector)) {
            revert NativeFunctionNotAllowed(selector);
        }

        // Make sure incoming execution function is not a function in IModule
        if (KnownSelectors.isIModuleFunction(selector)) {
            revert IModuleFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337
        // and called by the entry point. This prevents a malicious module from
        // sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own
        // personal paymaster.
        if (KnownSelectors.isErc4337Function(selector)) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        _selectorData.module = module;
        _selectorData.isPublic = isPublic;
        _selectorData.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.module = address(0);
        _selectorData.isPublic = false;
        _selectorData.allowGlobalValidation = false;
    }

    function _addValidationFunction(address module, ManifestValidation memory mv) internal {
        AccountStorage storage _storage = getAccountStorage();

        ModuleEntity validationFunction = ModuleEntityLib.pack(module, mv.entityId);

        if (mv.isDefault) {
            _storage.validationData[validationFunction].isGlobal = true;
        }

        if (mv.isSignatureValidation) {
            _storage.validationData[validationFunction].isSignatureValidation = true;
        }

        // Add the validation function to the selectors.
        uint256 length = mv.selectors.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = mv.selectors[i];
            _storage.validationData[validationFunction].selectors.add(toSetValue(selector));
        }
    }

    function _removeValidationFunction(address module, ManifestValidation memory mv) internal {
        AccountStorage storage _storage = getAccountStorage();

        ModuleEntity validationFunction = ModuleEntityLib.pack(module, mv.entityId);

        _storage.validationData[validationFunction].isGlobal = false;
        _storage.validationData[validationFunction].isSignatureValidation = false;

        // Clear the selectors
        while (_storage.validationData[validationFunction].selectors.length() > 0) {
            bytes32 selector = _storage.validationData[validationFunction].selectors.at(0);
            _storage.validationData[validationFunction].selectors.remove(selector);
        }
    }

    function _addExecHooks(
        EnumerableSet.Bytes32Set storage hooks,
        ModuleEntity hookFunction,
        bool isPreExecHook,
        bool isPostExecHook
    ) internal {
        hooks.add(
            toSetValue(
                ExecutionHook({hookFunction: hookFunction, isPreHook: isPreExecHook, isPostHook: isPostExecHook})
            )
        );
    }

    function _removeExecHooks(
        EnumerableSet.Bytes32Set storage hooks,
        ModuleEntity hookFunction,
        bool isPreExecHook,
        bool isPostExecHook
    ) internal {
        hooks.remove(
            toSetValue(
                ExecutionHook({hookFunction: hookFunction, isPreHook: isPreExecHook, isPostHook: isPostExecHook})
            )
        );
    }

    function _installModule(address module, ModuleManifest calldata manifest, bytes memory moduleInstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        if (module == address(0)) {
            revert NullModule();
        }

        // TODO: do we need this check? Or switch to a non-165 checking function?
        // Check that the module supports the IModule interface.
        if (!ERC165Checker.supportsInterface(module, type(IModule).interfaceId)) {
            revert ModuleInterfaceNotSupported(module);
        }

        // Update components according to the manifest.
        uint256 length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            bool isPublic = manifest.executionFunctions[i].isPublic;
            bool allowGlobalValidation = manifest.executionFunctions[i].allowGlobalValidation;
            _setExecutionFunction(selector, isPublic, allowGlobalValidation, module);
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            // Todo: limit this to only "direct runtime call" validation path (old EFP),
            // and add a way for the user to specify permission/pre-val hooks here.
            _addValidationFunction(module, manifest.validationFunctions[i]);
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            EnumerableSet.Bytes32Set storage execHooks = _storage.selectorData[mh.executionSelector].executionHooks;
            ModuleEntity hookFunction = ModuleEntityLib.pack(module, mh.entityId);
            _addExecHooks(execHooks, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        // Initialize the module storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IModule(module).onInstall(moduleInstallData) {}
        catch (bytes memory revertReason) {
            revert ModuleInstallCallbackFailed(module, revertReason);
        }

        emit ModuleInstalled(module);
    }

    function _uninstallModule(address module, ModuleManifest calldata manifest, bytes memory uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            ModuleEntity hookFunction = ModuleEntityLib.pack(module, mh.entityId);
            EnumerableSet.Bytes32Set storage execHooks = _storage.selectorData[mh.executionSelector].executionHooks;
            _removeExecHooks(execHooks, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            _removeValidationFunction(module, manifest.validationFunctions[i]);
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            _removeExecutionFunction(selector);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] -= 1;
        }

        // Clear the module storage for the account.
        bool onUninstallSuccess = true;
        // solhint-disable-next-line no-empty-blocks
        try IModule(module).onUninstall(uninstallData) {}
        catch {
            onUninstallSuccess = false;
        }

        emit ModuleUninstalled(module, onUninstallSuccess);
    }
}
