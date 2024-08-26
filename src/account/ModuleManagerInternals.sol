// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {collectReturnData} from "../helpers/CollectReturnData.sol";
import {MAX_PRE_VALIDATION_HOOKS} from "../helpers/Constants.sol";
import {HookConfigLib} from "../helpers/HookConfigLib.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {ExecutionManifest, ManifestExecutionHook} from "../interfaces/IExecutionModule.sol";
import {HookConfig, IModularAccount, ModuleEntity, ValidationConfig} from "../interfaces/IModularAccount.sol";
import {IModule} from "../interfaces/IModule.sol";
import {IValidationHookModule} from "../interfaces/IValidationHookModule.sol";
import {IValidationModule} from "../interfaces/IValidationModule.sol";

import {
    AccountStorage,
    ExecutionData,
    ValidationData,
    getAccountStorage,
    toModuleEntity,
    toSetValue
} from "./AccountStorage.sol";

abstract contract ModuleManagerInternals is IModularAccount {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error InterfaceNotSupported(address module);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullModule();
    error PermissionAlreadySet(ModuleEntity validationFunction, HookConfig hookConfig);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ModuleNotInstalled(address module);
    error PreValidationHookLimitExceeded();
    error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, bool isPublic, bool allowGlobalValidation, address module)
        internal
    {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        if (_executionData.module != address(0)) {
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

        _executionData.module = module;
        _executionData.isPublic = isPublic;
        _executionData.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        ExecutionData storage _executionData = getAccountStorage().executionData[selector];

        _executionData.module = address(0);
        _executionData.isPublic = false;
        _executionData.allowGlobalValidation = false;
    }

    function _removeValidationFunction(ModuleEntity validationFunction) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];

        _validationData.isGlobal = false;
        _validationData.isSignatureValidation = false;

        // Clear the selectors
        uint256 length = _validationData.selectors.length();
        for (uint256 i = 0; i < length; ++i) {
            _validationData.selectors.remove(_validationData.selectors.at(0));
        }
    }

    function _addExecHooks(EnumerableSet.Bytes32Set storage hooks, HookConfig hookConfig) internal {
        hooks.add(toSetValue(hookConfig));
    }

    function _removeExecHooks(EnumerableSet.Bytes32Set storage hooks, HookConfig hookConfig) internal {
        hooks.remove(toSetValue(hookConfig));
    }

    function _installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        if (module == address(0)) {
            revert NullModule();
        }

        // Update components according to the manifest.
        uint256 length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            bool isPublic = manifest.executionFunctions[i].isPublic;
            bool allowGlobalValidation = manifest.executionFunctions[i].allowGlobalValidation;
            _setExecutionFunction(selector, isPublic, allowGlobalValidation, module);
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            EnumerableSet.Bytes32Set storage execHooks =
                _storage.executionData[mh.executionSelector].executionHooks;
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _addExecHooks(execHooks, hookConfig);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        _onInstall(module, moduleInstallData, type(IModule).interfaceId);

        emit ExecutionInstalled(module, manifest);
    }

    function _uninstallExecution(address module, ExecutionManifest calldata manifest, bytes calldata uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            EnumerableSet.Bytes32Set storage execHooks =
                _storage.executionData[mh.executionSelector].executionHooks;
            HookConfig hookConfig = HookConfigLib.packExecHook({
                _module: module,
                _entityId: mh.entityId,
                _hasPre: mh.isPreHook,
                _hasPost: mh.isPostHook
            });
            _removeExecHooks(execHooks, hookConfig);
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
        bool onUninstallSuccess = _onUninstall(module, uninstallData);

        emit ExecutionUninstalled(module, onUninstallSuccess, manifest);
    }

    function _onInstall(address module, bytes calldata data, bytes4 interfaceId) internal {
        if (data.length > 0) {
            if (!ERC165Checker.supportsInterface(module, interfaceId)) {
                revert InterfaceNotSupported(module);
            }
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onInstall(data) {}
            catch {
                bytes memory revertReason = collectReturnData();
                revert ModuleInstallCallbackFailed(module, revertReason);
            }
        }
    }

    function _onUninstall(address module, bytes calldata data) internal returns (bool onUninstallSuccess) {
        onUninstallSuccess = true;
        if (data.length > 0) {
            // Clear the module storage for the account.
            // solhint-disable-next-line no-empty-blocks
            try IModule(module).onUninstall(data) {}
            catch {
                onUninstallSuccess = false;
            }
        }
    }

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.moduleEntity()];
        ModuleEntity moduleEntity = validationConfig.moduleEntity();

        for (uint256 i = 0; i < hooks.length; ++i) {
            HookConfig hookConfig = HookConfig.wrap(bytes26(hooks[i][:26]));
            bytes calldata hookData = hooks[i][26:];

            if (hookConfig.isValidationHook()) {
                _validationData.preValidationHooks.push(hookConfig.moduleEntity());

                // Avoid collision between reserved index and actual indices
                if (_validationData.preValidationHooks.length > MAX_PRE_VALIDATION_HOOKS) {
                    revert PreValidationHookLimitExceeded();
                }

                _onInstall(hookConfig.module(), hookData, type(IValidationHookModule).interfaceId);

                continue;
            }
            // Hook is a permission hook
            if (!_validationData.permissionHooks.add(toSetValue(hookConfig))) {
                revert PermissionAlreadySet(moduleEntity, hookConfig);
            }

            _onInstall(hookConfig.module(), hookData, type(IExecutionHookModule).interfaceId);
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationData.selectors.add(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, moduleEntity);
            }
        }

        _validationData.isGlobal = validationConfig.isGlobal();
        _validationData.isSignatureValidation = validationConfig.isSignatureValidation();

        _onInstall(validationConfig.module(), installData, type(IValidationModule).interfaceId);
        emit ValidationInstalled(validationConfig.module(), validationConfig.entityId());
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallDatas
    ) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];
        bool onUninstallSuccess = true;

        _removeValidationFunction(validationFunction);

        // Send `onUninstall` to hooks
        if (hookUninstallDatas.length > 0) {
            // If any uninstall data is provided, assert it is of the correct length.
            if (
                hookUninstallDatas.length
                    != _validationData.preValidationHooks.length + _validationData.permissionHooks.length()
            ) {
                revert ArrayLengthMismatch();
            }

            // Hook uninstall data is provided in the order of pre validation hooks, then permission hooks.
            uint256 hookIndex = 0;
            for (uint256 i = 0; i < _validationData.preValidationHooks.length; ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                (address hookModule,) = ModuleEntityLib.unpack(_validationData.preValidationHooks[i]);
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }

            for (uint256 i = 0; i < _validationData.permissionHooks.length(); ++i) {
                bytes calldata hookData = hookUninstallDatas[hookIndex];
                (address hookModule,) =
                    ModuleEntityLib.unpack(toModuleEntity(_validationData.permissionHooks.at(i)));
                onUninstallSuccess = onUninstallSuccess && _onUninstall(hookModule, hookData);
                hookIndex++;
            }
        }

        // Clear all stored hooks
        delete _validationData.preValidationHooks;

        EnumerableSet.Bytes32Set storage permissionHooks = _validationData.permissionHooks;
        uint256 permissionHookLen = permissionHooks.length();
        for (uint256 i = 0; i < permissionHookLen; ++i) {
            bytes32 permissionHook = permissionHooks.at(0);
            permissionHooks.remove(permissionHook);
        }

        // Clear selectors
        uint256 selectorLen = _validationData.selectors.length();
        for (uint256 i = 0; i < selectorLen; ++i) {
            bytes32 selectorSetValue = _validationData.selectors.at(0);
            _validationData.selectors.remove(selectorSetValue);
        }

        (address module, uint32 entityId) = ModuleEntityLib.unpack(validationFunction);
        onUninstallSuccess = onUninstallSuccess && _onUninstall(module, uninstallData);

        emit ValidationUninstalled(module, entityId, onUninstallSuccess);
    }
}
