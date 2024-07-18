// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {RESERVED_VALIDATION_DATA_INDEX, SELF_PERMIT_VALIDATION_FUNCTIONID} from "../helpers/Constants.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {IModule, ManifestExecutionHook, ModuleManifest} from "../interfaces/IModule.sol";
import {IModuleManager, ModuleEntity, ValidationConfig} from "../interfaces/IModuleManager.sol";
import {AccountStorage, SelectorData, ValidationData, getAccountStorage, toSetValue} from "./AccountStorage.sol";

abstract contract ModuleManagerInternals is IModuleManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IModuleFunctionNotAllowed(bytes4 selector);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullModule();
    error PermissionAlreadySet(ModuleEntity validationFunction, ExecutionHook hook);
    error ModuleInstallCallbackFailed(address module, bytes revertReason);
    error ModuleInterfaceNotSupported(address module);
    error ModuleNotInstalled(address module);
    error PreValidationHookLimitExceeded();
    error ValidationAlreadySet(bytes4 selector, ModuleEntity validationFunction);

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

    function _addValidationFunction(ValidationConfig validationConfig, bytes4[] memory selectors) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.moduleEntity()];

        if (validationConfig.isGlobal()) {
            _validationData.isGlobal = true;
        }

        if (validationConfig.isSignatureValidation()) {
            _validationData.isSignatureValidation = true;
        }

        // Add the validation function to the selectors.
        uint256 length = selectors.length;
        for (uint256 i = 0; i < length; ++i) {
            _validationData.selectors.add(toSetValue(selectors[i]));
        }
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

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks,
        bytes memory permissionHooks
    ) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.moduleEntity()];

        if (preValidationHooks.length > 0) {
            (ModuleEntity[] memory preValidationFunctions, bytes[] memory initDatas) =
                abi.decode(preValidationHooks, (ModuleEntity[], bytes[]));

            for (uint256 i = 0; i < preValidationFunctions.length; ++i) {
                ModuleEntity preValidationFunction = preValidationFunctions[i];

                _validationData.preValidationHooks.push(preValidationFunction);

                if (initDatas[i].length > 0) {
                    (address preValidationModule,) = ModuleEntityLib.unpack(preValidationFunction);
                    IModule(preValidationModule).onInstall(initDatas[i]);
                }
            }

            // Avoid collision between reserved index and actual indices
            if (_validationData.preValidationHooks.length > RESERVED_VALIDATION_DATA_INDEX) {
                revert PreValidationHookLimitExceeded();
            }
        }

        if (permissionHooks.length > 0) {
            (ExecutionHook[] memory permissionFunctions, bytes[] memory initDatas) =
                abi.decode(permissionHooks, (ExecutionHook[], bytes[]));

            for (uint256 i = 0; i < permissionFunctions.length; ++i) {
                ExecutionHook memory permissionFunction = permissionFunctions[i];

                if (!_validationData.permissionHooks.add(toSetValue(permissionFunction))) {
                    revert PermissionAlreadySet(validationConfig.moduleEntity(), permissionFunction);
                }

                if (initDatas[i].length > 0) {
                    (address executionModule,) = ModuleEntityLib.unpack(permissionFunction.hookFunction);
                    IModule(executionModule).onInstall(initDatas[i]);
                }
            }
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationData.selectors.add(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, validationConfig.moduleEntity());
            }
        }

        if (validationConfig.entityId() != SELF_PERMIT_VALIDATION_FUNCTIONID) {
            // Only allow global validations and signature validations if they're not direct-call validations.

            _validationData.isGlobal = validationConfig.isGlobal();
            _validationData.isSignatureValidation = validationConfig.isSignatureValidation();
            if (installData.length > 0) {
                IModule(validationConfig.module()).onInstall(installData);
            }
        }
    }

    function _uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];

        _removeValidationFunction(validationFunction);

        {
            bytes[] memory preValidationHookUninstallDatas = abi.decode(preValidationHookUninstallData, (bytes[]));

            // Clear pre validation hooks
            ModuleEntity[] storage preValidationHooks = _validationData.preValidationHooks;
            for (uint256 i = 0; i < preValidationHooks.length; ++i) {
                ModuleEntity preValidationFunction = preValidationHooks[i];
                if (preValidationHookUninstallDatas[0].length > 0) {
                    (address preValidationModule,) = ModuleEntityLib.unpack(preValidationFunction);
                    IModule(preValidationModule).onUninstall(preValidationHookUninstallDatas[0]);
                }
            }
            delete _validationData.preValidationHooks;
        }

        {
            bytes[] memory permissionHookUninstallDatas = abi.decode(permissionHookUninstallData, (bytes[]));

            // Clear permission hooks
            EnumerableSet.Bytes32Set storage permissionHooks = _validationData.permissionHooks;
            uint256 permissionHookLen = permissionHooks.length();
            for (uint256 i = 0; i < permissionHookLen; ++i) {
                bytes32 permissionHook = permissionHooks.at(0);
                permissionHooks.remove(permissionHook);
                address permissionHookModule = address(uint160(bytes20(permissionHook)));
                IModule(permissionHookModule).onUninstall(permissionHookUninstallDatas[i]);
            }
        }

        // Clear selectors
        uint256 selectorLen = _validationData.selectors.length();
        for (uint256 i = 0; i < selectorLen; ++i) {
            bytes32 selectorSetValue = _validationData.selectors.at(0);
            _validationData.selectors.remove(selectorSetValue);
        }

        if (uninstallData.length > 0) {
            (address module,) = ModuleEntityLib.unpack(validationFunction);
            IModule(module).onUninstall(uninstallData);
        }
    }
}
