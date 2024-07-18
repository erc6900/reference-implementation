// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {RESERVED_VALIDATION_DATA_INDEX, SELF_PERMIT_VALIDATION_FUNCTIONID} from "../helpers/Constants.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {PluginEntityLib} from "../helpers/PluginEntityLib.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";
import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {IPlugin, ManifestExecutionHook, PluginManifest} from "../interfaces/IPlugin.sol";
import {IPluginManager, PluginEntity, ValidationConfig} from "../interfaces/IPluginManager.sol";
import {AccountStorage, SelectorData, ValidationData, getAccountStorage, toSetValue} from "./AccountStorage.sol";

abstract contract PluginManagerInternals is IPluginManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using PluginEntityLib for PluginEntity;
    using ValidationConfigLib for ValidationConfig;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error IPluginFunctionNotAllowed(bytes4 selector);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullPlugin();
    error PermissionAlreadySet(PluginEntity validationFunction, ExecutionHook hook);
    error PluginInstallCallbackFailed(address plugin, bytes revertReason);
    error PluginInterfaceNotSupported(address plugin);
    error PluginNotInstalled(address plugin);
    error PreValidationHookLimitExceeded();
    error ValidationAlreadySet(bytes4 selector, PluginEntity validationFunction);

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, bool isPublic, bool allowGlobalValidation, address plugin)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (_selectorData.plugin != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        // Make sure incoming execution function does not collide with any native functions (data are stored on the
        // account implementation contract)
        if (KnownSelectors.isNativeFunction(selector)) {
            revert NativeFunctionNotAllowed(selector);
        }

        // Make sure incoming execution function is not a function in IPlugin
        if (KnownSelectors.isIPluginFunction(selector)) {
            revert IPluginFunctionNotAllowed(selector);
        }

        // Also make sure it doesn't collide with functions defined by ERC-4337
        // and called by the entry point. This prevents a malicious plugin from
        // sneaking in a function with the same selector as e.g.
        // `validatePaymasterUserOp` and turning the account into their own
        // personal paymaster.
        if (KnownSelectors.isErc4337Function(selector)) {
            revert Erc4337FunctionNotAllowed(selector);
        }

        _selectorData.plugin = plugin;
        _selectorData.isPublic = isPublic;
        _selectorData.allowGlobalValidation = allowGlobalValidation;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.plugin = address(0);
        _selectorData.isPublic = false;
        _selectorData.allowGlobalValidation = false;
    }

    function _addValidationFunction(ValidationConfig validationConfig, bytes4[] memory selectors) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.pluginEntity()];

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

    function _removeValidationFunction(PluginEntity validationFunction) internal {
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
        PluginEntity hookFunction,
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
        PluginEntity hookFunction,
        bool isPreExecHook,
        bool isPostExecHook
    ) internal {
        hooks.remove(
            toSetValue(
                ExecutionHook({hookFunction: hookFunction, isPreHook: isPreExecHook, isPostHook: isPostExecHook})
            )
        );
    }

    function _installPlugin(address plugin, PluginManifest calldata manifest, bytes memory pluginInstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        if (plugin == address(0)) {
            revert NullPlugin();
        }

        // TODO: do we need this check? Or switch to a non-165 checking function?
        // Check that the plugin supports the IPlugin interface.
        if (!ERC165Checker.supportsInterface(plugin, type(IPlugin).interfaceId)) {
            revert PluginInterfaceNotSupported(plugin);
        }

        // Update components according to the manifest.
        uint256 length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            bool isPublic = manifest.executionFunctions[i].isPublic;
            bool allowGlobalValidation = manifest.executionFunctions[i].allowGlobalValidation;
            _setExecutionFunction(selector, isPublic, allowGlobalValidation, plugin);
        }

        // Install direct call validation, if any, from the manifest

        // Todo: add a way for the user to specify permission/pre-val hooks here.

        ValidationConfig directCallValidation = ValidationConfigLib.pack({
            _plugin: plugin,
            _entityId: SELF_PERMIT_VALIDATION_FUNCTIONID,
            _isGlobal: manifest.globalDirectCallValidation,
            // Direct call validation is never a signature validation
            _isSignatureValidation: false
        });

        _addValidationFunction(directCallValidation, manifest.directCallValidationSelectors);

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            EnumerableSet.Bytes32Set storage execHooks = _storage.selectorData[mh.executionSelector].executionHooks;
            PluginEntity hookFunction = PluginEntityLib.pack(plugin, mh.entityId);
            _addExecHooks(execHooks, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
        }

        // Initialize the plugin storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onInstall(pluginInstallData) {}
        catch (bytes memory revertReason) {
            revert PluginInstallCallbackFailed(plugin, revertReason);
        }

        emit PluginInstalled(plugin);
    }

    function _uninstallPlugin(address plugin, PluginManifest calldata manifest, bytes memory uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            PluginEntity hookFunction = PluginEntityLib.pack(plugin, mh.entityId);
            EnumerableSet.Bytes32Set storage execHooks = _storage.selectorData[mh.executionSelector].executionHooks;
            _removeExecHooks(execHooks, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        if (manifest.globalDirectCallValidation || manifest.directCallValidationSelectors.length > 0) {
            PluginEntity directCallValidation = PluginEntityLib.pack(plugin, SELF_PERMIT_VALIDATION_FUNCTIONID);

            _removeValidationFunction(directCallValidation);
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

        // Clear the plugin storage for the account.
        bool onUninstallSuccess = true;
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onUninstall(uninstallData) {}
        catch {
            onUninstallSuccess = false;
        }

        emit PluginUninstalled(plugin, onUninstallSuccess);
    }

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks,
        bytes memory permissionHooks
    ) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.pluginEntity()];

        if (preValidationHooks.length > 0) {
            (PluginEntity[] memory preValidationFunctions, bytes[] memory initDatas) =
                abi.decode(preValidationHooks, (PluginEntity[], bytes[]));

            for (uint256 i = 0; i < preValidationFunctions.length; ++i) {
                PluginEntity preValidationFunction = preValidationFunctions[i];

                _validationData.preValidationHooks.push(preValidationFunction);

                if (initDatas[i].length > 0) {
                    (address preValidationPlugin,) = PluginEntityLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onInstall(initDatas[i]);
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
                    revert PermissionAlreadySet(validationConfig.pluginEntity(), permissionFunction);
                }

                if (initDatas[i].length > 0) {
                    (address executionPlugin,) = PluginEntityLib.unpack(permissionFunction.hookFunction);
                    IPlugin(executionPlugin).onInstall(initDatas[i]);
                }
            }
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationData.selectors.add(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, validationConfig.pluginEntity());
            }
        }

        if (validationConfig.entityId() != SELF_PERMIT_VALIDATION_FUNCTIONID) {
            // Only allow global validations and signature validations if they're not direct-call validations.

            _validationData.isGlobal = validationConfig.isGlobal();
            _validationData.isSignatureValidation = validationConfig.isSignatureValidation();
            if (installData.length > 0) {
                IPlugin(validationConfig.plugin()).onInstall(installData);
            }
        }
    }

    function _uninstallValidation(
        PluginEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];

        _removeValidationFunction(validationFunction);

        {
            bytes[] memory preValidationHookUninstallDatas = abi.decode(preValidationHookUninstallData, (bytes[]));

            // Clear pre validation hooks
            PluginEntity[] storage preValidationHooks = _validationData.preValidationHooks;
            for (uint256 i = 0; i < preValidationHooks.length; ++i) {
                PluginEntity preValidationFunction = preValidationHooks[i];
                if (preValidationHookUninstallDatas[0].length > 0) {
                    (address preValidationPlugin,) = PluginEntityLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onUninstall(preValidationHookUninstallDatas[0]);
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
                address permissionHookPlugin = address(uint160(bytes20(permissionHook)));
                IPlugin(permissionHookPlugin).onUninstall(permissionHookUninstallDatas[i]);
            }
        }

        // Clear selectors
        uint256 selectorLen = _validationData.selectors.length();
        for (uint256 i = 0; i < selectorLen; ++i) {
            bytes32 selectorSetValue = _validationData.selectors.at(0);
            _validationData.selectors.remove(selectorSetValue);
        }

        if (uninstallData.length > 0) {
            (address plugin,) = PluginEntityLib.unpack(validationFunction);
            IPlugin(plugin).onUninstall(uninstallData);
        }
    }
}
