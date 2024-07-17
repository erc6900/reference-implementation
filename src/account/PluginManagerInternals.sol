// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {PluginEntityLib} from "../helpers/PluginEntityLib.sol";
import {IPlugin, ManifestExecutionHook, ManifestValidation, PluginManifest} from "../interfaces/IPlugin.sol";
import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {PluginEntity, IPluginManager} from "../interfaces/IPluginManager.sol";
import {KnownSelectors} from "../helpers/KnownSelectors.sol";
import {AccountStorage, getAccountStorage, SelectorData, toSetValue} from "./AccountStorage.sol";

abstract contract PluginManagerInternals is IPluginManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using PluginEntityLib for PluginEntity;

    error ArrayLengthMismatch();
    error Erc4337FunctionNotAllowed(bytes4 selector);
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error InvalidPluginManifest();
    error IPluginFunctionNotAllowed(bytes4 selector);
    error NativeFunctionNotAllowed(bytes4 selector);
    error NullPluginEntity();
    error NullPlugin();
    error PluginAlreadyInstalled(address plugin);
    error PluginInstallCallbackFailed(address plugin, bytes revertReason);
    error PluginInterfaceNotSupported(address plugin);
    error PluginNotInstalled(address plugin);
    error ValidationFunctionAlreadySet(bytes4 selector, PluginEntity validationFunction);

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

    function _addValidationFunction(address plugin, ManifestValidation memory mv) internal {
        AccountStorage storage _storage = getAccountStorage();

        PluginEntity validationFunction = PluginEntityLib.pack(plugin, mv.entityId);

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

    function _removeValidationFunction(address plugin, ManifestValidation memory mv) internal {
        AccountStorage storage _storage = getAccountStorage();

        PluginEntity validationFunction = PluginEntityLib.pack(plugin, mv.entityId);

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

    function _installPlugin(address plugin, bytes32 manifestHash, bytes memory pluginInstallData) internal {
        AccountStorage storage _storage = getAccountStorage();

        if (plugin == address(0)) {
            revert NullPlugin();
        }

        // Check if the plugin exists.
        if (_storage.pluginManifestHashes.contains(plugin)) {
            revert PluginAlreadyInstalled(plugin);
        }

        // Check that the plugin supports the IPlugin interface.
        if (!ERC165Checker.supportsInterface(plugin, type(IPlugin).interfaceId)) {
            revert PluginInterfaceNotSupported(plugin);
        }

        // Check manifest hash.
        PluginManifest memory manifest = IPlugin(plugin).pluginManifest();
        if (!_isValidPluginManifest(manifest, manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Add the plugin metadata to the account
        _storage.pluginManifestHashes.set(plugin, uint256(manifestHash));

        // Update components according to the manifest.
        uint256 length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            bytes4 selector = manifest.executionFunctions[i].executionSelector;
            bool isPublic = manifest.executionFunctions[i].isPublic;
            bool allowGlobalValidation = manifest.executionFunctions[i].allowGlobalValidation;
            _setExecutionFunction(selector, isPublic, allowGlobalValidation, plugin);
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            // Todo: limit this to only "direct runtime call" validation path (old EFP),
            // and add a way for the user to specify permission/pre-val hooks here.
            _addValidationFunction(plugin, manifest.validationFunctions[i]);
        }

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

        emit PluginInstalled(plugin, manifestHash);
    }

    function _uninstallPlugin(address plugin, PluginManifest memory manifest, bytes memory uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Check if the plugin exists.
        if (!_storage.pluginManifestHashes.contains(plugin)) {
            revert PluginNotInstalled(plugin);
        }

        // Check manifest hash.
        bytes32 manifestHash = bytes32(_storage.pluginManifestHashes.get(plugin));
        if (!_isValidPluginManifest(manifest, manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        uint256 length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            PluginEntity hookFunction = PluginEntityLib.pack(plugin, mh.entityId);
            EnumerableSet.Bytes32Set storage execHooks = _storage.selectorData[mh.executionSelector].executionHooks;
            _removeExecHooks(execHooks, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            _removeValidationFunction(plugin, manifest.validationFunctions[i]);
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

        // Remove the plugin metadata from the account.
        _storage.pluginManifestHashes.remove(plugin);

        // Clear the plugin storage for the account.
        bool onUninstallSuccess = true;
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onUninstall(uninstallData) {}
        catch {
            onUninstallSuccess = false;
        }

        emit PluginUninstalled(plugin, onUninstallSuccess);
    }

    function _isValidPluginManifest(PluginManifest memory manifest, bytes32 manifestHash)
        internal
        pure
        returns (bool)
    {
        return manifestHash == keccak256(abi.encode(manifest));
    }
}
