// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExternalCallPermission,
    PluginManifest
} from "../interfaces/IPlugin.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {
    AccountStorage,
    getAccountStorage,
    HookData,
    SelectorData,
    toSetValue,
    getPermittedCallKey,
    PermittedExternalCallData
} from "./AccountStorage.sol";

abstract contract PluginManagerInternals is IPluginManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;
    using FunctionReferenceLib for FunctionReference;

    error ArrayLengthMismatch();
    error ExecutionFunctionAlreadySet(bytes4 selector);
    error InvalidDependenciesProvided();
    error InvalidPluginManifest();
    error MissingPluginDependency(address dependency);
    error NullFunctionReference();
    error NullPlugin();
    error PluginAlreadyInstalled(address plugin);
    error PluginDependencyViolation(address plugin);
    error PluginInstallCallbackFailed(address plugin, bytes revertReason);
    error PluginInterfaceNotSupported(address plugin);
    error PluginNotInstalled(address plugin);
    error ValidationFunctionAlreadySet(bytes4 selector, FunctionReference validationFunction);

    modifier notNullFunction(FunctionReference functionReference) {
        if (functionReference.isEmpty()) {
            revert NullFunctionReference();
        }
        _;
    }

    modifier notNullPlugin(address plugin) {
        if (plugin == address(0)) {
            revert NullPlugin();
        }
        _;
    }

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, address plugin) internal notNullPlugin(plugin) {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (_selectorData.plugin != address(0)) {
            revert ExecutionFunctionAlreadySet(selector);
        }

        _selectorData.plugin = plugin;
    }

    function _removeExecutionFunction(bytes4 selector) internal {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.plugin = address(0);
    }

    function _addValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (_selectorData.validation.notEmpty()) {
            revert ValidationFunctionAlreadySet(selector, validationFunction);
        }

        _selectorData.validation = validationFunction;
    }

    function _removeValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.validation = FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE;
    }

    function _addExecHooks(
        bytes4 selector,
        FunctionReference hookFunction,
        bool isPreExecHook,
        bool isPostExecHook
    ) internal {
        getAccountStorage().selectorData[selector].executionHooks.add(
            toSetValue(
                HookData({hookFunction: hookFunction, isPreHook: isPreExecHook, isPostHook: isPostExecHook})
            )
        );
    }

    function _removeExecHooks(
        bytes4 selector,
        FunctionReference hookFunction,
        bool isPreExecHook,
        bool isPostExecHook
    ) internal {
        getAccountStorage().selectorData[selector].executionHooks.remove(
            toSetValue(
                HookData({hookFunction: hookFunction, isPreHook: isPreExecHook, isPostHook: isPostExecHook})
            )
        );
    }

    function _addPreValidationHook(bytes4 selector, FunctionReference preValidationHook)
        internal
        notNullFunction(preValidationHook)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];
        if (preValidationHook.eq(FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY)) {
            // Increment `denyExecutionCount`, because this pre validation hook may be applied multiple times.
            _selectorData.denyExecutionCount += 1;
            return;
        }
        _selectorData.preValidationHooks.add(toSetValue(preValidationHook));
    }

    function _removePreValidationHook(bytes4 selector, FunctionReference preValidationHook)
        internal
        notNullFunction(preValidationHook)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];
        if (preValidationHook.eq(FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY)) {
            // Decrement `denyExecutionCount`, because this pre exec hook may be applied multiple times.
            _selectorData.denyExecutionCount -= 1;
            return;
        }
        // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
        _selectorData.preValidationHooks.remove(toSetValue(preValidationHook));
    }

    function _installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes memory pluginInstallData,
        FunctionReference[] memory dependencies
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        // Check if the plugin exists.
        if (!_storage.plugins.add(plugin)) {
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

        // Check that the dependencies match the manifest.
        if (dependencies.length != manifest.dependencyInterfaceIds.length) {
            revert InvalidDependenciesProvided();
        }

        uint256 length = dependencies.length;
        for (uint256 i = 0; i < length; ++i) {
            // Check the dependency interface id over the address of the dependency.
            (address dependencyAddr,) = dependencies[i].unpack();

            // Check that the dependency is installed.
            if (_storage.pluginData[dependencyAddr].manifestHash == bytes32(0)) {
                revert MissingPluginDependency(dependencyAddr);
            }

            // Check that the dependency supports the expected interface.
            if (!ERC165Checker.supportsInterface(dependencyAddr, manifest.dependencyInterfaceIds[i])) {
                revert InvalidDependenciesProvided();
            }

            // Increment the dependency's dependents counter.
            _storage.pluginData[dependencyAddr].dependentCount += 1;
        }

        // Add the plugin metadata to the account
        _storage.pluginData[plugin].manifestHash = manifestHash;
        _storage.pluginData[plugin].dependencies = dependencies;

        // Update components according to the manifest.

        // Mark whether or not this plugin may spend native token amounts
        if (manifest.canSpendNativeToken) {
            _storage.pluginData[plugin].canSpendNativeToken = true;
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            _setExecutionFunction(manifest.executionFunctions[i], plugin);
        }

        // Add installed plugin and selectors this plugin can call
        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            // If there are duplicates, this will just enable the flag again. This is not a problem, since the
            // boolean will be set to false twice during uninstall, which is fine.
            _storage.callPermitted[getPermittedCallKey(plugin, manifest.permittedExecutionSelectors[i])] = true;
        }

        // Add the permitted external calls to the account.
        if (manifest.permitAnyExternalAddress) {
            _storage.pluginData[plugin].anyExternalExecPermitted = true;
        } else {
            // Only store the specific permitted external calls if "permit any" flag was not set.
            length = manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission = manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    _storage.permittedExternalCalls[IPlugin(plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = true;

                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = true;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength; ++j) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = true;
                    }
                }
            }
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mv = manifest.validationFunctions[i];
            _addValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW
                )
            );
        }

        // Hooks are not allowed to be provided as dependencies, so we use an empty array for resolving them.
        FunctionReference[] memory emptyDependencies;

        length = manifest.preValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = manifest.preValidationHooks[i];
            _addPreValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            FunctionReference hookFunction = FunctionReferenceLib.pack(plugin, mh.functionId);
            _addExecHooks(mh.executionSelector, hookFunction, mh.isPreHook, mh.isPostHook);
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

        emit PluginInstalled(plugin, manifestHash, dependencies);
    }

    function _uninstallPlugin(address plugin, PluginManifest memory manifest, bytes memory uninstallData)
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        // Check if the plugin exists.
        if (!_storage.plugins.remove(plugin)) {
            revert PluginNotInstalled(plugin);
        }

        // Check manifest hash.
        bytes32 manifestHash = _storage.pluginData[plugin].manifestHash;
        if (!_isValidPluginManifest(manifest, manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Ensure that there are no dependent plugins.
        if (_storage.pluginData[plugin].dependentCount != 0) {
            revert PluginDependencyViolation(plugin);
        }

        // Remove this plugin as a dependent from its dependencies.
        FunctionReference[] memory dependencies = _storage.pluginData[plugin].dependencies;
        uint256 length = dependencies.length;
        for (uint256 i = 0; i < length; ++i) {
            FunctionReference dependency = dependencies[i];
            (address dependencyAddr,) = dependency.unpack();

            // Decrement the dependent count for the dependency function.
            _storage.pluginData[dependencyAddr].dependentCount -= 1;
        }

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        // Hooks are not allowed to be provided as dependencies, so we use an empty array for resolving them.
        FunctionReference[] memory emptyDependencies;

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            FunctionReference hookFunction = FunctionReferenceLib.pack(plugin, mh.functionId);
            _removeExecHooks(mh.executionSelector, hookFunction, mh.isPreHook, mh.isPostHook);
        }

        length = manifest.preValidationHooks.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mh = manifest.preValidationHooks[i];
            _removePreValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            ManifestAssociatedFunction memory mv = manifest.validationFunctions[i];
            _removeValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW
                )
            );
        }

        // remove external call permissions

        if (manifest.permitAnyExternalAddress) {
            // Only clear if it was set during install time
            _storage.pluginData[plugin].anyExternalExecPermitted = false;
        } else {
            // Only clear the specific permitted external calls if "permit any" flag was not set.
            length = manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length; ++i) {
                ManifestExternalCallPermission memory externalCallPermission = manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    _storage.permittedExternalCalls[IPlugin(plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = false;

                // Only clear this flag if it was set in the constructor.
                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = false;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength; ++j) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = false;
                    }
                }
            }
        }

        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.callPermitted[getPermittedCallKey(plugin, manifest.permittedExecutionSelectors[i])] = false;
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length; ++i) {
            _removeExecutionFunction(manifest.executionFunctions[i]);
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length; ++i) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] -= 1;
        }

        // Remove the plugin metadata from the account.
        delete _storage.pluginData[plugin];

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

    function _resolveManifestFunction(
        ManifestFunction memory manifestFunction,
        address plugin,
        FunctionReference[] memory dependencies,
        // Indicates which magic value, if any, is permissible for the function to resolve.
        ManifestAssociatedFunctionType allowedMagicValue
    ) internal pure returns (FunctionReference) {
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.SELF) {
            return FunctionReferenceLib.pack(plugin, manifestFunction.functionId);
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            if (manifestFunction.dependencyIndex >= dependencies.length) {
                revert InvalidPluginManifest();
            }
            return dependencies[manifestFunction.dependencyIndex];
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW)
        {
            if (allowedMagicValue == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                return FunctionReferenceLib._RUNTIME_VALIDATION_ALWAYS_ALLOW;
            } else {
                revert InvalidPluginManifest();
            }
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
                return FunctionReferenceLib._PRE_HOOK_ALWAYS_DENY;
            } else {
                revert InvalidPluginManifest();
            }
        }
        return FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE; // Empty checks are done elsewhere
    }
}
