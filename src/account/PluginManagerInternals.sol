// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
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
    SelectorData,
    getPermittedCallKey,
    PermittedExternalCallData,
    toPlugin
} from "./AccountStorage.sol";

abstract contract PluginManagerInternals is IPluginManager {
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;
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
    error ValidationFunctionAlreadySet(bytes4 selector, IPlugin validation);

    IPlugin internal constant NULL_PLUGIN = IPlugin(address(0));
    IPlugin internal constant _RUNTIME_VALIDATION_ALWAYS_ALLOW = IPlugin(address(1));
    IPlugin internal constant _PRE_HOOK_ALWAYS_DENY = IPlugin(address(2));

    modifier notNullPlugin(IPlugin plugin) {
        if (address(plugin) == address(0)) {
            revert NullPlugin();
        }
        _;
    }

    // Storage update operations

    function _setExecutionFunction(bytes4 selector, address plugin) internal notNullPlugin(IPlugin(plugin)) {
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

    function _addValidationFunction(bytes4 selector, IPlugin validation)
        internal
        notNullPlugin(validation)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (_selectorData.validation != NULL_PLUGIN) {
            revert ValidationFunctionAlreadySet(selector, validation);
        }

        _selectorData.validation = validation;
    }

    function _removeValidationFunction(bytes4 selector, IPlugin validation)
        internal
        notNullPlugin(validation)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.validation = NULL_PLUGIN;
    }

    function _addExecHooks(bytes4 selector, IPlugin preExecHook, IPlugin postExecHook)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (preExecHook != NULL_PLUGIN) {
            _addOrIncrement(_selectorData.preHooks, _toSetValue(preExecHook));

            if (postExecHook != NULL_PLUGIN) {
                _addOrIncrement(_selectorData.associatedPostHooks[preExecHook], _toSetValue(postExecHook));
            }
        } else {
            if (postExecHook == NULL_PLUGIN) {
                // both pre and post hooks cannot be null
                revert NullPlugin();
            }

            _addOrIncrement(_selectorData.postOnlyHooks, _toSetValue(postExecHook));
        }
    }

    function _removeExecHooks(bytes4 selector, IPlugin preExecHook, IPlugin postExecHook)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (preExecHook != NULL_PLUGIN) {
            _removeOrDecrement(_selectorData.preHooks, _toSetValue(preExecHook));

            if (postExecHook != NULL_PLUGIN) {
                _removeOrDecrement(_selectorData.associatedPostHooks[preExecHook], _toSetValue(postExecHook));
            }
        } else {
            // The case where both pre and post hooks are null was checked during installation.

            // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
            _removeOrDecrement(_selectorData.postOnlyHooks, _toSetValue(postExecHook));
        }
    }

    function _addPreUserOpValidationHook(bytes4 selector, IPlugin preUserOpValidationHook)
        internal
        notNullPlugin(preUserOpValidationHook)
    {
        _addOrIncrement(
            getAccountStorage().selectorData[selector].preUserOpValidationHooks,
            _toSetValue(preUserOpValidationHook)
        );
    }

    function _removePreUserOpValidationHook(bytes4 selector, IPlugin preUserOpValidationHook)
        internal
        notNullPlugin(preUserOpValidationHook)
    {
        // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
        _removeOrDecrement(
            getAccountStorage().selectorData[selector].preUserOpValidationHooks,
            _toSetValue(preUserOpValidationHook)
        );
    }

    function _addPreRuntimeValidationHook(bytes4 selector, IPlugin preRuntimeValidationHook)
        internal
        notNullPlugin(preRuntimeValidationHook)
    {
        _addOrIncrement(
            getAccountStorage().selectorData[selector].preRuntimeValidationHooks,
            _toSetValue(preRuntimeValidationHook)
        );
    }

    function _removePreRuntimeValidationHook(bytes4 selector, IPlugin preRuntimeValidationHook)
        internal
        notNullPlugin(preRuntimeValidationHook)
    {
        // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
        _removeOrDecrement(
            getAccountStorage().selectorData[selector].preRuntimeValidationHooks,
            _toSetValue(preRuntimeValidationHook)
        );
    }

    function _installPlugin(
        address plugin,
        bytes32 manifestHash,
        bytes memory pluginInstallData,
        address[] memory dependencies
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
        for (uint256 i = 0; i < length;) {
            // Check the dependency interface id over the address of the dependency.
            IPlugin dependencyAddr = IPlugin(dependencies[i]);

            // Check that the dependency is installed.
            if (_storage.pluginData[dependencyAddr].manifestHash == bytes32(0)) {
                revert MissingPluginDependency(address(dependencyAddr));
            }

            // Check that the dependency supports the expected interface.
            if (!ERC165Checker.supportsInterface(address(dependencyAddr), manifest.dependencyInterfaceIds[i])) {
                revert InvalidDependenciesProvided();
            }

            // Increment the dependency's dependents counter.
            _storage.pluginData[dependencyAddr].dependentCount += 1;

            unchecked {
                ++i;
            }
        }

        // Add the plugin metadata to the account
        _storage.pluginData[IPlugin(plugin)].manifestHash = manifestHash;
        _storage.pluginData[IPlugin(plugin)].dependencies = dependencies;

        // Update components according to the manifest.

        // Mark whether or not this plugin may spend native token amounts
        if (manifest.canSpendNativeToken) {
            _storage.pluginData[IPlugin(plugin)].canSpendNativeToken = true;
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length;) {
            _setExecutionFunction(manifest.executionFunctions[i], plugin);

            unchecked {
                ++i;
            }
        }

        // Add installed plugin and selectors this plugin can call
        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length;) {
            // If there are duplicates, this will just enable the flag again. This is not a problem, since the
            // boolean will be set to false twice during uninstall, which is fine.
            _storage.callPermitted[getPermittedCallKey(plugin, manifest.permittedExecutionSelectors[i])] = true;

            unchecked {
                ++i;
            }
        }

        // Add the permitted external calls to the account.
        if (manifest.permitAnyExternalAddress) {
            _storage.pluginData[IPlugin(plugin)].anyExternalExecPermitted = true;
        } else {
            // Only store the specific permitted external calls if "permit any" flag was not set.
            length = manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length;) {
                ManifestExternalCallPermission memory externalCallPermission = manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    _storage.permittedExternalCalls[IPlugin(plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = true;

                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = true;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength;) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = true;

                        unchecked {
                            ++j;
                        }
                    }
                }

                unchecked {
                    ++i;
                }
            }
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length;) {
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

            unchecked {
                ++i;
            }
        }

        // Hooks are not allowed to be provided as dependencies, so we use an empty array for resolving them.
        address[] memory emptyDependencies;

        length = manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mh = manifest.preUserOpValidationHooks[i];
            _addPreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mh = manifest.preRuntimeValidationHooks[i];
            _addPreRuntimeValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );
            unchecked {
                ++i;
            }
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            _addExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook, plugin, emptyDependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, emptyDependencies, ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length;) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] += 1;
            unchecked {
                ++i;
            }
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
        bytes32 manifestHash = _storage.pluginData[IPlugin(plugin)].manifestHash;
        if (!_isValidPluginManifest(manifest, manifestHash)) {
            revert InvalidPluginManifest();
        }

        // Ensure that there are no dependent plugins.
        if (_storage.pluginData[IPlugin(plugin)].dependentCount != 0) {
            revert PluginDependencyViolation(plugin);
        }

        // Remove this plugin as a dependent from its dependencies.
        address[] memory dependencies = _storage.pluginData[IPlugin(plugin)].dependencies;
        uint256 length = dependencies.length;
        for (uint256 i = 0; i < length;) {
            address dependency = dependencies[i];

            // Decrement the dependent count for the dependency function.
            _storage.pluginData[IPlugin(dependency)].dependentCount -= 1;

            unchecked {
                ++i;
            }
        }

        // Remove components according to the manifest, in reverse order (by component type) of their installation.

        // Hooks are not allowed to be provided as dependencies, so we use an empty array for resolving them.
        address[] memory emptyDependencies;

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            _removeExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook, plugin, emptyDependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, emptyDependencies, ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.preRuntimeValidationHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mh = manifest.preRuntimeValidationHooks[i];
            _removePreRuntimeValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mh = manifest.preUserOpValidationHooks[i];
            _removePreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    emptyDependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.validationFunctions.length;
        for (uint256 i = 0; i < length;) {
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

            unchecked {
                ++i;
            }
        }

        // remove external call permissions

        if (manifest.permitAnyExternalAddress) {
            // Only clear if it was set during install time
            _storage.pluginData[IPlugin(plugin)].anyExternalExecPermitted = false;
        } else {
            // Only clear the specific permitted external calls if "permit any" flag was not set.
            length = manifest.permittedExternalCalls.length;
            for (uint256 i = 0; i < length;) {
                ManifestExternalCallPermission memory externalCallPermission = manifest.permittedExternalCalls[i];

                PermittedExternalCallData storage permittedExternalCallData =
                    _storage.permittedExternalCalls[IPlugin(plugin)][externalCallPermission.externalAddress];

                permittedExternalCallData.addressPermitted = false;

                // Only clear this flag if it was set in the constructor.
                if (externalCallPermission.permitAnySelector) {
                    permittedExternalCallData.anySelectorPermitted = false;
                } else {
                    uint256 externalContractSelectorsLength = externalCallPermission.selectors.length;
                    for (uint256 j = 0; j < externalContractSelectorsLength;) {
                        permittedExternalCallData.permittedSelectors[externalCallPermission.selectors[j]] = false;

                        unchecked {
                            ++j;
                        }
                    }
                }

                unchecked {
                    ++i;
                }
            }
        }

        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length;) {
            _storage.callPermitted[getPermittedCallKey(plugin, manifest.permittedExecutionSelectors[i])] = false;

            unchecked {
                ++i;
            }
        }

        length = manifest.executionFunctions.length;
        for (uint256 i = 0; i < length;) {
            _removeExecutionFunction(manifest.executionFunctions[i]);

            unchecked {
                ++i;
            }
        }

        length = manifest.interfaceIds.length;
        for (uint256 i = 0; i < length;) {
            _storage.supportedIfaces[manifest.interfaceIds[i]] -= 1;
            unchecked {
                ++i;
            }
        }

        // Remove the plugin metadata from the account.
        delete _storage.pluginData[IPlugin(plugin)];

        // Clear the plugin storage for the account.
        bool onUninstallSuccess = true;
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onUninstall(uninstallData) {}
        catch {
            onUninstallSuccess = false;
        }

        emit PluginUninstalled(plugin, onUninstallSuccess);
    }

    function _addOrIncrement(EnumerableMap.Bytes32ToUintMap storage map, bytes32 key) internal {
        (bool success, uint256 value) = map.tryGet(key);
        map.set(key, success ? value + 1 : 0);
    }

    /// @return True if the key was removed or its value was decremented, false if the key was not found.
    function _removeOrDecrement(EnumerableMap.Bytes32ToUintMap storage map, bytes32 key) internal returns (bool) {
        (bool success, uint256 value) = map.tryGet(key);
        if (!success) {
            return false;
        }
        if (value == 0) {
            map.remove(key);
        } else {
            map.set(key, value - 1);
        }
        return true;
    }

    function _toSetValue(IPlugin plugin) internal pure returns (bytes32) {
        return bytes32(bytes20(address(plugin)));
    }

    function _toFunctionReference(bytes32 setValue) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes21(setValue));
    }

    function _isEmptyOrMagicValue(IPlugin plugin) internal pure returns (bool) {
        return address(plugin) <= address(2);
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
        address[] memory dependencies,
        // Indicates which magic value, if any, is permissible for the function to resolve.
        ManifestAssociatedFunctionType allowedMagicValue
    ) internal pure returns (IPlugin) {
        if (manifestFunction.functionType == ManifestAssociatedFunctionType.SELF) {
            return IPlugin(plugin);
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.DEPENDENCY) {
            if (manifestFunction.dependencyIndex >= dependencies.length) {
                revert InvalidPluginManifest();
            }
            return IPlugin(dependencies[manifestFunction.dependencyIndex]);
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW)
        {
            if (allowedMagicValue == ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW) {
                return _RUNTIME_VALIDATION_ALWAYS_ALLOW;
            } else {
                revert InvalidPluginManifest();
            }
        } else if (manifestFunction.functionType == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
            if (allowedMagicValue == ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY) {
                return _PRE_HOOK_ALWAYS_DENY;
            } else {
                revert InvalidPluginManifest();
            }
        }
        return IPlugin(address(0)); // Empty checks are done elsewhere
    }
}
