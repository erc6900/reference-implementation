// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {
    AccountStorage,
    getAccountStorage,
    SelectorData,
    PermittedCallData,
    getPermittedCallKey,
    HookGroup,
    PermittedExternalCallData,
    StoredInjectedHook
} from "../libraries/AccountStorage.sol";
import {FunctionReference, FunctionReferenceLib} from "../libraries/FunctionReferenceLib.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {
    IPlugin,
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExternalCallPermission,
    PluginManifest
} from "../interfaces/IPlugin.sol";

abstract contract PluginManagerInternals is IPluginManager {
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;
    using EnumerableSet for EnumerableSet.AddressSet;

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
    error RuntimeValidationFunctionAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error UserOpValidationFunctionAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error PluginApplyHookCallbackFailed(address providingPlugin, bytes revertReason);
    error PluginUnapplyHookCallbackFailed(address providingPlugin, bytes revertReason);

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

    function _addUserOpValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (!_selectorData.userOpValidation.isEmpty()) {
            revert UserOpValidationFunctionAlreadySet(selector, validationFunction);
        }

        _selectorData.userOpValidation = validationFunction;
    }

    function _removeUserOpValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.userOpValidation = FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE;
    }

    function _addRuntimeValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        if (!_selectorData.runtimeValidation.isEmpty()) {
            revert RuntimeValidationFunctionAlreadySet(selector, validationFunction);
        }

        _selectorData.runtimeValidation = validationFunction;
    }

    function _removeRuntimeValidationFunction(bytes4 selector, FunctionReference validationFunction)
        internal
        notNullFunction(validationFunction)
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _selectorData.runtimeValidation = FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE;
    }

    function _addExecHooks(bytes4 selector, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _addHooks(_selectorData.executionHooks, preExecHook, postExecHook);
    }

    function _removeExecHooks(bytes4 selector, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        SelectorData storage _selectorData = getAccountStorage().selectorData[selector];

        _removeHooks(_selectorData.executionHooks, preExecHook, postExecHook);
    }

    function _enableExecFromPlugin(bytes4 selector, address plugin, AccountStorage storage accountStorage)
        internal
    {
        bytes24 key = getPermittedCallKey(plugin, selector);

        // If there are duplicates, this will just enable the flag again. This is not a problem, since the boolean
        // will be set to false twice during uninstall, which is fine.
        accountStorage.permittedCalls[key].callPermitted = true;
    }

    function _disableExecFromPlugin(bytes4 selector, address plugin, AccountStorage storage accountStorage)
        internal
    {
        bytes24 key = getPermittedCallKey(plugin, selector);
        accountStorage.permittedCalls[key].callPermitted = false;
    }

    function _addPermittedCallHooks(
        bytes4 selector,
        address plugin,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal notNullPlugin(plugin) {
        bytes24 permittedCallKey = getPermittedCallKey(plugin, selector);
        PermittedCallData storage _permittedCalldata = getAccountStorage().permittedCalls[permittedCallKey];

        _addHooks(_permittedCalldata.permittedCallHooks, preExecHook, postExecHook);
    }

    function _removePermittedCallHooks(
        bytes4 selector,
        address plugin,
        FunctionReference preExecHook,
        FunctionReference postExecHook
    ) internal notNullPlugin(plugin) {
        bytes24 permittedCallKey = getPermittedCallKey(plugin, selector);
        PermittedCallData storage _permittedCallData = getAccountStorage().permittedCalls[permittedCallKey];

        _removeHooks(_permittedCallData.permittedCallHooks, preExecHook, postExecHook);
    }

    function _addHooks(HookGroup storage hooks, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        if (!preExecHook.isEmpty()) {
            _addOrIncrement(hooks.preHooks, _toSetValue(preExecHook));

            if (!postExecHook.isEmpty()) {
                _addOrIncrement(hooks.associatedPostHooks[preExecHook], _toSetValue(postExecHook));
            }
        } else {
            if (postExecHook.isEmpty()) {
                // both pre and post hooks cannot be null
                revert NullFunctionReference();
            }

            _addOrIncrement(hooks.postOnlyHooks, _toSetValue(postExecHook));
        }
    }

    function _removeHooks(HookGroup storage hooks, FunctionReference preExecHook, FunctionReference postExecHook)
        internal
    {
        if (!preExecHook.isEmpty()) {
            _removeOrDecrement(hooks.preHooks, _toSetValue(preExecHook));

            if (!postExecHook.isEmpty()) {
                _removeOrDecrement(hooks.associatedPostHooks[preExecHook], _toSetValue(postExecHook));
            }
        } else {
            // The case where both pre and post hooks are null was checked during installation.

            // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
            _removeOrDecrement(hooks.postOnlyHooks, _toSetValue(postExecHook));
        }
    }

    function _addPreUserOpValidationHook(bytes4 selector, FunctionReference preUserOpValidationHook)
        internal
        notNullFunction(preUserOpValidationHook)
    {
        _addOrIncrement(
            getAccountStorage().selectorData[selector].preUserOpValidationHooks,
            _toSetValue(preUserOpValidationHook)
        );
    }

    function _removePreUserOpValidationHook(bytes4 selector, FunctionReference preUserOpValidationHook)
        internal
        notNullFunction(preUserOpValidationHook)
    {
        // May ignore return value, as the manifest hash is validated to ensure that the hook exists.
        _removeOrDecrement(
            getAccountStorage().selectorData[selector].preUserOpValidationHooks,
            _toSetValue(preUserOpValidationHook)
        );
    }

    function _addPreRuntimeValidationHook(bytes4 selector, FunctionReference preRuntimeValidationHook)
        internal
        notNullFunction(preRuntimeValidationHook)
    {
        _addOrIncrement(
            getAccountStorage().selectorData[selector].preRuntimeValidationHooks,
            _toSetValue(preRuntimeValidationHook)
        );
    }

    function _removePreRuntimeValidationHook(bytes4 selector, FunctionReference preRuntimeValidationHook)
        internal
        notNullFunction(preRuntimeValidationHook)
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
        bytes memory pluginInitData,
        FunctionReference[] memory dependencies,
        InjectedHook[] memory injectedHooks
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

            unchecked {
                ++i;
            }
        }

        // Add the plugin metadata to the account
        _storage.pluginData[plugin].manifestHash = manifestHash;
        _storage.pluginData[plugin].dependencies = dependencies;

        // Update components according to the manifest.
        // All conflicts should revert.

        // Mark whether or not this plugin may spend native token amounts
        if (manifest.canSpendNativeToken) {
            _storage.pluginData[plugin].canSpendNativeToken = true;
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
            _enableExecFromPlugin(manifest.permittedExecutionSelectors[i], plugin, _storage);

            unchecked {
                ++i;
            }
        }

        // Add the permitted external calls to the account.
        if (manifest.permitAnyExternalAddress) {
            _storage.pluginData[plugin].anyExternalExecPermitted = true;
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

        length = injectedHooks.length;
        // manually set arr length
        StoredInjectedHook[] storage optionalHooksLengthArr = _storage.pluginData[plugin].injectedHooks;
        assembly ("memory-safe") {
            sstore(optionalHooksLengthArr.slot, length)
        }

        for (uint256 i = 0; i < length;) {
            InjectedHook memory hook = injectedHooks[i];
            _storage.pluginData[plugin].injectedHooks[i] = StoredInjectedHook({
                providingPlugin: hook.providingPlugin,
                selector: hook.selector,
                preExecHookFunctionId: hook.injectedHooksInfo.preExecHookFunctionId,
                isPostHookUsed: hook.injectedHooksInfo.isPostHookUsed,
                postExecHookFunctionId: hook.injectedHooksInfo.postExecHookFunctionId
            });

            // Increment the dependent count for the plugin providing the hook.
            _storage.pluginData[hook.providingPlugin].dependentCount += 1;

            if (!_storage.plugins.contains(hook.providingPlugin)) {
                revert MissingPluginDependency(hook.providingPlugin);
            }

            _addPermittedCallHooks(
                hook.selector,
                plugin,
                FunctionReferenceLib.pack(hook.providingPlugin, hook.injectedHooksInfo.preExecHookFunctionId),
                hook.injectedHooksInfo.isPostHookUsed
                    ? FunctionReferenceLib.pack(hook.providingPlugin, hook.injectedHooksInfo.postExecHookFunctionId)
                    : FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mv = manifest.userOpValidationFunctions[i];
            _addUserOpValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction, plugin, dependencies, ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mv = manifest.runtimeValidationFunctions[i];
            _addRuntimeValidationFunction(
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

        length = manifest.preUserOpValidationHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mh = manifest.preUserOpValidationHooks[i];
            _addPreUserOpValidationHook(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.associatedFunction,
                    plugin,
                    dependencies,
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
                    dependencies,
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
                    mh.preExecHook, plugin, dependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, dependencies, ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.permittedCallHooks.length;
        for (uint256 i = 0; i < length;) {
            _addPermittedCallHooks(
                manifest.permittedCallHooks[i].executionSelector,
                plugin,
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].preExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].postExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.NONE
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

        // call onHookApply after all setup, but before calling plugin onInstall
        length = injectedHooks.length;

        for (uint256 i = 0; i < length;) {
            InjectedHook memory hook = injectedHooks[i];
            // not inlined in function call to avoid stack too deep error
            bytes memory onHookApplyData = injectedHooks[i].hookApplyData;
            /* solhint-disable no-empty-blocks */
            try IPlugin(hook.providingPlugin).onHookApply(plugin, hook.injectedHooksInfo, onHookApplyData) {}
            catch (bytes memory revertReason) {
                revert PluginApplyHookCallbackFailed(hook.providingPlugin, revertReason);
            }
            /* solhint-enable no-empty-blocks */
            unchecked {
                ++i;
            }
        }

        // Initialize the plugin storage for the account.
        // solhint-disable-next-line no-empty-blocks
        try IPlugin(plugin).onInstall(pluginInitData) {}
        catch (bytes memory revertReason) {
            revert PluginInstallCallbackFailed(plugin, revertReason);
        }

        emit PluginInstalled(plugin, manifestHash, dependencies, injectedHooks);
    }

    function _uninstallPlugin(
        address plugin,
        PluginManifest memory manifest,
        bytes memory uninstallData,
        bytes[] calldata hookUnapplyData
    ) internal {
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
        for (uint256 i = 0; i < length;) {
            FunctionReference dependency = dependencies[i];
            (address dependencyAddr,) = dependency.unpack();

            // Decrement the dependent count for the dependency function.
            _storage.pluginData[dependencyAddr].dependentCount -= 1;

            unchecked {
                ++i;
            }
        }

        // Remove components according to the manifest, in reverse order (by component type) of their installation.
        // If any expected components are missing, revert.

        length = manifest.permittedCallHooks.length;
        for (uint256 i = 0; i < length;) {
            _removePermittedCallHooks(
                manifest.permittedCallHooks[i].executionSelector,
                plugin,
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].preExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    manifest.permittedCallHooks[i].postExecHook,
                    plugin,
                    dependencies,
                    ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.executionHooks.length;
        for (uint256 i = 0; i < length;) {
            ManifestExecutionHook memory mh = manifest.executionHooks[i];
            _removeExecHooks(
                mh.executionSelector,
                _resolveManifestFunction(
                    mh.preExecHook, plugin, dependencies, ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                ),
                _resolveManifestFunction(
                    mh.postExecHook, plugin, dependencies, ManifestAssociatedFunctionType.NONE
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
                    dependencies,
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
                    dependencies,
                    ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY
                )
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.runtimeValidationFunctions.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mv = manifest.runtimeValidationFunctions[i];
            _removeRuntimeValidationFunction(
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

        length = manifest.userOpValidationFunctions.length;
        for (uint256 i = 0; i < length;) {
            ManifestAssociatedFunction memory mv = manifest.userOpValidationFunctions[i];
            _removeUserOpValidationFunction(
                mv.executionSelector,
                _resolveManifestFunction(
                    mv.associatedFunction, plugin, dependencies, ManifestAssociatedFunctionType.NONE
                )
            );

            unchecked {
                ++i;
            }
        }

        // remove external call permissions

        if (manifest.permitAnyExternalAddress) {
            // Only clear if it was set during install time
            _storage.pluginData[plugin].anyExternalExecPermitted = false;
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

        length = _storage.pluginData[plugin].injectedHooks.length;
        for (uint256 i = 0; i < length;) {
            StoredInjectedHook memory hook = _storage.pluginData[plugin].injectedHooks[i];

            // Decrement the dependent count for the plugin providing the hook.
            _storage.pluginData[hook.providingPlugin].dependentCount -= 1;

            _removePermittedCallHooks(
                hook.selector,
                plugin,
                FunctionReferenceLib.pack(hook.providingPlugin, hook.preExecHookFunctionId),
                hook.isPostHookUsed
                    ? FunctionReferenceLib.pack(hook.providingPlugin, hook.postExecHookFunctionId)
                    : FunctionReferenceLib._EMPTY_FUNCTION_REFERENCE
            );

            unchecked {
                ++i;
            }
        }

        length = manifest.permittedExecutionSelectors.length;
        for (uint256 i = 0; i < length;) {
            _disableExecFromPlugin(manifest.permittedExecutionSelectors[i], plugin, _storage);

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

        length = _storage.pluginData[plugin].injectedHooks.length;
        bool hasUnapplyHookData = hookUnapplyData.length != 0;
        if (hasUnapplyHookData && hookUnapplyData.length != length) {
            revert ArrayLengthMismatch();
        }

        for (uint256 i = 0; i < length;) {
            StoredInjectedHook memory hook = _storage.pluginData[plugin].injectedHooks[i];

            /* solhint-disable no-empty-blocks */
            try IPlugin(hook.providingPlugin).onHookUnapply(
                plugin,
                InjectedHooksInfo({
                    preExecHookFunctionId: hook.preExecHookFunctionId,
                    isPostHookUsed: hook.isPostHookUsed,
                    postExecHookFunctionId: hook.postExecHookFunctionId
                }),
                hasUnapplyHookData ? hookUnapplyData[i] : bytes("")
            ) {} catch (bytes memory revertReason) {
                revert PluginUnapplyHookCallbackFailed(hook.providingPlugin, revertReason);
            }
            /* solhint-enable no-empty-blocks */

            unchecked {
                ++i;
            }
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

    function _toSetValue(FunctionReference functionReference) internal pure returns (bytes32) {
        return bytes32(FunctionReference.unwrap(functionReference));
    }

    function _toFunctionReference(bytes32 setValue) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes21(setValue));
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
