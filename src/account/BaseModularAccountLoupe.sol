// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPluginLoupe} from "../interfaces/IPluginLoupe.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {
    AccountStorage,
    getAccountStorage,
    getPermittedCallKey,
    toFunctionReferenceArray
} from "../libraries/AccountStorage.sol";
import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";

abstract contract BaseModularAccountLoupe is IPluginLoupe {
    using EnumerableSet for EnumerableSet.AddressSet;

    error ManifestDiscrepancy(address plugin);

    /// @notice Gets the validator and plugin configuration for a selector
    /// @param selector The selector to get the configuration for
    /// @return config The configuration for this selector
    function getExecutionFunctionConfig(bytes4 selector)
        external
        view
        returns (ExecutionFunctionConfig memory config)
    {
        AccountStorage storage _storage = getAccountStorage();

        if (
            selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
                || selector == UUPSUpgradeable.upgradeTo.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IPluginManager.installPlugin.selector
                || selector == IPluginManager.uninstallPlugin.selector
        ) {
            config.plugin = address(this);
        } else {
            config.plugin = _storage.selectorData[selector].plugin;
        }

        config.userOpValidationFunction = _storage.selectorData[selector].userOpValidation;

        config.runtimeValidationFunction = _storage.selectorData[selector].runtimeValidation;
    }

    /// @notice Gets the pre and post execution hooks for a selector
    /// @param selector The selector to get the hooks for
    /// @return execHooks The pre and post execution hooks for this selector
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory execHooks) {
        AccountStorage storage _storage = getAccountStorage();

        FunctionReference[] memory preExecHooks =
            toFunctionReferenceArray(_storage.selectorData[selector].preExecHooks);

        uint256 numHooks = preExecHooks.length;
        execHooks = new ExecutionHooks[](numHooks);

        for (uint256 i = 0; i < numHooks;) {
            execHooks[i].preExecHook = preExecHooks[i];
            execHooks[i].postExecHook = _storage.selectorData[selector].associatedPostExecHooks[preExecHooks[i]];

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Gets the pre and post permitted call hooks applied for a plugin calling this selector
    /// @param callingPlugin The plugin that is calling the selector
    /// @param selector The selector the plugin is calling
    /// @return execHooks The pre and post permitted call hooks for this selector
    function getPermittedCallHooks(address callingPlugin, bytes4 selector)
        external
        view
        returns (ExecutionHooks[] memory execHooks)
    {
        AccountStorage storage _storage = getAccountStorage();

        bytes24 key = getPermittedCallKey(callingPlugin, selector);

        FunctionReference[] memory prePermittedCallHooks =
            toFunctionReferenceArray(_storage.permittedCalls[key].prePermittedCallHooks);

        uint256 numHooks = prePermittedCallHooks.length;
        execHooks = new ExecutionHooks[](numHooks);

        for (uint256 i = 0; i < numHooks;) {
            execHooks[i].preExecHook = prePermittedCallHooks[i];
            execHooks[i].postExecHook =
                _storage.permittedCalls[key].associatedPostPermittedCallHooks[prePermittedCallHooks[i]];

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Gets the pre user op validation hooks associated with a selector
    /// @param selector The selector to get the hooks for
    /// @return preValidationHooks The pre user op validation hooks for this selector
    function getPreUserOpValidationHooks(bytes4 selector)
        external
        view
        returns (FunctionReference[] memory preValidationHooks)
    {
        preValidationHooks =
            toFunctionReferenceArray(getAccountStorage().selectorData[selector].preUserOpValidationHooks);
    }

    /// @notice Gets the pre runtime validation hooks associated with a selector
    /// @param selector The selector to get the hooks for
    /// @return preValidationHooks The pre runtime validation hooks for this selector
    function getPreRuntimeValidationHooks(bytes4 selector)
        external
        view
        returns (FunctionReference[] memory preValidationHooks)
    {
        preValidationHooks =
            toFunctionReferenceArray(getAccountStorage().selectorData[selector].preRuntimeValidationHooks);
    }

    /// @notice Gets an array of all installed plugins
    /// @return pluginAddresses The addresses of all installed plugins
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        pluginAddresses = getAccountStorage().plugins.values();
    }
}
