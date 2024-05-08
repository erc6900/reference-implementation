// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAccountLoupe, ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {
    AccountStorage,
    getAccountStorage,
    SelectorData,
    toFunctionReferenceArray,
    toExecutionHook
} from "./AccountStorage.sol";

abstract contract AccountLoupe is IAccountLoupe {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @inheritdoc IAccountLoupe
    function getExecutionFunctionConfig(bytes4 selector)
        external
        view
        returns (ExecutionFunctionConfig memory config)
    {
        AccountStorage storage _storage = getAccountStorage();

        if (
            selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IPluginManager.installPlugin.selector
                || selector == IPluginManager.uninstallPlugin.selector
        ) {
            config.plugin = address(this);
        } else {
            config.plugin = _storage.selectorData[selector].plugin;
        }

        config.validationFunction = _storage.selectorData[selector].validation;
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHook[] memory execHooks) {
        SelectorData storage selectorData = getAccountStorage().selectorData[selector];
        uint256 executionHooksLength = selectorData.executionHooks.length();

        execHooks = new ExecutionHook[](executionHooksLength);

        for (uint256 i = 0; i < executionHooksLength; ++i) {
            bytes32 key = selectorData.executionHooks.at(i);
            ExecutionHook memory execHook = execHooks[i];
            (execHook.hookFunction, execHook.isPreHook, execHook.isPostHook) = toExecutionHook(key);
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (FunctionReference[] memory preValidationHooks)
    {
        preValidationHooks =
            toFunctionReferenceArray(getAccountStorage().selectorData[selector].preValidationHooks);
    }

    /// @inheritdoc IAccountLoupe
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        pluginAddresses = getAccountStorage().plugins.values();
    }
}
