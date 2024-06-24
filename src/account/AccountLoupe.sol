// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAccountLoupe, ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {getAccountStorage, toExecutionHook, toSelector} from "./AccountStorage.sol";

abstract contract AccountLoupe is IAccountLoupe {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @inheritdoc IAccountLoupe
    function getExecutionFunctionHandler(bytes4 selector) external view override returns (address plugin) {
        if (
            selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IPluginManager.installPlugin.selector
                || selector == IPluginManager.uninstallPlugin.selector
        ) {
            return address(this);
        }

        return getAccountStorage().selectorData[selector].plugin;
    }

    /// @inheritdoc IAccountLoupe
    function getSelectors(FunctionReference validationFunction) external view returns (bytes4[] memory) {
        uint256 length = getAccountStorage().validationData[validationFunction].selectors.length();

        bytes4[] memory selectors = new bytes4[](length);

        for (uint256 i = 0; i < length; ++i) {
            selectors[i] = toSelector(getAccountStorage().validationData[validationFunction].selectors.at(i));
        }

        return selectors;
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector)
        external
        view
        override
        returns (ExecutionHook[] memory execHooks)
    {
        EnumerableSet.Bytes32Set storage hooks = getAccountStorage().selectorData[selector].executionHooks;
        uint256 executionHooksLength = hooks.length();

        execHooks = new ExecutionHook[](executionHooksLength);

        for (uint256 i = 0; i < executionHooksLength; ++i) {
            bytes32 key = hooks.at(i);
            ExecutionHook memory execHook = execHooks[i];
            (execHook.hookFunction, execHook.isPreHook, execHook.isPostHook) = toExecutionHook(key);
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPermissionHooks(FunctionReference validationFunction)
        external
        view
        override
        returns (ExecutionHook[] memory permissionHooks)
    {
        EnumerableSet.Bytes32Set storage hooks =
            getAccountStorage().validationData[validationFunction].permissionHooks;
        uint256 executionHooksLength = hooks.length();
        permissionHooks = new ExecutionHook[](executionHooksLength);
        for (uint256 i = 0; i < executionHooksLength; ++i) {
            bytes32 key = hooks.at(i);
            ExecutionHook memory execHook = permissionHooks[i];
            (execHook.hookFunction, execHook.isPreHook, execHook.isPostHook) = toExecutionHook(key);
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(FunctionReference validationFunction)
        external
        view
        override
        returns (FunctionReference[] memory preValidationHooks)
    {
        preValidationHooks = getAccountStorage().validationData[validationFunction].preValidationHooks;
    }

    /// @inheritdoc IAccountLoupe
    function getInstalledPlugins() external view override returns (address[] memory pluginAddresses) {
        pluginAddresses = getAccountStorage().plugins.values();
    }
}
