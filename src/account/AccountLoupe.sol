// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {FunctionReference, IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {AccountStorage, getAccountStorage, SelectorData, toFunctionReferenceArray} from "./AccountStorage.sol";

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
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory execHooks) {
        SelectorData storage selectorData = getAccountStorage().selectorData[selector];
        uint256 preExecHooksLength = selectorData.preHooks.length();
        uint256 postOnlyExecHooksLength = selectorData.postOnlyHooks.length();

        execHooks = new ExecutionHooks[](preExecHooksLength + postOnlyExecHooksLength);

        for (uint256 i = 0; i < preExecHooksLength; ++i) {
            bytes32 key = selectorData.preHooks.at(i);
            FunctionReference preExecHook = FunctionReference.wrap(bytes21(key));
            FunctionReference associatedPostExecHook = selectorData.associatedPostHooks[preExecHook];

            execHooks[i].preExecHook = preExecHook;
            execHooks[i].postExecHook = associatedPostExecHook;
        }

        for (uint256 i = 0; i < postOnlyExecHooksLength; ++i) {
            bytes32 key = selectorData.postOnlyHooks.at(i);
            execHooks[preExecHooksLength + i].postExecHook = FunctionReference.wrap(bytes21(key));
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
