// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {
    AccountStorage,
    getAccountStorage,
    getPermittedCallKey,
    toFunctionReferenceArray
} from "../libraries/AccountStorage.sol";
import {FunctionReference} from "../libraries/FunctionReferenceLib.sol";

abstract contract AccountLoupe is IAccountLoupe {
    using EnumerableSet for EnumerableSet.AddressSet;

    error ManifestDiscrepancy(address plugin);

    /// @inheritdoc IAccountLoupe
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

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory execHooks) {
        AccountStorage storage _storage = getAccountStorage();

        FunctionReference[] memory preExecHooks =
            toFunctionReferenceArray(_storage.selectorData[selector].executionHooks.preHooks);

        uint256 numHooks = preExecHooks.length;
        execHooks = new ExecutionHooks[](numHooks);

        for (uint256 i = 0; i < numHooks;) {
            execHooks[i].preExecHook = preExecHooks[i];
            execHooks[i].postExecHook =
                _storage.selectorData[selector].executionHooks.associatedPostHooks[preExecHooks[i]];

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPermittedCallHooks(address callingPlugin, bytes4 selector)
        external
        view
        returns (ExecutionHooks[] memory execHooks)
    {
        AccountStorage storage _storage = getAccountStorage();

        bytes24 key = getPermittedCallKey(callingPlugin, selector);

        FunctionReference[] memory prePermittedCallHooks =
            toFunctionReferenceArray(_storage.permittedCalls[key].permittedCallHooks.preHooks);

        uint256 numHooks = prePermittedCallHooks.length;
        execHooks = new ExecutionHooks[](numHooks);

        for (uint256 i = 0; i < numHooks;) {
            execHooks[i].preExecHook = prePermittedCallHooks[i];
            execHooks[i].postExecHook =
                _storage.permittedCalls[key].permittedCallHooks.associatedPostHooks[prePermittedCallHooks[i]];

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            FunctionReference[] memory preUserOpValidationHooks,
            FunctionReference[] memory preRuntimeValidationHooks
        )
    {
        preUserOpValidationHooks =
            toFunctionReferenceArray(getAccountStorage().selectorData[selector].preUserOpValidationHooks);
        preRuntimeValidationHooks =
            toFunctionReferenceArray(getAccountStorage().selectorData[selector].preRuntimeValidationHooks);
    }

    /// @inheritdoc IAccountLoupe
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        pluginAddresses = getAccountStorage().plugins.values();
    }
}
