// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {AccountStorage, getAccountStorage, toAddressArray, toPlugin, SelectorData} from "./AccountStorage.sol";

abstract contract AccountLoupe is IAccountLoupe {
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;
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

        config.validationPlugin = address(_storage.selectorData[selector].validation);
    }

    /// @inheritdoc IAccountLoupe
    function getExecutionHooks(bytes4 selector) external view returns (ExecutionHooks[] memory execHooks) {
        SelectorData storage selectorData = getAccountStorage().selectorData[selector];
        uint256 preExecHooksLength = selectorData.preHooks.length();
        uint256 postOnlyExecHooksLength = selectorData.postOnlyHooks.length();
        uint256 maxExecHooksLength = postOnlyExecHooksLength;

        // There can only be as many associated post hooks to run as there are pre hooks.
        for (uint256 i = 0; i < preExecHooksLength;) {
            (, uint256 count) = selectorData.preHooks.at(i);
            unchecked {
                maxExecHooksLength += (count + 1);
                ++i;
            }
        }

        // Overallocate on length - not all of this may get filled up. We set the correct length later.
        execHooks = new ExecutionHooks[](maxExecHooksLength);
        uint256 actualExecHooksLength;

        for (uint256 i = 0; i < preExecHooksLength;) {
            (bytes32 key,) = selectorData.preHooks.at(i);
            IPlugin preExecHookPlugin = toPlugin(key);

            uint256 associatedPostExecHooksLength = selectorData.associatedPostHooks[preExecHookPlugin].length();
            if (associatedPostExecHooksLength > 0) {
                for (uint256 j = 0; j < associatedPostExecHooksLength;) {
                    execHooks[actualExecHooksLength].preExecHookPlugin = address(preExecHookPlugin);
                    (key,) = selectorData.associatedPostHooks[preExecHookPlugin].at(j);
                    execHooks[actualExecHooksLength].postExecHookPlugin = address(toPlugin(key));

                    unchecked {
                        ++actualExecHooksLength;
                        ++j;
                    }
                }
            } else {
                execHooks[actualExecHooksLength].preExecHookPlugin = address(preExecHookPlugin);

                unchecked {
                    ++actualExecHooksLength;
                }
            }

            unchecked {
                ++i;
            }
        }

        for (uint256 i = 0; i < postOnlyExecHooksLength;) {
            (bytes32 key,) = selectorData.postOnlyHooks.at(i);
            execHooks[actualExecHooksLength].postExecHookPlugin = address(toPlugin(key));

            unchecked {
                ++actualExecHooksLength;
                ++i;
            }
        }

        // Trim the exec hooks array to the actual length, since we may have overallocated.
        assembly ("memory-safe") {
            mstore(execHooks, actualExecHooksLength)
        }
    }

    /// @inheritdoc IAccountLoupe
    function getPreValidationHooks(bytes4 selector)
        external
        view
        returns (
            address[] memory preUserOpValidationHooks,
            address[] memory preRuntimeValidationHooks
        )
    {
        preUserOpValidationHooks =
            toAddressArray(getAccountStorage().selectorData[selector].preUserOpValidationHooks);
        preRuntimeValidationHooks =
            toAddressArray(getAccountStorage().selectorData[selector].preRuntimeValidationHooks);
    }

    /// @inheritdoc IAccountLoupe
    function getInstalledPlugins() external view returns (address[] memory pluginAddresses) {
        pluginAddresses = getAccountStorage().plugins.values();
    }
}
