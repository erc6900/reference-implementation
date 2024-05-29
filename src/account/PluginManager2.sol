// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";
import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {AccountStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";

abstract contract PluginManager2 {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error DefaultValidationAlreadySet(address plugin, uint8 functionId);
    error ValidationAlreadySet(bytes4 selector, address plugin, uint8 functionId);
    error ValidationNotSet(bytes4 selector, address plugin, uint8 functionId);

    function _installValidation(
        address plugin,
        uint8 functionId,
        bool shared,
        bytes4[] memory selectors,
        bytes calldata installData
    ) internal {
        FunctionReference validationFunction = FunctionReferenceLib.pack(plugin, functionId);

        AccountStorage storage _storage = getAccountStorage();

        if (shared) {
            if (!_storage.defaultValidations.add(toSetValue(validationFunction))) {
                revert DefaultValidationAlreadySet(plugin, functionId);
            }
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.selectorData[selector].validations.add(toSetValue(validationFunction))) {
                revert ValidationAlreadySet(selector, plugin, functionId);
            }
        }

        IPlugin(plugin).onInstall(installData);
    }

    function _uninstallValidation(
        address plugin,
        uint8 functionId,
        bytes4[] calldata selectors,
        bytes calldata uninstallData
    ) internal {
        FunctionReference validationFunction = FunctionReferenceLib.pack(plugin, functionId);

        AccountStorage storage _storage = getAccountStorage();

        // Ignore return value - remove if present, do nothing otherwise.
        _storage.defaultValidations.remove(toSetValue(validationFunction));

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.selectorData[selector].validations.remove(toSetValue(validationFunction))) {
                revert ValidationNotSet(selector, plugin, functionId);
            }
        }

        IPlugin(plugin).onUninstall(uninstallData);
    }
}
