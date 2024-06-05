// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";
import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {AccountStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";

// Temporary additional functions for a user-controlled install flow for validation functions.
abstract contract PluginManager2 {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    error DefaultValidationAlreadySet(FunctionReference validationFunction);
    error ValidationAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error PreValidationAlreadySet(FunctionReference validationFunction, FunctionReference preValidationFunction);
    error ValidationNotSet(bytes4 selector, FunctionReference validationFunction);

    function _installValidation(
        FunctionReference validationFunction,
        bool isDefault,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks
    )
        // TODO: flag for signature validation
        internal
    {
        AccountStorage storage _storage = getAccountStorage();

        if (preValidationHooks.length > 0) {
            (FunctionReference[] memory preValidationFunctions, bytes[] memory initDatas) =
                abi.decode(preValidationHooks, (FunctionReference[], bytes[]));

            for (uint256 i = 0; i < preValidationFunctions.length; ++i) {
                FunctionReference preValidationFunction = preValidationFunctions[i];

                _storage.validationData[validationFunction].preValidationHooks.push(preValidationFunction);

                if (initDatas[i].length > 0) {
                    (address preValidationPlugin,) = FunctionReferenceLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onInstall(initDatas[i]);
                }
            }
        }

        if (isDefault) {
            if (_storage.validationData[validationFunction].isDefault) {
                revert DefaultValidationAlreadySet(validationFunction);
            }
            _storage.validationData[validationFunction].isDefault = true;
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.selectorData[selector].validations.add(toSetValue(validationFunction))) {
                revert ValidationAlreadySet(selector, validationFunction);
            }
        }

        if (installData.length > 0) {
            (address plugin,) = FunctionReferenceLib.unpack(validationFunction);
            IPlugin(plugin).onInstall(installData);
        }
    }

    function _uninstallValidation(
        FunctionReference validationFunction,
        bytes4[] calldata selectors,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        _storage.validationData[validationFunction].isDefault = false;
        _storage.validationData[validationFunction].isSignatureValidation = false;

        bytes[] memory preValidationHookUninstallDatas = abi.decode(preValidationHookUninstallData, (bytes[]));

        // Clear pre validation hooks
        FunctionReference[] storage preValidationHooks =
            _storage.validationData[validationFunction].preValidationHooks;
        for (uint256 i = 0; i < preValidationHooks.length; ++i) {
            FunctionReference preValidationFunction = preValidationHooks[i];
            if (preValidationHookUninstallDatas[0].length > 0) {
                (address preValidationPlugin,) = FunctionReferenceLib.unpack(preValidationFunction);
                IPlugin(preValidationPlugin).onUninstall(preValidationHookUninstallDatas[0]);
            }
        }
        delete _storage.validationData[validationFunction].preValidationHooks;

        // Because this function also calls `onUninstall`, and removes the shared flag from validation, we must
        // assume these selectors passed in to be exhaustive.
        // TODO: consider enforcing this from user-supplied install config.
        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.selectorData[selector].validations.remove(toSetValue(validationFunction))) {
                revert ValidationNotSet(selector, validationFunction);
            }
        }

        if (uninstallData.length > 0) {
            (address plugin,) = FunctionReferenceLib.unpack(validationFunction);
            IPlugin(plugin).onUninstall(uninstallData);
        }
    }
}
