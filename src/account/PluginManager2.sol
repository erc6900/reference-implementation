// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";
import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {
    AccountStorage,
    getAccountStorage,
    toSetValue,
    toFunctionReference,
    ValidationData
} from "./AccountStorage.sol";

// Temporary additional functions for a user-controlled install flow for validation functions.
abstract contract PluginManager2 {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event ValidationUpdated(bytes32 validationId);
    event ValidationUninstalled(bytes32 validationId);

    error DefaultValidationAlreadySet(FunctionReference validationFunction);
    error PreValidationAlreadySet(FunctionReference validationFunction, FunctionReference preValidationFunction);
    // TODO to be renamed once PR https://github.com/erc6900/reference-implementation/pull/85/files merged
    error ValidationAlreadySetNew(bytes32 validationId);
    error ValidationAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error ValidationNotSet(bytes4 selector, FunctionReference validationFunction);

    function _installValidation(
        bytes32 validationIdToUpdate,
        FunctionReference validationFunction,
        bool isDefault,
        bool isSignatureValidationAllowed,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks
    ) internal returns (bytes32 validationId) {
        AccountStorage storage _storage = getAccountStorage();
        validationId = validationIdToUpdate;

        if (validationId == bytes32(0)) {
            validationId = keccak256(abi.encode(validationFunction, isDefault, installData));

            if (FunctionReferenceLib.notEmpty(_storage.validationData[validationId].validationFunction)) {
                revert ValidationAlreadySetNew(validationId);
            }
        }

        // TODO: all fields can be updated on the validation except selectors and hooks are addition only, to
        // update, require uninstall and reinstall of validation

        _storage.validationData[validationId].isSignatureValidationAllowed = isSignatureValidationAllowed;

        if (preValidationHooks.length > 0) {
            (FunctionReference[] memory preValidationFunctions, bytes[] memory initDatas) =
                abi.decode(preValidationHooks, (FunctionReference[], bytes[]));

            for (uint256 i = 0; i < preValidationFunctions.length; ++i) {
                FunctionReference preValidationFunction = preValidationFunctions[i];

                if (
                    !_storage.validationData[validationId].preValidationHooks.add(toSetValue(preValidationFunction))
                ) {
                    revert PreValidationAlreadySet(validationFunction, preValidationFunction);
                }

                if (initDatas[i].length > 0) {
                    (address preValidationPlugin,) = FunctionReferenceLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onInstall(initDatas[i]);
                }
            }
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
        emit ValidationUpdated(validationId);
    }

    function _uninstallValidation(
        bytes32 validationId,
        bytes4[] calldata selectors,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();
        ValidationData storage validationData = _storage.validationData[validationId];

        validationData.isDefault = false;
        validationData.isSignatureValidationAllowed = false;

        bytes[] memory preValidationHookUninstallDatas = abi.decode(preValidationHookUninstallData, (bytes[]));

        // Clear pre validation hooks
        EnumerableSet.Bytes32Set storage preValidationHooks = validationData.preValidationHooks;
        while (preValidationHooks.length() > 0) {
            FunctionReference preValidationFunction = toFunctionReference(preValidationHooks.at(0));
            preValidationHooks.remove(toSetValue(preValidationFunction));
            (address preValidationPlugin,) = FunctionReferenceLib.unpack(preValidationFunction);
            if (preValidationHookUninstallDatas[0].length > 0) {
                IPlugin(preValidationPlugin).onUninstall(preValidationHookUninstallDatas[0]);
            }
        }

        // Because this function also calls `onUninstall`, and removes the default flag from validation, we must
        // assume these selectors passed in to be exhaustive.
        // TODO: consider enforcing this from user-supplied install config.
        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.selectorData[selector].validations.remove(toSetValue(validationData.validationFunction)))
            {
                revert ValidationNotSet(selector, validationData.validationFunction);
            }
        }

        if (uninstallData.length > 0) {
            (address plugin,) = FunctionReferenceLib.unpack(validationData.validationFunction);
            IPlugin(plugin).onUninstall(uninstallData);
        }
        emit ValidationUninstalled(validationId);
    }
}
