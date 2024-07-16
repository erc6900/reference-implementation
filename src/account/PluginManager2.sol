// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";
import {FunctionReference} from "../interfaces/IPluginManager.sol";
import {FunctionReferenceLib} from "../helpers/FunctionReferenceLib.sol";
import {AccountStorage, getAccountStorage, toSetValue, toFunctionReference} from "./AccountStorage.sol";
import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";

// Temporary additional functions for a user-controlled install flow for validation functions.
abstract contract PluginManager2 {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // Index marking the start of the data for the validation function.
    uint8 internal constant _RESERVED_VALIDATION_DATA_INDEX = 255;
    uint8 internal constant _SELF_PERMIT_VALIDATION_FUNCTIONID = type(uint8).max;

    error GlobalValidationAlreadySet(FunctionReference validationFunction);
    error PreValidationAlreadySet(FunctionReference validationFunction, FunctionReference preValidationFunction);
    error ValidationAlreadySet(bytes4 selector, FunctionReference validationFunction);
    error ValidationNotSet(bytes4 selector, FunctionReference validationFunction);
    error PermissionAlreadySet(FunctionReference validationFunction, ExecutionHook hook);
    error PreValidationHookLimitExceeded();

    function _installValidation(
        FunctionReference validationFunction,
        bool isGlobal,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks,
        bytes memory permissionHooks
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

            // Avoid collision between reserved index and actual indices
            if (
                _storage.validationData[validationFunction].preValidationHooks.length
                    > _RESERVED_VALIDATION_DATA_INDEX
            ) {
                revert PreValidationHookLimitExceeded();
            }
        }

        if (permissionHooks.length > 0) {
            (ExecutionHook[] memory permissionFunctions, bytes[] memory initDatas) =
                abi.decode(permissionHooks, (ExecutionHook[], bytes[]));

            for (uint256 i = 0; i < permissionFunctions.length; ++i) {
                ExecutionHook memory permissionFunction = permissionFunctions[i];

                if (
                    !_storage.validationData[validationFunction].permissionHooks.add(toSetValue(permissionFunction))
                ) {
                    revert PermissionAlreadySet(validationFunction, permissionFunction);
                }

                if (initDatas[i].length > 0) {
                    (address executionPlugin,) = FunctionReferenceLib.unpack(permissionFunction.hookFunction);
                    IPlugin(executionPlugin).onInstall(initDatas[i]);
                }
            }
        }

        (address plugin, uint8 functionId) = FunctionReferenceLib.unpack(validationFunction);
        // If the functionId indicates a self-permit for direct runtime calls from plugins, we don't need to
        // install a function as the functionReference will consist of the msg.sender + constant_functionId

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_storage.validationData[validationFunction].selectors.add(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, validationFunction);
            }
        }

        if (functionId != _SELF_PERMIT_VALIDATION_FUNCTIONID) {
            // Only allow global validations if they're not direct-calls.
            if (isGlobal) {
                if (_storage.validationData[validationFunction].isGlobal) {
                    revert GlobalValidationAlreadySet(validationFunction);
                }
                _storage.validationData[validationFunction].isGlobal = true;
            }

            if (installData.length > 0) {
                IPlugin(plugin).onInstall(installData);
            }
        }
    }

    function _uninstallValidation(
        FunctionReference validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) internal {
        AccountStorage storage _storage = getAccountStorage();

        _storage.validationData[validationFunction].isGlobal = false;
        _storage.validationData[validationFunction].isSignatureValidation = false;

        {
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
        }

        {
            bytes[] memory permissionHookUninstallDatas = abi.decode(permissionHookUninstallData, (bytes[]));

            // Clear permission hooks
            EnumerableSet.Bytes32Set storage permissionHooks =
                _storage.validationData[validationFunction].permissionHooks;

            uint256 len = permissionHooks.length();
            for (uint256 i = 0; i < len; ++i) {
                bytes32 permissionHook = permissionHooks.at(0);
                permissionHooks.remove(permissionHook);
                address permissionHookPlugin = address(uint160(bytes20(permissionHook)));
                IPlugin(permissionHookPlugin).onUninstall(permissionHookUninstallDatas[i]);
            }
        }
        delete _storage.validationData[validationFunction].preValidationHooks;

        // Clear selectors
        while (_storage.validationData[validationFunction].selectors.length() > 0) {
            bytes32 selector = _storage.validationData[validationFunction].selectors.at(0);
            _storage.validationData[validationFunction].selectors.remove(selector);
        }

        if (uninstallData.length > 0) {
            (address plugin,) = FunctionReferenceLib.unpack(validationFunction);
            IPlugin(plugin).onUninstall(uninstallData);
        }
    }
}
