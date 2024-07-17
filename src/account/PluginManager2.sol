// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {PluginEntityLib} from "../helpers/PluginEntityLib.sol";
import {ValidationConfigLib} from "../helpers/ValidationConfigLib.sol";

import {ExecutionHook} from "../interfaces/IAccountLoupe.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {PluginEntity, ValidationConfig} from "../interfaces/IPluginManager.sol";
import {ValidationData, getAccountStorage, toSetValue} from "./AccountStorage.sol";

// Temporary additional functions for a user-controlled install flow for validation functions.
abstract contract PluginManager2 {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ValidationConfigLib for ValidationConfig;

    // Index marking the start of the data for the validation function.
    uint8 internal constant _RESERVED_VALIDATION_DATA_INDEX = 255;
    uint32 internal constant _SELF_PERMIT_VALIDATION_FUNCTIONID = type(uint32).max;

    error PreValidationAlreadySet(PluginEntity validationFunction, PluginEntity preValidationFunction);
    error ValidationAlreadySet(bytes4 selector, PluginEntity validationFunction);
    error ValidationNotSet(bytes4 selector, PluginEntity validationFunction);
    error PermissionAlreadySet(PluginEntity validationFunction, ExecutionHook hook);
    error PreValidationHookLimitExceeded();

    function _installValidation(
        ValidationConfig validationConfig,
        bytes4[] memory selectors,
        bytes calldata installData,
        bytes memory preValidationHooks,
        bytes memory permissionHooks
    ) internal {
        ValidationData storage _validationData =
            getAccountStorage().validationData[validationConfig.pluginEntity()];

        if (preValidationHooks.length > 0) {
            (PluginEntity[] memory preValidationFunctions, bytes[] memory initDatas) =
                abi.decode(preValidationHooks, (PluginEntity[], bytes[]));

            for (uint256 i = 0; i < preValidationFunctions.length; ++i) {
                PluginEntity preValidationFunction = preValidationFunctions[i];

                _validationData.preValidationHooks.push(preValidationFunction);

                if (initDatas[i].length > 0) {
                    (address preValidationPlugin,) = PluginEntityLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onInstall(initDatas[i]);
                }
            }

            // Avoid collision between reserved index and actual indices
            if (_validationData.preValidationHooks.length > _RESERVED_VALIDATION_DATA_INDEX) {
                revert PreValidationHookLimitExceeded();
            }
        }

        if (permissionHooks.length > 0) {
            (ExecutionHook[] memory permissionFunctions, bytes[] memory initDatas) =
                abi.decode(permissionHooks, (ExecutionHook[], bytes[]));

            for (uint256 i = 0; i < permissionFunctions.length; ++i) {
                ExecutionHook memory permissionFunction = permissionFunctions[i];

                if (!_validationData.permissionHooks.add(toSetValue(permissionFunction))) {
                    revert PermissionAlreadySet(validationConfig.pluginEntity(), permissionFunction);
                }

                if (initDatas[i].length > 0) {
                    (address executionPlugin,) = PluginEntityLib.unpack(permissionFunction.hookFunction);
                    IPlugin(executionPlugin).onInstall(initDatas[i]);
                }
            }
        }

        for (uint256 i = 0; i < selectors.length; ++i) {
            bytes4 selector = selectors[i];
            if (!_validationData.selectors.add(toSetValue(selector))) {
                revert ValidationAlreadySet(selector, validationConfig.pluginEntity());
            }
        }

        if (validationConfig.entityId() != _SELF_PERMIT_VALIDATION_FUNCTIONID) {
            // Only allow global validations and signature validations if they're not direct-call validations.

            _validationData.isGlobal = validationConfig.isGlobal();
            _validationData.isSignatureValidation = validationConfig.isSignatureValidation();
            if (installData.length > 0) {
                IPlugin(validationConfig.plugin()).onInstall(installData);
            }
        }
    }

    function _uninstallValidation(
        PluginEntity validationFunction,
        bytes calldata uninstallData,
        bytes calldata preValidationHookUninstallData,
        bytes calldata permissionHookUninstallData
    ) internal {
        ValidationData storage _validationData = getAccountStorage().validationData[validationFunction];

        _validationData.isGlobal = false;
        _validationData.isSignatureValidation = false;

        {
            bytes[] memory preValidationHookUninstallDatas = abi.decode(preValidationHookUninstallData, (bytes[]));

            // Clear pre validation hooks
            PluginEntity[] storage preValidationHooks = _validationData.preValidationHooks;
            for (uint256 i = 0; i < preValidationHooks.length; ++i) {
                PluginEntity preValidationFunction = preValidationHooks[i];
                if (preValidationHookUninstallDatas[0].length > 0) {
                    (address preValidationPlugin,) = PluginEntityLib.unpack(preValidationFunction);
                    IPlugin(preValidationPlugin).onUninstall(preValidationHookUninstallDatas[0]);
                }
            }
            delete _validationData.preValidationHooks;
        }

        {
            bytes[] memory permissionHookUninstallDatas = abi.decode(permissionHookUninstallData, (bytes[]));

            // Clear permission hooks
            EnumerableSet.Bytes32Set storage permissionHooks = _validationData.permissionHooks;
            uint256 permissionHookLen = permissionHooks.length();
            for (uint256 i = 0; i < permissionHookLen; ++i) {
                bytes32 permissionHook = permissionHooks.at(0);
                permissionHooks.remove(permissionHook);
                address permissionHookPlugin = address(uint160(bytes20(permissionHook)));
                IPlugin(permissionHookPlugin).onUninstall(permissionHookUninstallDatas[i]);
            }
        }

        // Clear selectors
        uint256 selectorLen = _validationData.selectors.length();
        for (uint256 i = 0; i < selectorLen; ++i) {
            bytes32 selectorSetValue = _validationData.selectors.at(0);
            _validationData.selectors.remove(selectorSetValue);
        }

        if (uninstallData.length > 0) {
            (address plugin,) = PluginEntityLib.unpack(validationFunction);
            IPlugin(plugin).onUninstall(uninstallData);
        }
    }
}
