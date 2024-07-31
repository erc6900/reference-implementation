// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {HookConfigLib} from "../helpers/HookConfigLib.sol";
import {ExecutionDataView, IAccountLoupe, ValidationDataView} from "../interfaces/IAccountLoupe.sol";
import {HookConfig, IModuleManager, ModuleEntity} from "../interfaces/IModuleManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {ExecutionData, ValidationData, getAccountStorage} from "./AccountStorage.sol";

abstract contract AccountLoupe is IAccountLoupe {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using HookConfigLib for HookConfig;

    /// @inheritdoc IAccountLoupe
    function getExecutionData(bytes4 selector) external view override returns (ExecutionDataView memory data) {
        if (
            selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
                || selector == UUPSUpgradeable.upgradeToAndCall.selector
                || selector == IModuleManager.installExecution.selector
                || selector == IModuleManager.uninstallExecution.selector
        ) {
            data.module = address(this);
            data.allowGlobalValidation = true;
        } else {
            ExecutionData storage executionData = getAccountStorage().executionData[selector];
            data.module = executionData.module;
            data.isPublic = executionData.isPublic;
            data.allowGlobalValidation = executionData.allowGlobalValidation;
            data.executionHooks = executionData.executionHooks.values();
        }
    }

    /// @inheritdoc IAccountLoupe
    function getValidationData(ModuleEntity validationFunction)
        external
        view
        override
        returns (ValidationDataView memory data)
    {
        ValidationData storage validationData = getAccountStorage().validationData[validationFunction];
        data.isGlobal = validationData.isGlobal;
        data.isSignatureValidation = validationData.isSignatureValidation;
        data.preValidationHooks = validationData.preValidationHooks;
        data.permissionHooks = validationData.permissionHooks.values();
        data.selectors = validationData.selectors.values();
    }
}
