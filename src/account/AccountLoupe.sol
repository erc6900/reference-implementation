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

            uint256 executionHooksLen = executionData.executionHooks.length();
            data.executionHooks = new HookConfig[](executionHooksLen);
            for (uint256 i = 0; i < executionHooksLen; ++i) {
                data.executionHooks[i] = HookConfig.wrap(bytes26(executionData.executionHooks.at(i)));
            }
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

        uint256 permissionHooksLen = validationData.permissionHooks.length();
        data.permissionHooks = new HookConfig[](permissionHooksLen);
        for (uint256 i = 0; i < permissionHooksLen; ++i) {
            data.permissionHooks[i] = HookConfig.wrap(bytes26(validationData.permissionHooks.at(i)));
        }

        bytes32[] memory selectors = validationData.selectors.values();
        uint256 selectorsLen = selectors.length;
        data.selectors = new bytes4[](selectorsLen);
        for (uint256 j = 0; j < selectorsLen; ++j) {
            data.selectors[j] = bytes4(selectors[j]);
        }
    }
}
