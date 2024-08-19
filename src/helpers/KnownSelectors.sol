// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IExecutionHookModule} from "../interfaces/IExecutionHookModule.sol";
import {IExecutionModule} from "../interfaces/IExecutionModule.sol";
import {IModularAccount} from "../interfaces/IModularAccount.sol";
import {IModule} from "../interfaces/IModule.sol";
import {IValidationHookModule} from "../interfaces/IValidationHookModule.sol";
import {IValidationModule} from "../interfaces/IValidationModule.sol";

/// @dev Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectors {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return
        // check against IAccount methods
        selector == IAccount.validateUserOp.selector
        // check against module manager methods
        || selector == IModularAccount.installExecution.selector
            || selector == IModularAccount.uninstallExecution.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against UUPSUpgradeable methods
        || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
        // check against IModularAccount methods
        || selector == IModularAccount.execute.selector || selector == IModularAccount.executeBatch.selector
            || selector == IModularAccount.executeWithAuthorization.selector
        // check against account loupe methods
        || selector == IAccountLoupe.getExecutionData.selector
            || selector == IAccountLoupe.getValidationData.selector;
    }

    function isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function isIModuleFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IModule.onInstall.selector || selector == IModule.onUninstall.selector
            || selector == IExecutionModule.executionManifest.selector || selector == IModule.moduleMetadata.selector
            || selector == IExecutionHookModule.preExecutionHook.selector
            || selector == IExecutionHookModule.postExecutionHook.selector
            || selector == IValidationModule.validateUserOp.selector
            || selector == IValidationModule.validateRuntime.selector
            || selector == IValidationModule.validateSignature.selector
            || selector == IValidationHookModule.preUserOpValidationHook.selector
            || selector == IValidationHookModule.preRuntimeValidationHook.selector;
    }
}
