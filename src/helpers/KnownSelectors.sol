// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IAggregator} from "@eth-infinitism/account-abstraction/interfaces/IAggregator.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAccountLoupe} from "../interfaces/IAccountLoupe.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IPluginManager} from "../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../interfaces/IStandardExecutor.sol";
import {IValidation} from "../interfaces/IValidation.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";

/// @dev Library to help to check if a selector is a know function selector of the modular account or ERC-4337
/// contract.
library KnownSelectors {
    function isNativeFunction(bytes4 selector) internal pure returns (bool) {
        return
        // check against IAccount methods
        selector == IAccount.validateUserOp.selector
        // check against IPluginManager methods
        || selector == IPluginManager.installPlugin.selector || selector == IPluginManager.uninstallPlugin.selector
        // check against IERC165 methods
        || selector == IERC165.supportsInterface.selector
        // check against UUPSUpgradeable methods
        || selector == UUPSUpgradeable.proxiableUUID.selector
            || selector == UUPSUpgradeable.upgradeToAndCall.selector
        // check against IStandardExecutor methods
        || selector == IStandardExecutor.execute.selector || selector == IStandardExecutor.executeBatch.selector
            || selector == IStandardExecutor.executeWithAuthorization.selector
        // check against IAccountLoupe methods
        || selector == IAccountLoupe.getExecutionFunctionHandler.selector
            || selector == IAccountLoupe.getSelectors.selector || selector == IAccountLoupe.getExecutionHooks.selector
            || selector == IAccountLoupe.getPreValidationHooks.selector
            || selector == IAccountLoupe.getInstalledPlugins.selector;
    }

    function isErc4337Function(bytes4 selector) internal pure returns (bool) {
        return selector == IAggregator.validateSignatures.selector
            || selector == IAggregator.validateUserOpSignature.selector
            || selector == IAggregator.aggregateSignatures.selector
            || selector == IPaymaster.validatePaymasterUserOp.selector || selector == IPaymaster.postOp.selector;
    }

    function isIPluginFunction(bytes4 selector) internal pure returns (bool) {
        return selector == IPlugin.onInstall.selector || selector == IPlugin.onUninstall.selector
            || selector == IPlugin.pluginManifest.selector || selector == IPlugin.pluginMetadata.selector
            || selector == IExecutionHook.preExecutionHook.selector
            || selector == IExecutionHook.postExecutionHook.selector || selector == IValidation.validateUserOp.selector
            || selector == IValidation.validateRuntime.selector || selector == IValidation.validateSignature.selector
            || selector == IValidationHook.preUserOpValidationHook.selector
            || selector == IValidationHook.preRuntimeValidationHook.selector;
    }
}
