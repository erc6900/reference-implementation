// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

import {
    ManifestExecutionHook,
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata
} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract ComprehensivePlugin is BasePlugin {
    // todo: remove
    // enum FunctionId {
    //     PRE_USER_OP_VALIDATION_HOOK_1,
    //     PRE_USER_OP_VALIDATION_HOOK_2,
    //     PRE_RUNTIME_VALIDATION_HOOK_1,
    //     PRE_RUNTIME_VALIDATION_HOOK_2,
    //     VALIDATION,
    //     PRE_EXECUTION_HOOK,
    //     PRE_PERMITTED_CALL_EXECUTION_HOOK,
    //     POST_EXECUTION_HOOK,
    //     POST_PERMITTED_CALL_EXECUTION_HOOK
    // }

    string public constant NAME = "Comprehensive Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function foo() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preUserOpValidationHook(UserOperation calldata, bytes32) external pure override returns (uint256) {
        // if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)) {
        //     return 0;
        // } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)) {
        //     return 0;
        // }
        // revert NotImplemented();
        // Todo: is there a logic step missing here, with the two different hooks?
        return 0;
    }

    function validateUserOp(UserOperation calldata, bytes32) external pure override returns (uint256) {
        return 0;
    }

    function preRuntimeValidationHook(address, uint256, bytes calldata) external pure override {
        // if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1)) {
        //     return;
        // } else if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2)) {
        //     return;
        // }
        // revert NotImplemented();
        // Todo: is there a logic step missing here, with the two different hooks?
        return;
    }

    function validateRuntime(address, uint256, bytes calldata) external pure override {
        return;
    }

    function preExecutionHook(address, uint256, bytes calldata) external pure override returns (bytes memory) {
        // if (functionId == uint8(FunctionId.PRE_EXECUTION_HOOK)) {
        //     return "";
        // } else if (functionId == uint8(FunctionId.PRE_PERMITTED_CALL_EXECUTION_HOOK)) {
        //     return "";
        // }
        // revert NotImplemented();
        // Todo: is there a logic step missing here, with the two different hooks?
        return "";
    }

    function postExecutionHook(bytes calldata) external pure override {
        // if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
        //     return;
        // } else if (functionId == uint8(FunctionId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
        //     return;
        // }
        // revert NotImplemented();
        // Todo: is there a logic step missing here, with the two different hooks?
        return;
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.foo.selector;

        ManifestFunction memory fooValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: fooValidationFunction
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });
        // todo: manifest.preUserOpValidationHooks[1] = <duplicate of above>
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });
        // todo: manifest.preUserOpValidationHooks[3] = <duplicate of above>

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });
        // todo: manifest.preRuntimeValidationHooks[1] = <duplicate of above>
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });
        // todo: manifest.preRuntimeValidationHooks[3] = <duplicate of above>

        manifest.executionHooks = new ManifestExecutionHook[](1);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }

    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;
        return metadata;
    }
}
