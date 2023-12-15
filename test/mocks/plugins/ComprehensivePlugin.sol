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
    enum FunctionId {
        PRE_USER_OP_VALIDATION_HOOK_1,
        PRE_USER_OP_VALIDATION_HOOK_2,
        USER_OP_VALIDATION,
        PRE_RUNTIME_VALIDATION_HOOK_1,
        PRE_RUNTIME_VALIDATION_HOOK_2,
        RUNTIME_VALIDATION,
        PRE_EXECUTION_HOOK,
        PRE_PERMITTED_CALL_EXECUTION_HOOK,
        POST_EXECUTION_HOOK,
        POST_PERMITTED_CALL_EXECUTION_HOOK
    }

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

    function preUserOpValidationHook(uint8 functionId, UserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1)) {
            return 0;
        } else if (functionId == uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2)) {
            return 0;
        }
        revert NotImplemented();
    }

    function userOpValidationFunction(uint8 functionId, UserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return 0;
        }
        revert NotImplemented();
    }

    function preRuntimeValidationHook(uint8 functionId, address, uint256, bytes calldata) external pure override {
        if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1)) {
            return;
        } else if (functionId == uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2)) {
            return;
        }
        revert NotImplemented();
    }

    function runtimeValidationFunction(uint8 functionId, address, uint256, bytes calldata)
        external
        pure
        override
    {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION)) {
            return;
        }
        revert NotImplemented();
    }

    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes memory)
    {
        if (functionId == uint8(FunctionId.PRE_EXECUTION_HOOK)) {
            return "";
        } else if (functionId == uint8(FunctionId.PRE_PERMITTED_CALL_EXECUTION_HOOK)) {
            return "";
        }
        revert NotImplemented();
    }

    function postExecutionHook(uint8 functionId, bytes calldata) external pure override {
        if (functionId == uint8(FunctionId.POST_EXECUTION_HOOK)) {
            return;
        } else if (functionId == uint8(FunctionId.POST_PERMITTED_CALL_EXECUTION_HOOK)) {
            return;
        }
        revert NotImplemented();
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.foo.selector;

        ManifestFunction memory fooUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: fooUserOpValidationFunction
        });

        ManifestFunction memory fooRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: fooRuntimeValidationFunction
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preUserOpValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_USER_OP_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](4);
        manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preRuntimeValidationHooks[3] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_RUNTIME_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        manifest.executionHooks = new ManifestExecutionHook[](1);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_EXECUTION_HOOK),
                dependencyIndex: 0 // Unused.
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.POST_EXECUTION_HOOK),
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
