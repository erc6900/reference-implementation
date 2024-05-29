// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginMetadata,
    PluginManifest
} from "../../../src/interfaces/IPlugin.sol";
import {IValidation} from "../../../src/interfaces/IValidation.sol";
import {IValidationHook} from "../../../src/interfaces/IValidationHook.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

abstract contract MockBaseUserOpValidationPlugin is IValidation, IValidationHook, BasePlugin {
    enum FunctionId {
        USER_OP_VALIDATION,
        PRE_VALIDATION_HOOK_1,
        PRE_VALIDATION_HOOK_2
    }

    uint256 internal _userOpValidationFunctionData;
    uint256 internal _preUserOpValidationHook1Data;
    uint256 internal _preUserOpValidationHook2Data;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preUserOpValidationHook(uint8 functionId, PackedUserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.PRE_VALIDATION_HOOK_1)) {
            return _preUserOpValidationHook1Data;
        } else if (functionId == uint8(FunctionId.PRE_VALIDATION_HOOK_2)) {
            return _preUserOpValidationHook2Data;
        }
        revert NotImplemented();
    }

    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return _userOpValidationFunctionData;
        }
        revert NotImplemented();
    }

    // Empty stubs
    function pluginMetadata() external pure override returns (PluginMetadata memory) {}

    function preRuntimeValidationHook(uint8, address, uint256, bytes calldata) external pure override {
        revert NotImplemented();
    }

    function runtimeValidationFunction(uint8, address, uint256, bytes calldata) external pure override {
        revert NotImplemented();
    }
}

contract MockUserOpValidationPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 userOpValidationFunctionData) external {
        _userOpValidationFunctionData = userOpValidationFunctionData;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function foo() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.foo.selector;

        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.foo.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.USER_OP_VALIDATION),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

contract MockUserOpValidation1HookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 userOpValidationFunctionData, uint256 preUserOpValidationHook1Data)
        external
    {
        _userOpValidationFunctionData = userOpValidationFunctionData;
        _preUserOpValidationHook1Data = preUserOpValidationHook1Data;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function bar() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.bar.selector;

        ManifestFunction memory userOpValidationFunctionRef = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: userOpValidationFunctionRef
        });

        manifest.preValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

contract MockUserOpValidation2HookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(
        uint256 userOpValidationFunctionData,
        uint256 preUserOpValidationHook1Data,
        uint256 preUserOpValidationHook2Data
    ) external {
        _userOpValidationFunctionData = userOpValidationFunctionData;
        _preUserOpValidationHook1Data = preUserOpValidationHook1Data;
        _preUserOpValidationHook2Data = preUserOpValidationHook2Data;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function baz() external {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.baz.selector;

        ManifestFunction memory userOpValidationFunctionRef = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION),
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: userOpValidationFunctionRef
        });

        manifest.preValidationHooks = new ManifestAssociatedFunction[](2);
        manifest.preValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_VALIDATION_HOOK_1),
                dependencyIndex: 0 // Unused.
            })
        });
        manifest.preValidationHooks[1] = ManifestAssociatedFunction({
            executionSelector: this.baz.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: uint8(FunctionId.PRE_VALIDATION_HOOK_2),
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}
