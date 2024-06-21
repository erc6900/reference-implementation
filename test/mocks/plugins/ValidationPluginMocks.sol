// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    ManifestFunction,
    ManifestExecutionFunction,
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

    function validateUserOp(uint8 functionId, PackedUserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256, bytes memory)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION)) {
            return (_userOpValidationFunctionData, "");
        }
        revert NotImplemented();
    }

    function validateSignature(uint8, address, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert NotImplemented();
    }

    // Empty stubs
    function pluginMetadata() external pure override returns (PluginMetadata memory) {}

    function preRuntimeValidationHook(uint8, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {
        revert NotImplemented();
    }

    function validateRuntime(uint8, address, uint256, bytes calldata, bytes calldata) external pure override {
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

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            isPublic: false,
            allowDefaultValidation: false
        });

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

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.bar.selector,
            isPublic: false,
            allowDefaultValidation: false
        });

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

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.baz.selector,
            isPublic: false,
            allowDefaultValidation: false
        });

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

        return manifest;
    }
}
