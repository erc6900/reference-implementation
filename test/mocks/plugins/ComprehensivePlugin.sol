// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {
    ManifestExecutionHook,
    ManifestExecutionFunction,
    ManifestValidation,
    PluginManifest,
    PluginMetadata
} from "../../../src/interfaces/IPlugin.sol";
import {PluginManifest} from "../../../src/interfaces/IPlugin.sol";
import {IValidation} from "../../../src/interfaces/IValidation.sol";
import {IValidationHook} from "../../../src/interfaces/IValidationHook.sol";
import {IExecutionHook} from "../../../src/interfaces/IExecutionHook.sol";

import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract ComprehensivePlugin is IValidation, IValidationHook, IExecutionHook, BasePlugin {
    enum ValidationId {
        PRE_VALIDATION_HOOK_1,
        PRE_VALIDATION_HOOK_2,
        VALIDATION,
        BOTH_EXECUTION_HOOKS,
        PRE_EXECUTION_HOOK,
        POST_EXECUTION_HOOK,
        SIG_VALIDATION
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

    function preUserOpValidationHook(uint32 validationId, PackedUserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (validationId == uint32(ValidationId.PRE_VALIDATION_HOOK_1)) {
            return 0;
        } else if (validationId == uint32(ValidationId.PRE_VALIDATION_HOOK_2)) {
            return 0;
        }
        revert NotImplemented();
    }

    function validateUserOp(uint32 validationId, PackedUserOperation calldata, bytes32)
        external
        pure
        override
        returns (uint256)
    {
        if (validationId == uint32(ValidationId.VALIDATION)) {
            return 0;
        }
        revert NotImplemented();
    }

    function preRuntimeValidationHook(uint32 validationId, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {
        if (validationId == uint32(ValidationId.PRE_VALIDATION_HOOK_1)) {
            return;
        } else if (validationId == uint32(ValidationId.PRE_VALIDATION_HOOK_2)) {
            return;
        }
        revert NotImplemented();
    }

    function validateRuntime(uint32 validationId, address, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
    {
        if (validationId == uint32(ValidationId.VALIDATION)) {
            return;
        }
        revert NotImplemented();
    }

    function validateSignature(uint32 validationId, address, bytes32, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        if (validationId == uint32(ValidationId.SIG_VALIDATION)) {
            return 0xffffffff;
        }
        revert NotImplemented();
    }

    function preExecutionHook(uint32 validationId, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes memory)
    {
        if (validationId == uint32(ValidationId.PRE_EXECUTION_HOOK)) {
            return "";
        } else if (validationId == uint32(ValidationId.BOTH_EXECUTION_HOOKS)) {
            return "";
        }
        revert NotImplemented();
    }

    function postExecutionHook(uint32 validationId, bytes calldata) external pure override {
        if (validationId == uint32(ValidationId.POST_EXECUTION_HOOK)) {
            return;
        } else if (validationId == uint32(ValidationId.BOTH_EXECUTION_HOOKS)) {
            return;
        }
        revert NotImplemented();
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            isPublic: false,
            allowGlobalValidation: false
        });

        bytes4[] memory validationSelectors = new bytes4[](1);
        validationSelectors[0] = this.foo.selector;

        manifest.validationFunctions = new ManifestValidation[](1);
        manifest.validationFunctions[0] = ManifestValidation({
            validationId: uint32(ValidationId.VALIDATION),
            isDefault: true,
            isSignatureValidation: false,
            selectors: validationSelectors
        });

        manifest.executionHooks = new ManifestExecutionHook[](3);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            validationId: uint32(ValidationId.BOTH_EXECUTION_HOOKS),
            isPreHook: true,
            isPostHook: true
        });
        manifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            validationId: uint32(ValidationId.PRE_EXECUTION_HOOK),
            isPreHook: true,
            isPostHook: false
        });
        manifest.executionHooks[2] = ManifestExecutionHook({
            executionSelector: this.foo.selector,
            validationId: uint32(ValidationId.POST_EXECUTION_HOOK),
            isPreHook: false,
            isPostHook: true
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
