// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest
} from "../../../src/interfaces/IPlugin.sol";
import {BaseTestPlugin} from "./BaseTestPlugin.sol";

abstract contract MockBaseUserOpValidationPlugin is BaseTestPlugin {
    uint256 internal _userOpValidationFunctionData;
    uint256 internal _preUserOpValidationHookData;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preUserOpValidationHook(UserOperation calldata, bytes32) external view override returns (uint256) {
        // todo: is there a test case we don't cover by not having multiple hooks?
        return _preUserOpValidationHookData;
    }

    function validateUserOp(UserOperation calldata, bytes32) external view override returns (uint256) {
        return _userOpValidationFunctionData;
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
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

contract MockUserOpValidationWithPreHookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 userOpValidationFunctionData, uint256 preUserOpValidationHookData)
        external
    {
        _userOpValidationFunctionData = userOpValidationFunctionData;
        _preUserOpValidationHookData = preUserOpValidationHookData;
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
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: userOpValidationFunctionRef
        });

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: this.bar.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}

// Applies a second pre validation hook over the `bar()` function from MockUserOpValidationWithPreHookPlugin.
contract MockOnlyPreUserOpValidationHookPlugin is MockBaseUserOpValidationPlugin {
    function setValidationData(uint256 preUserOpValidationHookData) external {
        _preUserOpValidationHookData = preUserOpValidationHookData;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.preUserOpValidationHooks = new ManifestAssociatedFunction[](1);
        manifest.preUserOpValidationHooks[0] = ManifestAssociatedFunction({
            executionSelector: MockUserOpValidationWithPreHookPlugin.bar.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                dependencyIndex: 0 // Unused.
            })
        });

        return manifest;
    }
}
