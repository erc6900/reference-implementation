// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {
    ManifestExecutionFunction,
    ManifestExternalCallPermission,
    PluginManifest,
    PluginMetadata
} from "../../../src/interfaces/IPlugin.sol";
import {IPluginExecutor} from "../../../src/interfaces/IPluginExecutor.sol";

import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract RegularResultContract {
    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }
}

contract ResultCreatorPlugin is BasePlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function foo() external pure returns (bytes32) {
        return keccak256("bar");
    }

    function bar() external pure returns (bytes32) {
        return keccak256("foo");
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.foo.selector,
            isPublic: true,
            allowSharedValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.bar.selector,
            isPublic: false,
            allowSharedValidation: false
        });

        return manifest;
    }

    function pluginMetadata() external pure override returns (PluginMetadata memory) {}
}

contract ResultConsumerPlugin is BasePlugin {
    ResultCreatorPlugin public immutable RESULT_CREATOR;
    RegularResultContract public immutable REGULAR_RESULT_CONTRACT;

    constructor(ResultCreatorPlugin _resultCreator, RegularResultContract _regularResultContract) {
        RESULT_CREATOR = _resultCreator;
        REGULAR_RESULT_CONTRACT = _regularResultContract;
    }

    // Check the return data through the executeFromPlugin fallback case
    function checkResultEFPFallback(bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));

        bytes32 actual = ResultCreatorPlugin(msg.sender).foo();

        return actual == expected;
    }

    // Check the rturn data through the executeFromPlugin std exec case
    function checkResultEFPExternal(address target, bytes32 expected) external returns (bool) {
        // This result should be allowed based on the manifest permission request
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            target, 0, abi.encodeCall(RegularResultContract.foo, ())
        );

        bytes32 actual = abi.decode(returnData, (bytes32));

        return actual == expected;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        // We want to return the address of the immutable RegularResultContract in the permitted external calls
        // area of the manifest.
        // However, reading from immutable values is not permitted in pure functions. So we use this hack to get
        // around that.
        // In regular, non-mock plugins, external call targets in the plugin manifest should be constants, not just
        // immutbales.
        // But to make testing easier, we do this.

        function() internal pure returns (PluginManifest memory) pureManifestGetter;

        function() internal view returns (PluginManifest memory) viewManifestGetter = _innerPluginManifest;

        assembly ("memory-safe") {
            pureManifestGetter := viewManifestGetter
        }

        return pureManifestGetter();
    }

    function _innerPluginManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.checkResultEFPFallback.selector,
            isPublic: true,
            allowSharedValidation: false
        });
        manifest.executionFunctions[1] = ManifestExecutionFunction({
            executionSelector: this.checkResultEFPExternal.selector,
            isPublic: true,
            allowSharedValidation: false
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](1);

        bytes4[] memory allowedSelectors = new bytes4[](1);
        allowedSelectors[0] = RegularResultContract.foo.selector;
        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: address(REGULAR_RESULT_CONTRACT),
            permitAnySelector: false,
            selectors: allowedSelectors
        });

        return manifest;
    }

    function pluginMetadata() external pure override returns (PluginMetadata memory) {}
}
