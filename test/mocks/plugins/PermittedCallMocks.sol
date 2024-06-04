// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ManifestExecutionFunction, PluginManifest, PluginMetadata} from "../../../src/interfaces/IPlugin.sol";

import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {ResultCreatorPlugin} from "./ReturnDataPluginMocks.sol";

contract PermittedCallerPlugin is BasePlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0].executionSelector = this.usePermittedCallAllowed.selector;
        manifest.executionFunctions[1].executionSelector = this.usePermittedCallNotAllowed.selector;

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.executionFunctions[i].isPublic = true;
        }

        // Request permission only for "foo", but not "bar", from ResultCreatorPlugin
        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        return manifest;
    }

    function pluginMetadata() external pure override returns (PluginMetadata memory) {}

    // The manifest requested access to use the plugin-defined method "foo"
    function usePermittedCallAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorPlugin(msg.sender).foo());
    }

    // The manifest has not requested access to use the plugin-defined method "bar", so this should revert.
    function usePermittedCallNotAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorPlugin(msg.sender).bar());
    }
}
