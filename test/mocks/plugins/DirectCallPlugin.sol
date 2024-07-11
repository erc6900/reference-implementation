// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ManifestExecutionFunction, PluginManifest, PluginMetadata} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";

import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {ResultCreatorPlugin} from "./ReturnDataPluginMocks.sol";

contract DirectCallPlugin is BasePlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.DirectCallSelectors = new bytes4[](1);
        manifest.DirectCallSelectors[0] = IStandardExecutor.execute.selector;

        return manifest;
    }

    function directCall() external returns (bytes memory) {
        return IStandardExecutor(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return hex"04546b";
    }

    function pluginMetadata() external pure override returns (PluginMetadata memory) {}
}
