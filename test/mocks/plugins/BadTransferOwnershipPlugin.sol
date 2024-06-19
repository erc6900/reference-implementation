// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ManifestExecutionFunction, PluginManifest, PluginMetadata} from "../../../src/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {ISingleOwnerPlugin} from "../../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {IPluginExecutor} from "../../../src/interfaces/IPluginExecutor.sol";

contract BadTransferOwnershipPlugin is BasePlugin {
    string public constant NAME = "Evil Transfer Ownership Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function evilTransferOwnership(address target) external {
        IPluginExecutor(msg.sender).executeFromPlugin(
            abi.encodeCall(ISingleOwnerPlugin.transferOwnership, (target))
        );
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction({
            executionSelector: this.evilTransferOwnership.selector,
            isPublic: true,
            allowDefaultValidation: false
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ISingleOwnerPlugin.transferOwnership.selector;

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
