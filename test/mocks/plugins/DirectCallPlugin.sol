// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PluginManifest, PluginMetadata} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {IExecutionHook} from "../../../src/interfaces/IExecutionHook.sol";

import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";

contract DirectCallPlugin is BasePlugin, IExecutionHook {
    bool public preHookRan = false;
    bool public postHookRan = false;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {}

    function directCall() external returns (bytes memory) {
        return IStandardExecutor(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return hex"04546b";
    }

    function pluginMetadata() external pure override returns (PluginMetadata memory) {}

    function preExecutionHook(uint32, address sender, uint256, bytes calldata)
        external
        override
        returns (bytes memory)
    {
        require(sender == address(this), "mock direct call pre permission hook failed");
        preHookRan = true;
        return abi.encode(keccak256(hex"04546b"));
    }

    function postExecutionHook(uint32, bytes calldata preExecHookData) external override {
        require(
            abi.decode(preExecHookData, (bytes32)) == keccak256(hex"04546b"),
            "mock direct call post permission hook failed"
        );
        postHookRan = true;
    }
}
