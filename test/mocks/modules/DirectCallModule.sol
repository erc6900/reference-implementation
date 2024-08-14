// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IExecutionHookModule} from "../../../src/interfaces/IExecutionHookModule.sol";
import {ModuleMetadata} from "../../../src/interfaces/IModule.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";

contract DirectCallModule is BaseModule, IExecutionHookModule {
    bool public preHookRan = false;
    bool public postHookRan = false;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function directCall() external returns (bytes memory) {
        return IStandardExecutor(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return hex"04546b";
    }

    function moduleMetadata() external pure override returns (ModuleMetadata memory) {}

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
