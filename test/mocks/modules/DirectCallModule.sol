// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {IExecutionHookModule} from "../../../src/interfaces/IExecutionHookModule.sol";
import {IModularAccount} from "../../../src/interfaces/IModularAccount.sol";
import {BaseModule} from "../../../src/modules/BaseModule.sol";

contract DirectCallModule is BaseModule, IExecutionHookModule {
    bool public preHookRan = false;
    bool public postHookRan = false;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function directCall() external returns (bytes memory) {
        return IModularAccount(msg.sender).execute(address(this), 0, abi.encodeCall(this.getData, ()));
    }

    function getData() external pure returns (bytes memory) {
        return hex"04546b";
    }

    function moduleId() external pure returns (string memory) {
        return "erc6900/direct-call-module/1.0.0";
    }

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
