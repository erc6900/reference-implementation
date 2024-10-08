// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {AllowlistModule} from "../src/modules/permissions/AllowlistModule.sol";

contract DeployAllowlistModuleScript is Script {
    address public allowlistModule = vm.envOr("ALLOWLIST_MODULE", address(0));

    bytes32 public allowlistModuleSalt = bytes32(vm.envOr("ALLOWLIST_MODULE_SALT", uint256(0)));

    function run() public {
        console.log("******** Deploying AllowlistModule ********");
        console.log("Chain: ", block.chainid);

        vm.startBroadcast();
        _deployAllowlistModule(allowlistModuleSalt, allowlistModule);
        vm.stopBroadcast();
    }

    function _deployAllowlistModule(bytes32 salt, address expected) internal {
        console.log(string.concat("Deploying AllowlistModule with salt: ", vm.toString(salt)));

        address addr = Create2.computeAddress(salt, keccak256(type(AllowlistModule).creationCode), CREATE2_FACTORY);
        if (addr != expected) {
            console.log("Expected address mismatch");
            console.log("Expected: ", expected);
            console.log("Actual: ", addr);
            revert();
        }

        if (addr.code.length == 0) {
            console.log("No code found at expected address, deploying...");
            AllowlistModule deployed = new AllowlistModule{salt: salt}();

            if (address(deployed) != expected) {
                console.log("Deployed address mismatch");
                console.log("Expected: ", expected);
                console.log("Actual: ", address(deployed));
                revert();
            }

            console.log("Deployed AllowlistModule at: ", address(deployed));
        } else {
            console.log("Code found at expected address, skipping deployment");
        }
    }
}
