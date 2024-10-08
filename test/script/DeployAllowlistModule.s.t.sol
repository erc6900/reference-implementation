// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployAllowlistModuleScript} from "../../script/DeployAllowlistModule.s.sol";

import {AllowlistModule} from "../../src/modules/permissions/AllowlistModule.sol";

contract DeployAllowlistModuleTest is Test {
    DeployAllowlistModuleScript internal _deployScript;

    address internal _allowlistModule;

    function setUp() public {
        _allowlistModule =
            Create2.computeAddress(bytes32(0), keccak256(type(AllowlistModule).creationCode), CREATE2_FACTORY);

        vm.setEnv("ALLOWLIST_MODULE", vm.toString(address(_allowlistModule)));

        _deployScript = new DeployAllowlistModuleScript();
    }

    function test_deployAllowlistModuleScript_run() public {
        _deployScript.run();

        assertTrue(_allowlistModule.code.length > 0, "AllowlistModule not deployed");
        assertEq(_allowlistModule.code, type(AllowlistModule).runtimeCode, "AllowlistModule runtime code mismatch");
    }
}
