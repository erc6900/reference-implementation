// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";
import {Test} from "forge-std/Test.sol";

import {KnownSelectors} from "../../src/helpers/KnownSelectors.sol";
import {IModule} from "../../src/interfaces/IModule.sol";

contract KnownSelectorsTest is Test {
    function test_isNativeFunction() public {
        assertTrue(KnownSelectors.isNativeFunction(IAccount.validateUserOp.selector));
    }

    function test_isErc4337Function() public {
        assertTrue(KnownSelectors.isErc4337Function(IPaymaster.validatePaymasterUserOp.selector));
    }

    function test_isIModuleFunction() public {
        assertTrue(KnownSelectors.isIModuleFunction(IModule.moduleId.selector));
    }
}
