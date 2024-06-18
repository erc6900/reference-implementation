// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {IAccount} from "@eth-infinitism/account-abstraction/interfaces/IAccount.sol";
import {IPaymaster} from "@eth-infinitism/account-abstraction/interfaces/IPaymaster.sol";

import {KnownSelectors} from "../../src/helpers/KnownSelectors.sol";
import {IPlugin} from "../../src/interfaces/IPlugin.sol";

contract KnownSelectorsTest is Test {
    function test_isNativeFunction() public {
        assertTrue(KnownSelectors.isNativeFunction(IAccount.validateUserOp.selector));
    }

    function test_isErc4337Function() public {
        assertTrue(KnownSelectors.isErc4337Function(IPaymaster.validatePaymasterUserOp.selector));
    }

    function test_isIPluginFunction() public {
        assertTrue(KnownSelectors.isIPluginFunction(IPlugin.pluginMetadata.selector));
    }
}
