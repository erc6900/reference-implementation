// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {AccountFactory} from "../../src/account/AccountFactory.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountFactoryTest is AccountTestBase {
    AccountFactory internal _factory;
    UpgradeableModularAccount internal _account;

    function setUp() public {
        _account = new UpgradeableModularAccount(entryPoint);
        _factory = new AccountFactory(entryPoint, _account, address(singleSignerValidation));
    }

    function test_createAccount() public {
        UpgradeableModularAccount account = _factory.createAccount(address(this), 100, 0);

        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_createAccountAndGetAddress() public {
        UpgradeableModularAccount account = _factory.createAccount(address(this), 100, 0);

        assertEq(address(account), address(_factory.createAccount(address(this), 100, 0)));
    }

    function test_multipleDeploy() public {
        UpgradeableModularAccount account = _factory.createAccount(address(this), 100, 0);

        uint256 startGas = gasleft();

        UpgradeableModularAccount account2 = _factory.createAccount(address(this), 100, 0);

        // Assert that the 2nd deployment call cost less than 1 sstore
        // Implies that no deployment was done on the second calls
        assertLe(startGas - 22_000, gasleft());

        // Assert the return addresses are the same
        assertEq(address(account), address(account2));
    }
}
