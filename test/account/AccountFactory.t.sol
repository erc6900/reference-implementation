// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {AccountFactory} from "../../src/account/AccountFactory.sol";

import {ReferenceModularAccount} from "../../src/account/ReferenceModularAccount.sol";
import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract AccountFactoryTest is AccountTestBase {
    AccountFactory internal _factory;
    ReferenceModularAccount internal _account;
    SemiModularAccount internal _semiModularAccount;

    function setUp() public {
        _account = new ReferenceModularAccount(entryPoint);
        _semiModularAccount = new SemiModularAccount(entryPoint);

        _factory = new AccountFactory(
            entryPoint, _account, _semiModularAccount, address(singleSignerValidationModule), address(this)
        );
    }

    function test_createAccount() public {
        ReferenceModularAccount account = _factory.createAccount(address(this), 100, 0);

        assertEq(address(account.entryPoint()), address(entryPoint));
    }

    function test_createAccountAndGetAddress() public {
        ReferenceModularAccount account = _factory.createAccount(address(this), 100, 0);

        assertEq(address(account), address(_factory.createAccount(address(this), 100, 0)));
    }

    function test_multipleDeploy() public {
        ReferenceModularAccount account = _factory.createAccount(address(this), 100, 0);

        uint256 startGas = gasleft();

        ReferenceModularAccount account2 = _factory.createAccount(address(this), 100, 0);

        // Assert that the 2nd deployment call cost less than 1 sstore
        // Implies that no deployment was done on the second calls
        assertLe(startGas - 22_000, gasleft());

        // Assert the return addresses are the same
        assertEq(address(account), address(account2));
    }
}
