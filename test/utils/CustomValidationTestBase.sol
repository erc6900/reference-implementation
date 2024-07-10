// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {AccountTestBase} from "./AccountTestBase.sol";

/// @dev This test contract base is used to test custom validation logic.
/// To use this, override the _initialValidationConfig function to return the desired validation configuration.
/// Then, call _customValidationSetup in the test setup.
/// Make sure to do so after any state variables that `_initialValidationConfig` relies on are set.
abstract contract CustomValidationTestBase is AccountTestBase {
    function _customValidationSetup() internal {
        (
            FunctionReference validationFunction,
            bool shared,
            bytes4[] memory selectors,
            bytes memory installData,
            bytes memory preValidationHooks,
            bytes memory permissionHooks
        ) = _initialValidationConfig();

        address accountImplementation = address(factory.accountImplementation());

        account1 = UpgradeableModularAccount(payable(new ERC1967Proxy{salt: 0}(accountImplementation, "")));

        account1.initializeWithValidation(
            validationFunction, shared, selectors, installData, preValidationHooks, permissionHooks
        );

        vm.deal(address(account1), 100 ether);
    }

    function _initialValidationConfig()
        internal
        virtual
        returns (
            FunctionReference validationFunction,
            bool shared,
            bytes4[] memory selectors,
            bytes memory installData,
            bytes memory preValidationHooks,
            bytes memory permissionHooks
        );
}
