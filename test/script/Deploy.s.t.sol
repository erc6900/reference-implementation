// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {DeployScript} from "../../script/Deploy.s.sol";

import {AccountFactory} from "../../src/account/AccountFactory.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleSignerValidation} from "../../src/modules/validation/SingleSignerValidation.sol";

contract DeployTest is Test {
    DeployScript internal _deployScript;

    EntryPoint internal _entryPoint;

    address internal _owner;

    address internal _accountImpl;
    address internal _singleSignerValidation;
    address internal _factory;

    function setUp() public {
        _entryPoint = new EntryPoint();
        _owner = makeAddr("OWNER");

        vm.setEnv("ENTRYPOINT", vm.toString(address(_entryPoint)));
        vm.setEnv("OWNER", vm.toString(_owner));

        _accountImpl = Create2.computeAddress(
            bytes32(0),
            keccak256(
                abi.encodePacked(type(UpgradeableModularAccount).creationCode, abi.encode(address(_entryPoint)))
            ),
            CREATE2_FACTORY
        );

        _singleSignerValidation = Create2.computeAddress(
            bytes32(0), keccak256(abi.encodePacked(type(SingleSignerValidation).creationCode)), CREATE2_FACTORY
        );

        _factory = Create2.computeAddress(
            bytes32(0),
            keccak256(
                abi.encodePacked(
                    type(AccountFactory).creationCode,
                    abi.encode(address(_entryPoint), _accountImpl, _singleSignerValidation, _owner)
                )
            ),
            CREATE2_FACTORY
        );

        vm.setEnv("ACCOUNT_IMPL", vm.toString(address(_accountImpl)));
        vm.setEnv("FACTORY", vm.toString(address(_factory)));
        vm.setEnv("SINGLE_SIGNER_VALIDATION", vm.toString(address(_singleSignerValidation)));

        vm.setEnv("ACCOUNT_IMPL_SALT", vm.toString(uint256(0)));
        vm.setEnv("FACTORY_SALT", vm.toString(uint256(0)));
        vm.setEnv("SINGLE_SIGNER_VALIDATION_SALT", vm.toString(uint256(0)));

        _deployScript = new DeployScript();

        vm.deal(address(_deployScript), 0.1 ether);
    }

    function test_deployScript_run() public {
        _deployScript.run();

        assertTrue(_accountImpl.code.length > 0);
        assertTrue(_factory.code.length > 0);
        assertTrue(_singleSignerValidation.code.length > 0);
    }
}
