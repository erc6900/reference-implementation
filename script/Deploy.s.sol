// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/Test.sol";

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {AccountFactory} from "../src/account/AccountFactory.sol";
import {UpgradeableModularAccount} from "../src/account/UpgradeableModularAccount.sol";
import {SingleSignerValidation} from "../src/modules/validation/SingleSignerValidation.sol";

contract DeployScript is Script {
    IEntryPoint public entryPoint = IEntryPoint(payable(vm.envAddress("ENTRYPOINT")));

    address public owner = vm.envAddress("OWNER");

    address public accountImpl = vm.envOr("ACCOUNT_IMPL", address(0));
    address public factory = vm.envOr("FACTORY", address(0));
    address public singleSignerValidation = vm.envOr("SINGLE_SIGNER_VALIDATION", address(0));

    bytes32 public accountImplSalt = bytes32(vm.envOr("ACCOUNT_IMPL_SALT", uint256(0)));
    bytes32 public factorySalt = bytes32(vm.envOr("FACTORY_SALT", uint256(0)));
    bytes32 public singleSignerValidationSalt = bytes32(vm.envOr("SINGLE_SIGNER_VALIDATION_SALT", uint256(0)));

    uint256 public requiredStakeAmount = vm.envOr("STAKE_AMOUNT", uint256(0.1 ether));
    uint256 public requiredUnstakeDelay = vm.envOr("UNSTAKE_DELAY", uint256(1 days));

    function run() public {
        console2.log("******** Deploying ERC-6900 Reference Implementation ********");
        console2.log("Chain: ", block.chainid);
        console2.log("EP: ", address(entryPoint));
        console2.log("Factory owner: ", owner);

        _deployAccountImpl(accountImplSalt, accountImpl);
        _deploySingleSignerValidation(singleSignerValidationSalt, singleSignerValidation);
        _deployAccountFactory(factorySalt, factory);
        _addStakeForFactory(uint32(requiredUnstakeDelay), requiredStakeAmount);
    }

    function _deployAccountImpl(bytes32 salt, address expected) internal {
        console2.log(string.concat("Deploying AccountImpl with salt: ", vm.toString(salt)));

        address addr = Create2.computeAddress(
            salt, keccak256(abi.encodePacked(type(UpgradeableModularAccount).creationCode, abi.encode(entryPoint)))
        );
        if (addr != expected) {
            console2.log("Expected address mismatch");
            console2.log("Expected: ", expected);
            console2.log("Actual: ", addr);
            revert();
        }

        if (addr.code.length == 0) {
            console2.log("No code found at expected address, deploying...");
            UpgradeableModularAccount deployed = new UpgradeableModularAccount{salt: salt}(entryPoint);

            if (address(deployed) != expected) {
                console2.log("Deployed address mismatch");
                console2.log("Expected: ", expected);
                console2.log("Deployed: ", address(deployed));
                revert();
            }

            console2.log("Deployed AccountImpl at: ", address(deployed));
        } else {
            console2.log("Code found at expected address, skipping deployment");
        }
    }

    function _deploySingleSignerValidation(bytes32 salt, address expected) internal {
        console2.log(string.concat("Deploying SingleSignerValidation with salt: ", vm.toString(salt)));

        address addr =
            Create2.computeAddress(salt, keccak256(abi.encodePacked(type(SingleSignerValidation).creationCode)));
        if (addr != expected) {
            console2.log("Expected address mismatch");
            console2.log("Expected: ", expected);
            console2.log("Actual: ", addr);
            revert();
        }

        if (addr.code.length == 0) {
            console2.log("No code found at expected address, deploying...");
            SingleSignerValidation deployed = new SingleSignerValidation{salt: salt}();

            if (address(deployed) != expected) {
                console2.log("Deployed address mismatch");
                console2.log("Expected: ", expected);
                console2.log("Deployed: ", address(deployed));
                revert();
            }

            console2.log("Deployed SingleSignerValidation at: ", address(deployed));
        } else {
            console2.log("Code found at expected address, skipping deployment");
        }
    }

    function _deployAccountFactory(bytes32 salt, address expected) internal {
        console2.log(string.concat("Deploying AccountFactory with salt: ", vm.toString(salt)));

        address addr = Create2.computeAddress(
            salt,
            keccak256(
                abi.encodePacked(
                    type(AccountFactory).creationCode,
                    abi.encode(entryPoint, accountImpl, singleSignerValidation, owner)
                )
            )
        );
        if (addr != expected) {
            console2.log("Expected address mismatch");
            console2.log("Expected: ", expected);
            console2.log("Actual: ", addr);
            revert();
        }

        if (addr.code.length == 0) {
            console2.log("No code found at expected address, deploying...");
            AccountFactory deployed = new AccountFactory{salt: salt}(
                entryPoint, UpgradeableModularAccount(payable(accountImpl)), singleSignerValidation, owner
            );

            if (address(deployed) != expected) {
                console2.log("Deployed address mismatch");
                console2.log("Expected: ", expected);
                console2.log("Deployed: ", address(deployed));
                revert();
            }

            console2.log("Deployed AccountFactory at: ", address(deployed));
        } else {
            console2.log("Code found at expected address, skipping deployment");
        }
    }

    function _addStakeForFactory(uint32 unstakeDelay, uint256 stakeAmount) internal {
        console2.log("Adding stake to factory");

        uint256 currentStake = entryPoint.getDepositInfo(address(factory)).stake;
        console2.log("Current stake: ", currentStake);
        uint256 stakeToAdd = stakeAmount - currentStake;

        if (stakeToAdd > 0) {
            console2.log("Adding stake: ", stakeToAdd);
            entryPoint.addStake{value: stakeToAdd}(unstakeDelay);
            console2.log("Staked factory: ", address(factory));
            console2.log("Total stake amount: ", entryPoint.getDepositInfo(address(factory)).stake);
            console2.log("Unstake delay: ", entryPoint.getDepositInfo(address(factory)).unstakeDelaySec);
        } else {
            console2.log("No stake to add");
        }
    }
}
