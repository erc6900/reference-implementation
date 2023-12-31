// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

import {SimpleAccount} from "@eth-infinitism/account-abstraction/samples/SimpleAccount.sol";
import {SimpleAccountFactory} from "@eth-infinitism/account-abstraction/samples/SimpleAccountFactory.sol";

import {Counter} from "../mocks/Counter.sol";

contract CompareSimpleAccountTest is Test {
    using ECDSA for bytes32;

    EntryPoint public entryPoint;
    address payable public beneficiary;

    SimpleAccountFactory public factory;

    // Owner 1 deploys account contract in the same transaction
    address public owner1;
    uint256 public owner1Key;
    address public account1;

    // owner 2 pre-deploys account contract
    address public owner2;
    uint256 public owner2Key;
    address public account2;

    Counter public counter;

    function setUp() public {
        entryPoint = new EntryPoint();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);

        factory = new SimpleAccountFactory(entryPoint);
        account1 = factory.getAddress(owner1, 0);
        vm.deal(account1, 100 ether);

        counter = new Counter();
        counter.increment();

        // Pre-generate account 2
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        account2 = address(factory.createAccount(owner2, 0));
        vm.deal(account2, 100 ether);
        vm.prank(account2);
        entryPoint.depositTo{value: 1 wei}(account2);
    }

    function test_SimpleAccount_deploy_basicSend() public {
        UserOperation memory userOp = UserOperation({
            sender: account1,
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner1, 0))),
            callData: abi.encodeCall(SimpleAccount.execute, (beneficiary, 1, "")),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_deploy_empty() public {
        UserOperation memory userOp = UserOperation({
            sender: account1,
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner1, 0))),
            callData: "",
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_postDeploy_basicSend() public {
        UserOperation memory userOp = UserOperation({
            sender: account2,
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(SimpleAccount.execute, (beneficiary, 1, "")),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_SimpleAccount_postDeploy_contractInteraction() public {
        UserOperation memory userOp = UserOperation({
            sender: account2,
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                SimpleAccount.execute, (address(counter), 0, abi.encodeCall(Counter.increment, ()))
                ),
            callGasLimit: 5000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
    }
}
