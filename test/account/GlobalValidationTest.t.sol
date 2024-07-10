// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {GlobalValidationFactoryFixture} from "../mocks/GlobalValidationFactoryFixture.sol";

contract GlobalValidationTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    GlobalValidationFactoryFixture public globalValidationFactoryFixture;

    address public ethRecipient;

    function setUp() public {
        globalValidationFactoryFixture = new GlobalValidationFactoryFixture(entryPoint, singleOwnerPlugin);

        account1 = UpgradeableModularAccount(payable(globalValidationFactoryFixture.getAddress(owner1, 0)));

        vm.deal(address(account1), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
    }

    function test_globalValidation_userOp_simple() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: abi.encodePacked(
                globalValidationFactoryFixture,
                abi.encodeCall(globalValidationFactoryFixture.createAccount, (owner1, 0))
            ),
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = _encodeSignature(_ownerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_globalValidation_runtime_simple() public {
        // Deploy the account first
        globalValidationFactoryFixture.createAccount(owner1, 0);

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(_ownerValidation, GLOBAL_VALIDATION, "")
        );

        assertEq(ethRecipient.balance, 2 wei);
    }
}
