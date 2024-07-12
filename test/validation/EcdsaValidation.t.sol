// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {PluginEntityLib} from "../../src/helpers/PluginEntityLib.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ID} from "../utils/TestConstants.sol";

contract EcdsaValidationTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    address public ethRecipient;
    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account;

    function setUp() public {
        ethRecipient = makeAddr("ethRecipient");
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        account = ecdsaFactory.createAccount(owner1, 0);
        vm.deal(address(account), 100 ether);
    }

    function test_userOpValidation() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
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
        userOp.signature = _encodeSignature(
            PluginEntityLib.pack(address(ecdsaValidation), TEST_DEFAULT_VALIDATION_ID),
            GLOBAL_VALIDATION,
            abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 1 wei);
    }

    function test_runtime() public {
        vm.prank(owner1);
        account.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                PluginEntityLib.pack(address(ecdsaValidation), TEST_DEFAULT_VALIDATION_ID), GLOBAL_VALIDATION, ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }

    function test_runtime_with2ndValidation() public {
        uint32 newValidationId = TEST_DEFAULT_OWNER_FUNCTION_ID + 1;
        vm.prank(address(entryPoint));
        account.installValidation(
            ValidationConfigLib.pack(address(ecdsaValidation), newValidationId, true, false),
            new bytes4[](0),
            abi.encode(newValidationId, owner2),
            "",
            ""
        );

        vm.prank(owner2);
        account.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                PluginEntityLib.pack(address(ecdsaValidation), newValidationId), GLOBAL_VALIDATION, ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }
}
