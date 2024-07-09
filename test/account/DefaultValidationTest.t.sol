// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {DefaultValidationFactoryFixture} from "../mocks/DefaultValidationFactoryFixture.sol";

contract DefaultValidationTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    DefaultValidationFactoryFixture public defaultValidationFactoryFixture;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;

    FunctionReference public ownerValidation;

    address public ethRecipient;

    function setUp() public {
        defaultValidationFactoryFixture = new DefaultValidationFactoryFixture(entryPoint, singleOwnerPlugin);

        account1 = UpgradeableModularAccount(payable(defaultValidationFactoryFixture.getAddress(owner1, 0)));

        vm.deal(address(account1), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);

        ownerValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER)
        );
    }

    function test_defaultValidation_userOp_simple() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: abi.encodePacked(
                defaultValidationFactoryFixture,
                abi.encodeCall(DefaultValidationFactoryFixture.createAccount, (owner1, 0))
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
        userOp.signature = _encodeSignature(ownerValidation, DEFAULT_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_defaultValidation_runtime_simple() public {
        // Deploy the account first
        defaultValidationFactoryFixture.createAccount(owner1, 0);

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(ownerValidation, DEFAULT_VALIDATION, "")
        );

        assertEq(ethRecipient.balance, 2 wei);
    }
}
