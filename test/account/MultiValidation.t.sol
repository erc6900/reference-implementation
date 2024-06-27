// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {EcdsaValidationPlugin} from "../../src/plugins/validation/EcdsaValidationPlugin.sol";

contract MultiValidationTest is AccountTestBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    SingleOwnerPlugin public validator2;
    EcdsaValidationPlugin public ecdsaValidationPlugin;

    address public owner2;
    uint256 public owner2Key;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;

    function setUp() public {
        validator2 = new SingleOwnerPlugin();
        ecdsaValidationPlugin = new EcdsaValidationPlugin();

        (owner2, owner2Key) = makeAddrAndKey("owner2");
    }

    function test_overlappingValidationInstall() public {
        vm.prank(address(entryPoint));
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IStandardExecutor.execute.selector;
        FunctionReference validationFunction = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(0));
        account1.installValidation(
            bytes32(0), validationFunction, true, false, selectors, abi.encode(owner2), bytes("")
        );

        FunctionReference[] memory validations = account1.getValidations(IStandardExecutor.execute.selector);
        assertEq(validations.length, 1);
        assertEq(FunctionReference.unwrap(validations[0]), FunctionReference.unwrap(validationFunction));
    }

    function test_runtimeValidation_specify() public {
        test_overlappingValidationInstall();

        // Assert that the runtime validation can be specified.

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
                address(validator2),
                0,
                abi.encodeWithSignature("NotAuthorized()")
            )
        );
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(0), 0, "")),
            abi.encodePacked(
                address(validator2), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), DEFAULT_VALIDATION
            )
        );

        vm.prank(owner2);
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.execute, (address(0), 0, "")),
            abi.encodePacked(
                address(validator2), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), DEFAULT_VALIDATION
            )
        );
    }

    function test_userOpValidation_specify() public {
        test_overlappingValidationInstall();

        // Assert that the userOp validation can be specified.

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (address(0), 0, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(
            address(validator2),
            SELECTOR_ASSOCIATED_VALIDATION,
            uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER),
            r,
            s,
            v
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        // Sign with owner 1, expect fail

        userOp.nonce = 1;
        (v, r, s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature =
            abi.encodePacked(address(validator2), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), r, s, v);

        userOps[0] = userOp;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        entryPoint.handleOps(userOps, beneficiary);
    }
}
