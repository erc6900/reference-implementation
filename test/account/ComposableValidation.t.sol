// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ECDSAValidationPlugin} from "../../src/plugins/owner/ECDSAValidationPlugin.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {MultisigPlugin} from "../../src/plugins/owner/MultisigPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";

import {CustomValidationTestBase} from "../utils/CustomValidationTestBase.sol";

contract ComposableValidationTest is CustomValidationTestBase {
    using MessageHashUtils for bytes32;

    ECDSAValidationPlugin public ecdsaValidationPlugin;
    MultisigPlugin public multisigPlugin;

    function setUp() public {
        ecdsaValidationPlugin = new ECDSAValidationPlugin();
        multisigPlugin = new MultisigPlugin();

        _ownerValidation = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(123));
    }

    function test_basicUserOp_withECDSAValidation() public {
        _customValidationSetup();

        // Now that the account is set up with the ECDSAValidationPlugin, we can test the basic user op
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(IStandardExecutor.execute, (beneficiary, 0, hex"")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_basicUserOp_withComposableMultisig_oneLayer() public {
        (address owner2, uint256 owner2Key) = makeAddrAndKey("owner2");
        (address owner3, uint256 owner3Key) = makeAddrAndKey("owner3");

        _customValidationSetup();

        // Install the multisig plugin with signers 2 and 3

        FunctionReference composableMultisigValidation =
            FunctionReferenceLib.pack(address(multisigPlugin), uint8(0));
        FunctionReference owner2Validation = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(2));
        FunctionReference owner3Validation = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(3));

        FunctionReference[] memory multisigSigners = new FunctionReference[](2);
        multisigSigners[0] = owner2Validation;
        multisigSigners[1] = owner3Validation;

        // Set up the composable MultisigPlugin
        Call[] memory calls = new Call[](3);
        calls[0] = Call(
            address(ecdsaValidationPlugin),
            0,
            abi.encodeCall(ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(2), abi.encode(owner2))))
        );
        calls[1] = Call(
            address(ecdsaValidationPlugin),
            0,
            abi.encodeCall(ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(3), abi.encode(owner3))))
        );
        calls[2] = Call(
            address(account1),
            0,
            abi.encodeCall(
                UpgradeableModularAccount.installValidation,
                (
                    composableMultisigValidation,
                    true,
                    new bytes4[](0),
                    abi.encodePacked(uint8(0), abi.encode(multisigSigners)),
                    ""
                )
            )
        );

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, "")
        );

        // test the multisig validation

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(IStandardExecutor.execute, (beneficiary, 0, hex"")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        bytes memory owner2Signature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(owner3Key, userOpHash.toEthSignedMessageHash());
        bytes memory owner3Signature = abi.encodePacked(r, s, v);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = owner2Signature;
        signatures[1] = owner3Signature;

        userOp.signature =
            _encodeSignature(composableMultisigValidation, DEFAULT_VALIDATION, abi.encode(signatures));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_basicUserOp_withComposableMultisig_twoLayers() public {
        (address owner2, uint256 owner2Key) = makeAddrAndKey("owner2");
        (address owner3, uint256 owner3Key) = makeAddrAndKey("owner3");
        (address owner4, uint256 owner4Key) = makeAddrAndKey("owner4");

        _customValidationSetup();

        // create signers 2, 3, 4
        // Install the multisig plugin with [signer 2, another multisig [signer 3, signer 4]]

        // To prevent stack too deep, put it in memory.
        // 0 = outerMultisigValidation
        // 1 = owner2Validation
        // 2 = innerMultisigValidation
        // 3 = owner3Validation
        // 4 = owner4Validation

        FunctionReference[5] memory validations;

        validations[0] = FunctionReferenceLib.pack(address(multisigPlugin), uint8(0));
        validations[1] = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(2));
        validations[2] = FunctionReferenceLib.pack(address(multisigPlugin), uint8(1));
        validations[3] = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(3));
        validations[4] = FunctionReferenceLib.pack(address(ecdsaValidationPlugin), uint8(4));

        FunctionReference[] memory innerMultisigSigners = new FunctionReference[](2);
        innerMultisigSigners[0] = validations[3];
        innerMultisigSigners[1] = validations[4];

        FunctionReference[] memory outerMultisigSigners = new FunctionReference[](2);
        outerMultisigSigners[0] = validations[1];
        outerMultisigSigners[1] = validations[2];

        // Set up the ComposableMultisigPlugin
        Call[] memory calls = new Call[](5);
        calls[0] = Call(
            address(ecdsaValidationPlugin),
            0,
            abi.encodeCall(ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(2), abi.encode(owner2))))
        );
        calls[1] = Call(
            address(ecdsaValidationPlugin),
            0,
            abi.encodeCall(ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(3), abi.encode(owner3))))
        );
        calls[2] = Call(
            address(ecdsaValidationPlugin),
            0,
            abi.encodeCall(ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(4), abi.encode(owner4))))
        );
        calls[3] = Call(
            address(multisigPlugin),
            0,
            abi.encodeCall(
                ECDSAValidationPlugin.onInstall, (abi.encodePacked(uint8(1), abi.encode(innerMultisigSigners)))
            )
        );
        calls[4] = Call(
            address(account1),
            0,
            abi.encodeCall(
                UpgradeableModularAccount.installValidation,
                (
                    validations[0],
                    true,
                    new bytes4[](0),
                    abi.encodePacked(uint8(0), abi.encode(outerMultisigSigners)),
                    ""
                )
            )
        );

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, "")
        );

        // test the multisig of multisigs validation

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: hex"",
            callData: abi.encodeCall(IStandardExecutor.execute, (beneficiary, 0, hex"")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        bytes memory owner2Signature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(owner3Key, userOpHash.toEthSignedMessageHash());
        bytes memory owner3Signature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(owner4Key, userOpHash.toEthSignedMessageHash());
        bytes memory owner4Signature = abi.encodePacked(r, s, v);

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = owner3Signature;
        innerSignatures[1] = owner4Signature;

        bytes[] memory outerSignatures = new bytes[](2);
        outerSignatures[0] = owner2Signature;
        outerSignatures[1] = abi.encode(innerSignatures);

        userOp.signature = _encodeSignature(validations[0], DEFAULT_VALIDATION, abi.encode(outerSignatures));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function _initialValidationConfig()
        internal
        virtual
        override
        returns (FunctionReference, bool, bytes4[] memory, bytes memory, bytes memory)
    {
        return (
            _ownerValidation,
            true,
            new bytes4[](0),
            abi.encodePacked(uint8(123), abi.encode(owner1)),
            abi.encodePacked("")
        );
    }
}
