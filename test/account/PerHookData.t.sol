// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";

import {MockAccessControlHookPlugin} from "../mocks/plugins/MockAccessControlHookPlugin.sol";
import {Counter} from "../mocks/Counter.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PerHookDataTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    MockAccessControlHookPlugin internal _accessControlHookPlugin;

    Counter internal _counter;

    FunctionReference internal _ownerValidation;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;

    function setUp() public {
        _counter = new Counter();

        _accessControlHookPlugin = new MockAccessControlHookPlugin();

        // Write over `account1` with a new account proxy, with different initialization.

        address accountImplementation = address(factory.accountImplementation());

        account1 = UpgradeableModularAccount(payable(new ERC1967Proxy(accountImplementation, "")));

        _ownerValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER)
        );

        FunctionReference accessControlHook = FunctionReferenceLib.pack(
            address(_accessControlHookPlugin), uint8(MockAccessControlHookPlugin.FunctionId.PRE_VALIDATION_HOOK)
        );

        FunctionReference[] memory preValidationHooks = new FunctionReference[](1);
        preValidationHooks[0] = accessControlHook;

        bytes[] memory preValidationHookData = new bytes[](1);
        // Access control is restricted to only the _counter
        preValidationHookData[0] = abi.encode(_counter);

        bytes memory packedPreValidationHooks = abi.encode(preValidationHooks, preValidationHookData);

        vm.prank(address(entryPoint));
        account1.installValidation(
            _ownerValidation, true, new bytes4[](0), abi.encode(owner1), packedPreValidationHooks, ""
        );

        vm.deal(address(account1), 100 ether);
    }

    function test_passAccessControl_userOp() public {
        assertEq(_counter.number(), 0);

        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _ownerValidation, DEFAULT_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_badSigData_userOp() public {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({
            index: 0,
            validationData: abi.encodePacked(address(0x1234123412341234123412341234123412341234))
        });

        userOp.signature = _encodeSignature(
            _ownerValidation, DEFAULT_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failAccessControl_noSigData_userOp() public {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failAccessControl_badIndexProvided_userOp() public {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        userOp.signature = _encodeSignature(
            _ownerValidation, DEFAULT_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(UpgradeableModularAccount.ValidationSignatureSegmentMissing.selector)
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    // todo: index out of order failure case with 2 pre hooks

    function test_failAccessControl_badTarget_userOp() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (beneficiary, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(beneficiary)});

        userOp.signature = _encodeSignature(
            _ownerValidation, DEFAULT_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSignature("Error(string)", "Target not allowed")
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_failPerHookData_nonCanonicalEncoding_userOp() public {
        (PackedUserOperation memory userOp, bytes32 userOpHash) = _getCounterUserOP();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: ""});

        userOp.signature = _encodeSignature(
            _ownerValidation, DEFAULT_VALIDATION, preValidationHookData, abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(UpgradeableModularAccount.NonCanonicalEncoding.selector)
            )
        );
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_passAccessControl_runtime() public {
        assertEq(_counter.number(), 0);

        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, preValidationHookData, "")
        );

        assertEq(_counter.number(), 1);
    }

    function test_failAccessControl_badSigData_runtime() public {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({
            index: 0,
            validationData: abi.encodePacked(address(0x1234123412341234123412341234123412341234))
        });

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                _accessControlHookPlugin,
                uint8(MockAccessControlHookPlugin.FunctionId.PRE_VALIDATION_HOOK),
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        account1.executeWithAuthorization(
            abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, preValidationHookData, "")
        );
    }

    function test_failAccessControl_noSigData_runtime() public {
        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                _accessControlHookPlugin,
                uint8(MockAccessControlHookPlugin.FunctionId.PRE_VALIDATION_HOOK),
                abi.encodeWithSignature("Error(string)", "Proof doesn't match target")
            )
        );
        account1.executeWithAuthorization(
            abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, "")
        );
    }

    function test_failAccessControl_badIndexProvided_runtime() public {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](2);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(_counter)});
        preValidationHookData[1] = PreValidationHookData({index: 1, validationData: abi.encodePacked(_counter)});

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(UpgradeableModularAccount.ValidationSignatureSegmentMissing.selector)
        );
        account1.executeWithAuthorization(
            abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, preValidationHookData, "")
        );
    }

    //todo: index out of order failure case with 2 pre hooks

    function test_failAccessControl_badTarget_runtime() public {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: abi.encodePacked(beneficiary)});

        vm.prank(owner1);
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.PreRuntimeValidationHookFailed.selector,
                _accessControlHookPlugin,
                uint8(MockAccessControlHookPlugin.FunctionId.PRE_VALIDATION_HOOK),
                abi.encodeWithSignature("Error(string)", "Target not allowed")
            )
        );
        account1.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (beneficiary, 1 wei, "")),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, preValidationHookData, "")
        );
    }

    function test_failPerHookData_nonCanonicalEncoding_runtime() public {
        PreValidationHookData[] memory preValidationHookData = new PreValidationHookData[](1);
        preValidationHookData[0] = PreValidationHookData({index: 0, validationData: ""});

        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(UpgradeableModularAccount.NonCanonicalEncoding.selector));
        account1.executeWithAuthorization(
            abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            _encodeSignature(_ownerValidation, DEFAULT_VALIDATION, preValidationHookData, "")
        );
    }

    function _getCounterUserOP() internal view returns (PackedUserOperation memory, bytes32) {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                UpgradeableModularAccount.execute, (address(_counter), 0 wei, abi.encodeCall(Counter.increment, ()))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        return (userOp, userOpHash);
    }
}
