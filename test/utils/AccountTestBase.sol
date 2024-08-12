// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {SemiModularAccount} from "../../src/account/SemiModularAccount.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {Call, IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {SingleSignerValidationModule} from "../../src/modules/validation/SingleSignerValidationModule.sol";

import {OptimizedTest} from "./OptimizedTest.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID as EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID} from
    "./TestConstants.sol";

import {SingleSignerFactoryFixture} from "../mocks/SingleSignerFactoryFixture.sol";

/// @dev This contract handles common boilerplate setup for tests using UpgradeableModularAccount with
/// SingleSignerValidationModule.
abstract contract AccountTestBase is OptimizedTest {
    using ModuleEntityLib for ModuleEntity;
    using MessageHashUtils for bytes32;

    EntryPoint public entryPoint;
    address payable public beneficiary;

    SingleSignerValidationModule public singleSignerValidationModule;
    SingleSignerFactoryFixture public factory;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    ModuleEntity internal _signerValidation;

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant GLOBAL_VALIDATION = 1;

    // Re-declare the constant to prevent derived test contracts from having to import it
    uint32 public constant TEST_DEFAULT_VALIDATION_ENTITY_ID = EXT_CONST_TEST_DEFAULT_VALIDATION_ENTITY_ID;

    uint256 public constant CALL_GAS_LIMIT = 100_000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1_200_000;

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    constructor() {
        entryPoint = new EntryPoint();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));

        address deployedSingleSignerValidation = address(_deploySingleSignerValidation());

        // We etch the single signer validation to the max address, such that it coincides with the fallback
        // validation module entity for semi modular account tests.
        singleSignerValidation = SingleSignerValidation(address(type(uint160).max));
        vm.etch(address(singleSignerValidation), deployedSingleSignerValidation.code);

        factory = new SingleSignerFactoryFixture(entryPoint, singleSignerValidation);

        account1 = factory.createAccount(owner1, 0);
        vm.deal(address(account1), 100 ether);

        _signerValidation =
            ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID);
    }

    function _runExecUserOp(address target, bytes memory callData) internal {
        _runUserOp(abi.encodeCall(IStandardExecutor.execute, (target, 0, callData)));
    }

    function _runExecUserOp(address target, bytes memory callData, bytes memory revertReason) internal {
        _runUserOp(abi.encodeCall(IStandardExecutor.execute, (target, 0, callData)), revertReason);
    }

    function _runExecBatchUserOp(Call[] memory calls) internal {
        _runUserOp(abi.encodeCall(IStandardExecutor.executeBatch, (calls)));
    }

    function _runExecBatchUserOp(Call[] memory calls, bytes memory revertReason) internal {
        _runUserOp(abi.encodeCall(IStandardExecutor.executeBatch, (calls)), revertReason);
    }

    function _runUserOp(bytes memory callData) internal {
        // Run user op without expecting a revert
        _runUserOp(callData, hex"");
    }

    function _runUserOp(bytes memory callData, bytes memory expectedRevertData) internal {
        uint256 nonce = entryPoint.getNonce(address(account1), 0);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: nonce,
            initCode: hex"",
            callData: callData,
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: hex"",
            signature: hex""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());

        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }
        entryPoint.handleOps(userOps, beneficiary);
    }

    function _runtimeExec(address target, bytes memory callData) internal {
        _runtimeCall(abi.encodeCall(IStandardExecutor.execute, (target, 0, callData)));
    }

    function _runtimeExec(address target, bytes memory callData, bytes memory expectedRevertData) internal {
        _runtimeCall(abi.encodeCall(IStandardExecutor.execute, (target, 0, callData)), expectedRevertData);
    }

    function _runtimeExecExpFail(address target, bytes memory callData, bytes memory expectedRevertData)
        internal
    {
        _runtimeCallExpFail(abi.encodeCall(IStandardExecutor.execute, (target, 0, callData)), expectedRevertData);
    }

    function _runtimeExecBatch(Call[] memory calls) internal {
        _runtimeCall(abi.encodeCall(IStandardExecutor.executeBatch, (calls)));
    }

    function _runtimeExecBatch(Call[] memory calls, bytes memory expectedRevertData) internal {
        _runtimeCall(abi.encodeCall(IStandardExecutor.executeBatch, (calls)), expectedRevertData);
    }

    function _runtimeExecBatchExpFail(Call[] memory calls, bytes memory expectedRevertData) internal {
        _runtimeCallExpFail(abi.encodeCall(IStandardExecutor.executeBatch, (calls)), expectedRevertData);
    }

    function _runtimeCall(bytes memory callData) internal {
        _runtimeCall(callData, "");
    }

    function _runtimeCall(bytes memory callData, bytes memory expectedRevertData) internal {
        if (expectedRevertData.length > 0) {
            vm.expectRevert(expectedRevertData);
        }

        vm.prank(owner1);
        account1.executeWithAuthorization(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    // Always expects a revert, even if the revert data is zero-length.
    function _runtimeCallExpFail(bytes memory callData, bytes memory expectedRevertData) internal {
        vm.expectRevert(expectedRevertData);

        vm.prank(owner1);
        account1.executeWithAuthorization(callData, _encodeSignature(_signerValidation, GLOBAL_VALIDATION, ""));
    }

    function _transferOwnershipToTest() internal {
        // Transfer ownership to test contract for easier invocation.
        vm.prank(owner1);
        if (vm.envBool("SMA_TEST")) {
            account1.executeWithAuthorization(
                abi.encodeCall(SemiModularAccount(payable(account1)).updateFallbackSigner, (address(this))),
                _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
            );
            return;
        }
        account1.executeWithAuthorization(
            abi.encodeCall(
                account1.execute,
                (
                    address(singleSignerValidation),
                    0,
                    abi.encodeCall(
                        SingleSignerValidation.transferSigner, (TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this))
                    )
                )
            ),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }

    // helper function to encode a signature, according to the per-hook and per-validation data format.
    function _encodeSignature(
        ModuleEntity validationFunction,
        uint8 globalOrNot,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction, globalOrNot);

        for (uint256 i = 0; i < preValidationHookData.length; ++i) {
            sig = abi.encodePacked(
                sig,
                _packValidationResWithIndex(
                    preValidationHookData[i].index, preValidationHookData[i].validationData
                )
            );
        }

        // Index of the actual validation data is the length of the preValidationHooksRetrieved - aka
        // one-past-the-end
        sig = abi.encodePacked(sig, _packValidationResWithIndex(255, validationData));

        return sig;
    }

    // overload for the case where there are no pre-validation hooks
    function _encodeSignature(ModuleEntity validationFunction, uint8 globalOrNot, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encodeSignature(validationFunction, globalOrNot, emptyPreValidationHookData, validationData);
    }

    // helper function to pack validation data with an index, according to the sparse calldata segment spec.
    function _packValidationResWithIndex(uint8 index, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint32(validationData.length + 1), index, validationData);
    }
}
