// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {UpgradeableModularAccount} from "./UpgradeableModularAccount.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModuleEntityLib} from "../helpers/ModuleEntityLib.sol";

import {IModuleManager, ModuleEntity, ValidationConfig} from "../interfaces/IModuleManager.sol";
import {IValidation} from "../interfaces/IValidation.sol";

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract SemiModularAccount is UpgradeableModularAccount {
    using MessageHashUtils for bytes32;
    using ModuleEntityLib for ModuleEntity;

    struct SemiModularAccountStorage {
        address fallbackSigner;
        bool fallbackSignerDisabled;
    }

    // keccak256("ERC6900.SemiModularAccount.Storage")
    uint256 constant _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT =
        0x5b9dc9aa943f8fa2653ceceda5e3798f0686455280432166ba472eca0bc17a32;

    ModuleEntity internal constant _FALLBACK_VALIDATION = ModuleEntity.wrap(bytes24(type(uint192).max));

    event FallbackSignerSet(address indexed previousFallbackSigner, address indexed newFallbackSigner);

    error FallbackSignerMismatch();
    error FallbackSignerDisabled();
    error InitializerDisabled();

    constructor(IEntryPoint anEntryPoint) UpgradeableModularAccount(anEntryPoint) {}

    function initializeWithValidation(ValidationConfig, bytes4[] calldata, bytes calldata, bytes[] calldata)
        external
        override
        initializer
    {
        revert InitializerDisabled();
    }

    function updateFallbackSigner(address fallbackSigner) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        emit FallbackSignerSet(_storage.fallbackSigner, fallbackSigner);
        _storage.fallbackSigner = fallbackSigner;
    }

    function setFallbackSignerEnabled(bool enabled) external wrapNativeFunction {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();
        _storage.fallbackSignerDisabled = !enabled;
        // TODO: event
    }

    function _exec1271Validation(ModuleEntity sigValidation, bytes32 hash, bytes calldata signature)
        internal
        view
        override
        returns (bytes4)
    {
        if (sigValidation.eq(_FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (SignatureChecker.isValidSignatureNow(fallbackSigner, hash, signature)) {
                return _1271_MAGIC_VALUE;
            }
            return _1271_INVALID;
        }
        return super._exec1271Validation(sigValidation, hash, signature);
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        if (userOpValidationFunction.eq(_FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (
                SignatureChecker.isValidSignatureNow(
                    fallbackSigner, userOpHash.toEthSignedMessageHash(), userOp.signature
                )
            ) {
                return _SIG_VALIDATION_PASSED;
            }
            return _SIG_VALIDATION_FAILED;
        }

        return super._execUserOpValidation(userOpValidationFunction, userOp, userOpHash);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        bytes calldata callData,
        bytes calldata authorization
    ) internal override {
        if (runtimeValidationFunction.eq(_FALLBACK_VALIDATION)) {
            address fallbackSigner = _getFallbackSigner();

            if (msg.sender != fallbackSigner) {
                revert FallbackSignerMismatch();
            }
            return;
        }
        super._execRuntimeValidation(runtimeValidationFunction, callData, authorization);
    }

    function _getFallbackSigner() internal view returns (address) {
        SemiModularAccountStorage storage _storage = _getSemiModularAccountStorage();

        if (_storage.fallbackSignerDisabled) {
            revert FallbackSignerDisabled();
        }

        address storageFallbackSigner = _storage.fallbackSigner;
        if (storageFallbackSigner != address(0)) {
            return storageFallbackSigner;
        }

        bytes memory appendedData = LibClone.argsOnERC1967(address(this), 0, 20);

        return address(uint160(bytes20(appendedData)));
    }

    function _globalValidationAllowed(bytes4 selector) internal view override returns (bool) {
        return selector == this.updateFallbackSigner.selector || super._globalValidationAllowed(selector);
    }

    // todo: remove storage from input
    function _isValidationGlobal(ModuleEntity validationFunction)
        internal
        view
        override
        returns (bool)
    {
        return
            validationFunction.eq(_FALLBACK_VALIDATION) || super._isValidationGlobal(validationFunction);
    }

    function _getSemiModularAccountStorage() internal pure returns (SemiModularAccountStorage storage) {
        SemiModularAccountStorage storage _storage;
        assembly ("memory-safe") {
            _storage.slot := _SEMI_MODULAR_ACCOUNT_STORAGE_SLOT
        }
        return _storage;
    }
}
