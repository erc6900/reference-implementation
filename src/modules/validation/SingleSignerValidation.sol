// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IModule, ModuleManifest, ModuleMetadata} from "../../interfaces/IModule.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BaseModule} from "../BaseModule.sol";
import {ISingleSignerValidation} from "./ISingleSignerValidation.sol";

/// @title ECSDA Validation
/// @author ERC-6900 Authors
/// @notice This validation enables any ECDSA (secp256k1 curve) signature validation. It handles installation by
/// each entity (entityId).
/// Note: Uninstallation will NOT disable all installed validation entities. None of the functions are installed on
/// the account. Account states are to be retrieved from this global singleton directly.
///
/// - This validation supports ERC-1271. The signature is valid if it is signed by the owner's private key
/// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
/// owner (if the owner is a contract).
///
/// - This validation supports composition that other validation can relay on entities in this validation
/// to validate partially or fully.
contract SingleSignerValidation is ISingleSignerValidation, BaseModule {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string internal constant _NAME = "SingleSigner Validation";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(uint32 entityId => mapping(address account => address)) public signer;

    /// @inheritdoc ISingleSignerValidation
    function transferSigner(uint32 entityId, address newSigner) external {
        _transferSigner(entityId, newSigner);
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata data) external override {
        (uint32 entityId, address newSigner) = abi.decode(data, (uint32, address));
        _transferSigner(entityId, newSigner);
    }

    /// @inheritdoc IModule
    function onUninstall(bytes calldata data) external override {
        // ToDo: what does it mean in the world of composable validation world to uninstall one type of validation
        // We can either get rid of all SingleSigner signers. What about the nested ones?
        _transferSigner(abi.decode(data, (uint32)), address(0));
    }

    /// @inheritdoc ISingleSignerValidation
    function signerOf(uint32 entityId, address account) external view returns (address) {
        return signer[entityId][account];
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        // Validate the user op signature against the owner.
        (address sigSigner,,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (sigSigner == address(0) || sigSigner != signer[entityId][userOp.sender]) {
            return _SIG_VALIDATION_FAILED;
        }
        return _SIG_VALIDATION_PASSED;
    }

    /// @inheritdoc IValidation
    function validateRuntime(
        address account,
        uint32 entityId,
        address sender,
        uint256,
        bytes calldata,
        bytes calldata
    ) external view override {
        // Validate that the sender is the owner of the account or self.
        if (sender != signer[entityId][account]) {
            revert NotAuthorized();
        }
        return;
    }

    /// @inheritdoc IValidation
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does///*not** wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function validateSignature(address account, uint32 entityId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        if (SignatureChecker.isValidSignatureNow(signer[entityId][account], digest, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModule
    function moduleManifest() external pure override returns (ModuleManifest memory) {
        ModuleManifest memory manifest;
        return manifest;
    }

    /// @inheritdoc IModule
    function moduleMetadata() external pure virtual override returns (ModuleMetadata memory) {
        ModuleMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferSigner(uint32 entityId, address newSigner) internal {
        address previousSigner = signer[entityId][msg.sender];
        signer[entityId][msg.sender] = newSigner;
        emit SignerTransferred(msg.sender, entityId, previousSigner, newSigner);
    }
}
