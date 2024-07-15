// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IPlugin, PluginManifest, PluginMetadata} from "../../interfaces/IPlugin.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {IEcdsaValidation} from "./IEcdsaValidation.sol";

/// @title ECSDA Validation
/// @author ERC-6900 Authors
/// @notice This validation enables any ECDSA (secp256k1 curve) signature validation. It handles installation by
/// each entity (validationId). Uninstallation will NOT disable all installed validation entities. None of the
/// functions are installed on the account. Account states are to be retrieved from this global singleton directly.
/// Note: This validation also support composition that other validation can relay on entities in this validation
/// to validate partially or fully.
contract EcdsaValidation is IEcdsaValidation, BasePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Ecdsa Validation";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    mapping(uint32 validationId => mapping(address account => address)) public signer;

    /// @inheritdoc IEcdsaValidation
    function signerOf(uint32 validationId, address account) external view returns (address) {
        return signer[validationId][account];
    }

    /// @inheritdoc IEcdsaValidation
    function transferSigner(uint32 validationId, address newSigner) external {
        _transferSigner(validationId, newSigner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;
        return metadata;
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (uint32 validationId, address newSigner) = abi.decode(data, (uint32, address));
        _transferSigner(validationId, newSigner);
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        // ToDo: what does it mean in the world of composable validation world to uninstall one type of validation
        // We can either get rid of all Ecdsa signers. What about the nested ones?
        _transferSigner(abi.decode(data, (uint32)), address(0));
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint32 validationId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        // Validate the user op signature against the owner.
        (address sigSigner,,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (sigSigner == address(0) || sigSigner != signer[validationId][userOp.sender]) {
            return _SIG_VALIDATION_FAILED;
        }
        return _SIG_VALIDATION_PASSED;
    }

    /// @inheritdoc IValidation
    function validateRuntime(
        address account,
        uint32 validationId,
        address sender,
        uint256,
        bytes calldata,
        bytes calldata
    ) external view override {
        // Validate that the sender is the owner of the account or self.
        if (sender != signer[validationId][account]) {
            revert NotAuthorized();
        }
        return;
    }

    /// @inheritdoc IValidation
    function validateSignature(uint32, address, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert NotImplemented();
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferSigner(uint32 validationId, address newSigner) internal {
        address previousSigner = signer[validationId][msg.sender];
        signer[validationId][msg.sender] = newSigner;
        emit SignerTransferred(msg.sender, validationId, previousSigner, newSigner);
    }
}
