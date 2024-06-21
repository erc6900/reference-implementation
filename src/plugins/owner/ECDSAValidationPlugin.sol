// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";
import {
    PluginManifest,
    PluginMetadata
} from "../../interfaces/IPlugin.sol";

contract ECDSAValidationPlugin is IValidation, BasePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    error AlreadyInitialized();
    error NotAuthorized();
    error NotInitialized();

    mapping(uint8 id => mapping(address account => address)) public owners;

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {        
        uint8 id = uint8(bytes1(data[:1]));

        if (owners[id][msg.sender] != address(0)) {
            revert AlreadyInitialized();
        }

        address owner = abi.decode(data[1:], (address));
        owners[id][msg.sender] = owner;
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        uint8 id = uint8(bytes1(data[:1]));

        if (owners[id][msg.sender] == address(0)) {
            revert NotInitialized();
        }

        delete owners[id][msg.sender];
    }

    /// @inheritdoc IValidation
    function validateRuntime(uint8 functionId, address sender, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    {
        // Validate that the sender is the owner of the account or self.
        if (sender != owners[functionId][msg.sender]) {
            revert NotAuthorized();
        }
        return;
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256, bytes memory)
    {
        // Validate the user op signature against the owner.
        (address signer,,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (signer == address(0) || signer != owners[functionId][msg.sender]) {
            return (_SIG_VALIDATION_FAILED, "");
        }
        return (_SIG_VALIDATION_PASSED, "");
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IValidation
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does **not** wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function validateSignature(uint8 functionId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        if (digest.recover(signature) == owners[functionId][msg.sender]) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {}

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {}

}