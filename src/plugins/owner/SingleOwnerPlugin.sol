// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {PluginManifest, PluginMetadata, SelectorPermission} from "../../interfaces/IPlugin.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";

/// @title Single Owner Plugin
/// @author ERC-6900 Authors
/// @notice This plugin allows an EOA or smart contract to own a modular account.
/// It also supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the owner of
/// modular account also support ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be
/// used as owners to validate user operation signatures. For example, the
/// contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967
/// proxy as it accesses a constant implementation slot not associated with
/// the account, violating storage access rules. This also means that the
/// owner of a modular account may not be another modular account if you want to
/// send user operations through a bundler.
contract SingleOwnerPlugin is IValidation, BasePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string internal constant _NAME = "Single Owner Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(uint32 id => mapping(address account => address)) public owners;

    /// @notice This event is emitted when ownership of the account changes.
    /// @param account The account whose ownership changed.
    /// @param previousOwner The address of the previous owner.
    /// @param newOwner The address of the new owner.
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    error AlreadyInitialized();
    error NotAuthorized();
    error NotInitialized();

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @notice Transfer ownership of an account and ID to `newOwner`. The caller address (`msg.sender`) is user to
    /// identify the account.
    /// @param newOwner The address of the new owner.
    function transferOwnership(uint32 id, address newOwner) external {
        _transferOwnership(id, newOwner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (uint32 id, address owner) = abi.decode(data, (uint32, address));
        _transferOwnership(id, owner);
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        uint32 id = abi.decode(data, (uint32));
        _transferOwnership(id, address(0));
    }

    /// @inheritdoc IValidation
    function validateRuntime(uint32 entityId, address sender, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    {
        // Validate that the sender is the owner of the account or self.
        if (sender != owners[entityId][msg.sender]) {
            revert NotAuthorized();
        }
        return;
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint32 entityId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        // Validate the user op signature against the owner.
        if (
            SignatureChecker.isValidSignatureNow(
                owners[entityId][msg.sender], userOpHash.toEthSignedMessageHash(), userOp.signature
            )
        ) {
            return _SIG_VALIDATION_PASSED;
        }
        return _SIG_VALIDATION_FAILED;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IValidation
    /// @dev The signature is valid if it is signed by the owner's private key
    /// (if the owner is an EOA) or if it is a valid ERC-1271 signature from the
    /// owner (if the owner is a contract). Note that unlike the signature
    /// validation used in `validateUserOp`, this does///*not** wrap the digest in
    /// an "Ethereum Signed Message" envelope before checking the signature in
    /// the EOA-owner case.
    function validateSignature(uint32 entityId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        if (SignatureChecker.isValidSignatureNow(owners[entityId][msg.sender], digest, signature)) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Ownership";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.transferOwnership.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        return interfaceId == type(IValidation).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // Transfers ownership and emits and event.
    function _transferOwnership(uint32 id, address newOwner) internal {
        address previousOwner = owners[id][msg.sender];
        owners[id][msg.sender] = newOwner;
        // Todo: include id in event
        emit OwnershipTransferred(msg.sender, previousOwner, newOwner);
    }
}
