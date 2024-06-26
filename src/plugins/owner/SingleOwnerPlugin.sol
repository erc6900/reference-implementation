// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IPluginManager} from "../../interfaces/IPluginManager.sol";
import {
    PluginManifest, ManifestValidation, PluginMetadata, SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";
import {ISingleOwnerPlugin} from "./ISingleOwnerPlugin.sol";

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
contract SingleOwnerPlugin is ISingleOwnerPlugin, BasePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Single Owner Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(address => address) internal _owners;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISingleOwnerPlugin
    function transferOwnership(address newOwner) external {
        _transferOwnership(newOwner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        _transferOwnership(abi.decode(data, (address)));
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata) external override {
        _transferOwnership(address(0));
    }

    /// @inheritdoc IValidation
    function validateRuntime(uint8 functionId, address sender, uint256, bytes calldata, bytes calldata)
        external
        view
        override
    {
        if (functionId == uint8(FunctionId.VALIDATION_OWNER)) {
            // Validate that the sender is the owner of the account or self.
            if (sender != _owners[msg.sender] && sender != msg.sender) {
                revert NotAuthorized();
            }
            return;
        }
        revert NotImplemented();
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.VALIDATION_OWNER)) {
            // Validate the user op signature against the owner.
            (address signer,,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
            if (signer == address(0) || signer != _owners[msg.sender]) {
                return _SIG_VALIDATION_FAILED;
            }
            return _SIG_VALIDATION_PASSED;
        }
        revert NotImplemented();
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
    function validateSignature(uint8 functionId, address, bytes32 digest, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        if (functionId == uint8(FunctionId.VALIDATION_OWNER)) {
            if (SignatureChecker.isValidSignatureNow(_owners[msg.sender], digest, signature)) {
                return _1271_MAGIC_VALUE;
            }
            return _1271_INVALID;
        }
        revert NotImplemented();
    }

    /// @inheritdoc ISingleOwnerPlugin
    function owner() external view returns (address) {
        return _owners[msg.sender];
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISingleOwnerPlugin
    function ownerOf(address account) external view returns (address) {
        return _owners[account];
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        // TODO: use default validation instead
        bytes4[] memory accountSelectors = new bytes4[](5);
        accountSelectors[0] = IStandardExecutor.execute.selector;
        accountSelectors[1] = IStandardExecutor.executeBatch.selector;
        accountSelectors[2] = IPluginManager.installPlugin.selector;
        accountSelectors[3] = IPluginManager.uninstallPlugin.selector;
        accountSelectors[4] = UUPSUpgradeable.upgradeToAndCall.selector;

        ManifestValidation memory ownerValidationFunction = ManifestValidation({
            functionId: uint8(FunctionId.VALIDATION_OWNER),
            isDefault: false,
            isSignatureValidation: true,
            selectors: accountSelectors
        });

        manifest.validationFunctions = new ManifestValidation[](1);
        manifest.validationFunctions[0] = ownerValidationFunction;

        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

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
        return interfaceId == type(ISingleOwnerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferOwnership(address newOwner) internal {
        address previousOwner = _owners[msg.sender];
        _owners[msg.sender] = newOwner;
        emit OwnershipTransferred(msg.sender, previousOwner, newOwner);
    }
}
