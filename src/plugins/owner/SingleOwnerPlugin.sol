// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IPluginManager} from "../../interfaces/IPluginManager.sol";
import {IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {Signer} from "../../validators/ISignatureValidator.sol";
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
    string public constant NAME = "Single Owner Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    mapping(address => Signer) internal _owners;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISingleOwnerPlugin
    function transferOwnership(Signer calldata newOwner) external {
        _transferOwnership(newOwner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        _transferOwnership(abi.decode(data, (Signer)));
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata) external override {
        Signer memory empty;
        _transferOwnership(empty);
    }

    /// @inheritdoc IValidation
    function validateRuntime(uint8 functionId, address sender, uint256, bytes calldata) external view override {
        if (functionId == uint8(FunctionId.VALIDATION_OWNER_OR_SELF)) {
            // Validate that the sender is the owner of the account or self.
            if (sender != abi.decode(_owners[msg.sender].data, (address)) && sender != msg.sender) {
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
        if (functionId == uint8(FunctionId.VALIDATION_OWNER_OR_SELF)) {
            Signer memory signer = _owners[msg.sender];
            (bool isValid,) = signer.validator.validate(msg.sender, signer.data, userOpHash, userOp.signature);
            return isValid ? _SIG_VALIDATION_PASSED : _SIG_VALIDATION_FAILED;
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
        if (functionId == uint8(FunctionId.SIG_VALIDATION)) {
            Signer memory signer = _owners[msg.sender];
            (bool isValid,) = signer.validator.validate(msg.sender, signer.data, digest, signature);
            return isValid ? _1271_MAGIC_VALUE : _1271_INVALID;
        }
        revert NotImplemented();
    }

    /// @inheritdoc ISingleOwnerPlugin
    function owner() external view returns (Signer memory) {
        return _owners[msg.sender];
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISingleOwnerPlugin
    function ownerOf(address account) external view returns (Signer memory) {
        return _owners[account];
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        ManifestFunction memory ownerValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.VALIDATION_OWNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](5);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerValidationFunction
        });

        manifest.signatureValidationFunctions = new uint8[](1);
        manifest.signatureValidationFunctions[0] = uint8(FunctionId.SIG_VALIDATION);

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

    function _transferOwnership(Signer memory newOwner) internal {
        Signer memory previousOwner = _owners[msg.sender];
        _owners[msg.sender] = newOwner;
        emit OwnershipTransferred(msg.sender, previousOwner, newOwner);
    }
}
