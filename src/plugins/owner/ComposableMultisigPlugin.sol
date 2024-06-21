// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {FunctionReference} from "../../helpers/FunctionReferenceLib.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {PluginManifest, PluginMetadata} from "../../interfaces/IPlugin.sol";

// Non-threshold based multisig plugin - all owners must sign.
// Supports up to 100 owners per id.
contract ComposableMultisigPlugin is IValidation, BasePlugin {
    struct OwnerInfo {
        uint256 length;
        FunctionReference[100] validations;
    }

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    mapping(uint8 id => mapping(address account => OwnerInfo)) public ownerInfo;

    error AlreadyInitialized();
    error NotAuthorized();
    error NotInitialized();
    error InvalidOwners();

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        uint8 id = uint8(bytes1(data[:1]));

        if (ownerInfo[id][msg.sender].length != 0) {
            revert AlreadyInitialized();
        }

        FunctionReference[] memory validations = abi.decode(data[1:], (FunctionReference[]));

        if (validations.length == 0 || validations.length > 100) {
            revert InvalidOwners();
        }

        ownerInfo[id][msg.sender].length = validations.length;

        for (uint256 i = 0; i < validations.length; i++) {
            ownerInfo[id][msg.sender].validations[i] = validations[i];
        }
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        uint8 id = uint8(bytes1(data[:1]));

        uint256 length = ownerInfo[id][msg.sender].length;

        if (length == 0) {
            revert NotInitialized();
        }

        for (uint256 i = 0; i < length; i++) {
            ownerInfo[id][msg.sender].validations[i] = FunctionReference.wrap(bytes21(0));
        }

        ownerInfo[id][msg.sender].length = 0;
    }

    /// @inheritdoc IValidation
    function validateUserOp(uint8 functionId, PackedUserOperation calldata, bytes32)
        external
        view
        override
        returns (uint256, bytes memory)
    {
        OwnerInfo storage info = ownerInfo[functionId][msg.sender];

        if (info.length == 0) {
            revert NotInitialized();
        }

        FunctionReference[] memory validations = new FunctionReference[](info.length);

        for (uint256 i = 0; i < info.length; i++) {
            validations[i] = info.validations[i];
        }

        return (_SIG_VALIDATION_PASSED, abi.encode(validations));
    }

    /// @inheritdoc IValidation
    function validateRuntime(uint8, address, uint256, bytes calldata, bytes calldata) external pure override {
        revert NotImplemented();
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
    function validateSignature(uint8, address, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    // solhint-disable-next-line no-empty-blocks
    function pluginManifest() external pure override returns (PluginManifest memory) {}

    /// @inheritdoc IPlugin
    // solhint-disable-next-line no-empty-blocks
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {}
}
