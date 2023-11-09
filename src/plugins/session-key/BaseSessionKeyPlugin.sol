
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {UpgradeableModularAccount} from "../../account/UpgradeableModularAccount.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction,
    ManifestExternalCallPermission
} from "../../interfaces/IPlugin.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {ISessionKeyPlugin} from "./interfaces/ISessionKeyPlugin.sol";
import {ISingleOwnerPlugin} from "../owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../owner/SingleOwnerPlugin.sol";

/// @title Base Session Key Plugin
/// @author Decipher ERC-6900 Team
/// @notice This plugin allows some designated EOA or smart contract to temporarily
/// own a modular account.
/// This base session key plugin acts as a 'parent plugin' for all specific session
/// keys. Using dependency, this plugin can be thought as a proxy contract that stores
/// session key duration information, but with validation functions for session keys.
///
/// It allows for session key owners to access MSCA both through user operation and 
/// runtime, with its own validation functions.

contract BaseSessionKeyPlugin is BasePlugin, ISessionKeyPlugin {
    using ECDSA for bytes32;

    string public constant NAME = "Base Session Key Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Decipher ERC-6900 Team";

    mapping(address => mapping(address => mapping(bytes4 => bytes))) internal _sessionInfo;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function addTemporaryOwner(address tempOwner, bytes4 allowedSelector, uint48 _after, uint48 _until) external {
        if (_until <= _after) {
            revert WrongTimeRangeForSession();
        }
        bytes memory sessionInfo = abi.encodePacked(_after, _until);
        _sessionInfo[msg.sender][tempOwner][allowedSelector] = sessionInfo;
        emit TemporaryOwnerAdded(msg.sender, tempOwner, allowedSelector, _after, _until);
    }

    /// @inheritdoc ISessionKeyPlugin
    function removeTemporaryOwner(address tempOwner, bytes4 allowedSelector) external {
        delete _sessionInfo[msg.sender][tempOwner][allowedSelector];
        emit TemporaryOwnerRemoved(msg.sender, tempOwner, allowedSelector);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function getSessionDuration(address account, address tempOwner, bytes4 allowedSelector) external view returns (uint48 _after, uint48 _until) {
        (_after, _until) = _decode(_sessionInfo[account][tempOwner][allowedSelector]);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER)) {
            bytes4 selector = bytes4(userOp.callData[0:4]);
            bytes memory duration = _sessionInfo[userOp.sender][signer][selector];
            if (duration.length != 0) {
                (uint48 _after, uint48 _until) = _decode(duration);
                // first parameter of _packValidationData is sigFailed, which should be false
                return _packValidationData(false, _until, _after);
            }
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata data)
        external
        view
        override
    {
        if (functionId == uint8(FunctionId.RUNTIME_VALIDATION_TEMPORARY_OWNER)) {
            bytes4 selector = bytes4(data[0:4]);
            bytes memory duration = _sessionInfo[msg.sender][sender][selector];
            if (duration.length != 0) {
                (uint48 _after, uint48 _until) = _decode(duration);
                if (block.timestamp < _after || block.timestamp > _until) {
                    revert WrongTimeRangeForSession();
                }
                return;
            }
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        string[] memory ownerPermissions = new string[](1);
        ownerPermissions[0] = "Allow Temporary Ownership";

        manifest.executionFunctions = new ManifestExecutionFunction[](3);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.addTemporaryOwner.selector, ownerPermissions);
        manifest.executionFunctions[1] =
            ManifestExecutionFunction(this.removeTemporaryOwner.selector, ownerPermissions);
        manifest.executionFunctions[2] =
            ManifestExecutionFunction(this.getSessionDuration.selector, new string[](0));

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Used as first index.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addTemporaryOwner.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeTemporaryOwner.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        
        ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused.
            dependencyIndex: 1
        });
        ManifestFunction memory alwaysAllowFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Unused.
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addTemporaryOwner.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeTemporaryOwner.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.getSessionDuration.selector,
            associatedFunction: alwaysAllowFunction
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(ISingleOwnerPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(ISingleOwnerPlugin).interfaceId;

        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _decode(bytes memory _data) internal pure returns (uint48 _after, uint48 _until) {
        assembly {
            _after := mload(add(_data, 0x06))
            _until := mload(add(_data, 0x0C))
        }
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }
}
