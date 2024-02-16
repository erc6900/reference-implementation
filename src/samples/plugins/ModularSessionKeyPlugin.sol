// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {UpgradeableModularAccount} from "../../account/UpgradeableModularAccount.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
import {BasePlugin} from "../../plugins/BasePlugin.sol";
import {IModularSessionKeyPlugin} from "./interfaces/ISessionKeyPlugin.sol";
import {ISingleOwnerPlugin} from "../../plugins/owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../plugins/owner/SingleOwnerPlugin.sol";
import {PluginStorageLib, StoragePointer} from "../../libraries/PluginStorageLib.sol";

/// @title Modular Session Key Plugin
/// @author Decipher ERC-6900 Team
/// @notice This plugin allows some designated EOA or smart contract to temporarily
/// own a modular account. Note that this plugin is ONLY for demonstrating the purpose
/// of the functionalities of ERC-6900, and MUST not be used at the production level.
/// This modular session key plugin acts as a 'parent plugin' for all specific session
/// keys. Using dependency, this plugin can be thought as a parent contract that stores
/// session key duration information, and validation functions for session keys. All
/// logics for session keys will be implemented in child plugins.
/// It allows for session key owners to access MSCA both through user operation and
/// runtime, with its own validation functions.
/// Also, it has a dependency on SingleOwnerPlugin, to make sure that only the owner of
/// the MSCA can add or remove session keys.
contract ModularSessionKeyPlugin is BasePlugin, IModularSessionKeyPlugin {
    using ECDSA for bytes32;
    using PluginStorageLib for address;
    using PluginStorageLib for bytes;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    string public constant NAME = "Modular Session Key Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Decipher ERC-6900 Team";

    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    mapping(address account => EnumerableSet.Bytes32Set) private _sessionKeySet;

    struct SessionInfo {
        uint48 validAfter;
        uint48 validUntil;
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModularSessionKeyPlugin
    function addSessionKey(address sessionKey, bytes4 allowedSelector, uint48 validAfter, uint48 validUntil)
        external
    {
        _addSessionKey(msg.sender, sessionKey, allowedSelector, validAfter, validUntil);
        emit SessionKeyAdded(msg.sender, sessionKey, allowedSelector, validAfter, validUntil);
    }

    /// @inheritdoc IModularSessionKeyPlugin
    function removeSessionKey(address sessionKey, bytes4 allowedSelector) external {
        _removeSessionKey(msg.sender, sessionKey, allowedSelector);
        emit SessionKeyRemoved(msg.sender, sessionKey, allowedSelector);
    }

    /// @inheritdoc IModularSessionKeyPlugin
    function addSessionKeyBatch(
        address[] calldata sessionKeys,
        bytes4[] calldata allowedSelectors,
        uint48[] calldata validAfters,
        uint48[] calldata validUntils
    ) external {
        if (
            sessionKeys.length != allowedSelectors.length || sessionKeys.length != validAfters.length
                || sessionKeys.length != validUntils.length
        ) {
            revert WrongDataLength();
        }
        for (uint256 i = 0; i < sessionKeys.length;) {
            _addSessionKey(msg.sender, sessionKeys[i], allowedSelectors[i], validAfters[i], validUntils[i]);

            unchecked {
                ++i;
            }
        }
        emit SessionKeysAdded(msg.sender, sessionKeys, allowedSelectors, validAfters, validUntils);
    }

    function removeSessionKeyBatch(address[] calldata sessionKeys, bytes4[] calldata allowedSelectors) external {
        if (sessionKeys.length != allowedSelectors.length) {
            revert WrongDataLength();
        }
        for (uint256 i = 0; i < sessionKeys.length;) {
            _removeSessionKey(msg.sender, sessionKeys[i], allowedSelectors[i]);

            unchecked {
                ++i;
            }
        }
        emit SessionKeysRemoved(msg.sender, sessionKeys, allowedSelectors);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IModularSessionKeyPlugin
    function getSessionDuration(address account, address sessionKey, bytes4 allowedSelector)
        external
        view
        returns (uint48 validAfter, uint48 validUntil)
    {
        bytes memory key = account.allocateAssociatedStorageKey(0, 1);
        StoragePointer ptr = key.associatedStorageLookup(keccak256(abi.encodePacked(sessionKey, allowedSelector)));
        SessionInfo storage sessionInfo = _castPtrToStruct(ptr);
        validAfter = sessionInfo.validAfter;
        validUntil = sessionInfo.validUntil;
    }

    /// @inheritdoc IModularSessionKeyPlugin
    function getSessionKeysAndSelectors(address account)
        external
        view
        returns (address[] memory sessionKeys, bytes4[] memory selectors)
    {
        EnumerableSet.Bytes32Set storage sessionKeySet = _sessionKeySet[account];
        uint256 length = sessionKeySet.length();
        sessionKeys = new address[](length);
        selectors = new bytes4[](length);
        for (uint256 i = 0; i < length;) {
            (sessionKeys[i], selectors[i]) = _castToAddressAndBytes4(sessionKeySet.at(i));

            unchecked {
                ++i;
            }
        }
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {
        if (data.length != 0) {
            (
                address[] memory sessionKeys,
                bytes4[] memory allowedSelectors,
                uint48[] memory validAfters,
                uint48[] memory validUntils
            ) = abi.decode(data, (address[], bytes4[], uint48[], uint48[]));
            if (
                sessionKeys.length != allowedSelectors.length || sessionKeys.length != validAfters.length
                    || sessionKeys.length != validUntils.length
            ) {
                revert WrongDataLength();
            }
            for (uint256 i = 0; i < sessionKeys.length;) {
                _addSessionKey(msg.sender, sessionKeys[i], allowedSelectors[i], validAfters[i], validUntils[i]);

                unchecked {
                    ++i;
                }
            }
        }
    }

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {
        EnumerableSet.Bytes32Set storage sessionKeySet = _sessionKeySet[msg.sender];
        uint256 length = sessionKeySet.length();
        for (uint256 i = 0; i < length;) {
            (address sessionKey, bytes4 allowedSelecor) = _castToAddressAndBytes4(sessionKeySet.at(i));
            _removeSessionKey(msg.sender, sessionKey, allowedSelecor);

            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER)) {
            (address signer, ECDSA.RecoverError err) =
                userOpHash.toEthSignedMessageHash().tryRecover(userOp.signature);
            if (err != ECDSA.RecoverError.NoError) {
                revert InvalidSignature();
            }
            bytes4 selector = bytes4(userOp.callData[0:4]);
            bytes memory key = msg.sender.allocateAssociatedStorageKey(0, 1);
            StoragePointer ptr = key.associatedStorageLookup(keccak256(abi.encodePacked(signer, selector)));
            SessionInfo storage duration = _castPtrToStruct(ptr);
            uint48 validAfter = duration.validAfter;
            uint48 validUntil = duration.validUntil;

            return _packValidationData(validUntil == 0, validUntil, validAfter);
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
            bytes memory key = msg.sender.allocateAssociatedStorageKey(0, 1);
            StoragePointer ptr = key.associatedStorageLookup(keccak256(abi.encodePacked(sender, selector)));
            SessionInfo storage duration = _castPtrToStruct(ptr);
            uint48 validAfter = duration.validAfter;
            uint48 validUntil = duration.validUntil;

            if (validUntil != 0) {
                if (block.timestamp < validAfter || block.timestamp > validUntil) {
                    revert WrongTimeRangeForSession();
                }
                return;
            }
            revert NotAuthorized();
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](4);
        manifest.executionFunctions[0] = this.addSessionKey.selector;
        manifest.executionFunctions[1] = this.removeSessionKey.selector;
        manifest.executionFunctions[2] = this.addSessionKeyBatch.selector;
        manifest.executionFunctions[3] = this.removeSessionKeyBatch.selector;

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused.
            dependencyIndex: 0 // Used as first index.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](4);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKey.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKeyBatch.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKeyBatch.selector,
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

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKey.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKey.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.addSessionKeyBatch.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: this.removeSessionKeyBatch.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: this.getSessionDuration.selector,
            associatedFunction: alwaysAllowFunction
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(ISingleOwnerPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(ISingleOwnerPlugin).interfaceId;

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IModularSessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _addSessionKey(
        address account,
        address sessionKey,
        bytes4 allowedSelector,
        uint48 validAfter,
        uint48 validUntil
    ) internal {
        if (validUntil <= validAfter) {
            revert WrongTimeRangeForSession();
        }
        bytes memory key = account.allocateAssociatedStorageKey(0, 1);
        StoragePointer ptr = key.associatedStorageLookup(keccak256(abi.encodePacked(sessionKey, allowedSelector)));
        SessionInfo storage sessionInfo = _castPtrToStruct(ptr);
        sessionInfo.validAfter = validAfter;
        sessionInfo.validUntil = validUntil;

        EnumerableSet.Bytes32Set storage sessionKeySet = _sessionKeySet[account];
        sessionKeySet.add(_castToBytes32(sessionKey, allowedSelector));
    }

    function _removeSessionKey(address account, address sessionKey, bytes4 allowedSelector) internal {
        bytes memory key = account.allocateAssociatedStorageKey(0, 1);
        StoragePointer ptr = key.associatedStorageLookup(keccak256(abi.encodePacked(sessionKey, allowedSelector)));
        SessionInfo storage sessionInfo = _castPtrToStruct(ptr);
        sessionInfo.validAfter = 0;
        sessionInfo.validUntil = 0;

        EnumerableSet.Bytes32Set storage sessionKeySet = _sessionKeySet[account];
        sessionKeySet.remove(_castToBytes32(sessionKey, allowedSelector));
    }

    function _castPtrToStruct(StoragePointer ptr) internal pure returns (SessionInfo storage val) {
        assembly ("memory-safe") {
            val.slot := ptr
        }
    }

    function _castToBytes32(address addr, bytes4 b4) internal pure returns (bytes32 res) {
        assembly {
            res := or(shl(32, addr), b4)
        }
    }

    function _castToAddressAndBytes4(bytes32 b32) internal pure returns (address addr, bytes4 b4) {
        assembly {
            addr := shr(32, b32)
            b4 := and(b32, 0xFFFFFFFF)
        }
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter)
        internal
        pure
        returns (uint256)
    {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }
}
