// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC721} from "@openzeppelin/contracts/token/erc721/IERC721.sol";

import {IPluginManager} from "../../interfaces/IPluginManager.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../interfaces/IPlugin.sol";
// import {IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {IValidation} from "../../interfaces/IValidation.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";
import {IColdStoragePlugin} from "./IColdStoragePlugin.sol";

/// @title Cold Storage Plugin
/// @author ERC-6900 Authors
contract ColdStoragePlugin is BasePlugin, IColdStoragePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Cold Storage Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    struct TokenLockData {
        bool locked;
        address[] signers;
    }

    // Allows for easier uninstallation
    mapping(address account => TokenLockInput[]) internal _accountLockedTokens;

    mapping(address account => mapping(address nftAddress => TokenLockData tokenLockData)) internal
        _fullTokenLockData;
    mapping(address account => mapping(address nftAddress => mapping(uint256 tokenId => bool TokenLockData)))
        internal _individualTokenLockData;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    struct TokenLockInput {
        address token;
        bool shouldLockAll;
        uint256[] tokenIdsToLock;
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (TokenLockInput[] memory inputs) = abi.decode(data, (TokenLockInput[]));

        for (uint256 i = 0; i < inputs.length; ++i) {}
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata) external override {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {}

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        // Permission strings
        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        // return interfaceId == type(ColdStoragePlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    function validateUserOp(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {}

    function validateRuntime(
        uint8 functionId,
        address sender,
        uint256 value,
        bytes calldata data,
        bytes calldata authorization
    ) external override {}

    function validateSignature(uint8 functionId, address sender, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {}

    function setIndividualTokenLock(address tokenAddress, uint256 tokenId, bool locked) external override {}

    function setFullTokenock(address tokenAddress, bool locked) external override {}
}
