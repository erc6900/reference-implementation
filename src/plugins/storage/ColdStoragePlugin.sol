// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
// import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC721} from "@openzeppelin/contracts/token/erc721/IERC721.sol";

import {IPluginManager} from "../../interfaces/IPluginManager.sol";
import {ManifestExecutionHook, PluginManifest, PluginMetadata} from "../../interfaces/IPlugin.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";
import {IColdStoragePlugin} from "./IColdStoragePlugin.sol";
import {IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";

/// @title Cold Storage Plugin
/// @author ERC-6900 Authors
/// @dev There is a limitation, you can't lock "all except N" tokens. TODO: Evaluate this since we're
/// using an install nonce, it could be doable.
contract ColdStoragePlugin is BasePlugin, IColdStoragePlugin, EIP712 {
    struct GlobalTokenLockInput {
        address token;
        address[] signers;
    }

    struct IndividualTokenLockInput {
        address token;
        uint256[] tokenIdsToLock;
        address[] signers;
    }

    struct AccountData {
        mapping(uint256 installNonce => mapping(address nftAddress => address[] signers)) globalTokenLockData;
        mapping(
            uint256 installNonce => mapping(address nftAddress => mapping(uint256 tokenId => address[] signers))
        ) individualTokenLockData;
        address[] uninstallSigners;
    }

    string public constant NAME = "Cold Storage Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint8 public constant EXECUTE_HOOK_FUNCTION_ID = 0;
    uint8 public constant EXECUTE_BATCH_HOOK_FUNCTION_ID = 1;

    bytes32 private constant UNINSTALL_TYPEHASH = keccak256("Uninstall(address account,uint256 accountNonce)");

    // State
    mapping(address account => uint256 installNonce) internal _accountInstallNonce;
    mapping(address account => AccountData accountData) internal _accountData;

    event GlobalTokenLock(address indexed account, address indexed token, address[] signers);
    event IndividualTokenLock(
        address indexed account, address indexed token, uint256 indexed tokenId, address[] signers
    );

    constructor() EIP712(NAME, VERSION) {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        uint256 accountNonce = ++_accountInstallNonce[msg.sender];

        (
            GlobalTokenLockInput[] memory globalInputs,
            IndividualTokenLockInput[] memory individualInputs,
            address[] memory uninstallSigners
        ) = abi.decode(data, (GlobalTokenLockInput[], IndividualTokenLockInput[], address[]));

        // Start with global token locks
        _installGlobalInputs(globalInputs, accountNonce);

        // Continue with individual token locks
        _installIndividualInputs(individualInputs, accountNonce);

        // Set the uninstall signers
        _accountData[msg.sender].uninstallSigners = uninstallSigners;
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata signatures) external view override {
        // TODO consider adding a deadline
        // TODO consider ensuring that the "main signer" is included, or use a M of N multisig structure
        uint256 uninstallSignersLength = _accountData[msg.sender].uninstallSigners.length;
        uint256 accountNonce = _accountInstallNonce[msg.sender];

        // Decode signatures from calldata
        bytes[] memory decodedSignatures = abi.decode(signatures, (bytes[]));

        // Assert length
        require(decodedSignatures.length == uninstallSignersLength, "Invalid number of signatures");

        bytes32 uninstallTypedDataHash = _getUninstallTypedDataHash(msg.sender, accountNonce);

        // Check signatures
        for (uint256 i = 0; i < uninstallSignersLength; ++i) {
            address signer = _accountData[msg.sender].uninstallSigners[i];
            //todo update to custom error
            require(
                SignatureChecker.isValidSignatureNow(signer, uninstallTypedDataHash, decodedSignatures[i]),
                "Uninstall signature verification failed"
            );
        }
    }

    function setIndividualTokenLock(address tokenAddress, uint256 tokenId, bool locked) external override {}

    function setGlobalTokenLock(address tokenAddress, bool locked) external override {}

    function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        override
        returns (bytes memory)
    {}

    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external override {}

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        // Goal: Install
        ManifestExecutionHook[] memory executionFunctions = new ManifestExecutionHook[](2);
        executionFunctions[0] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.execute.selector,
            functionId: EXECUTE_HOOK_FUNCTION_ID,
            isPreHook: true,
            isPostHook: false
        });
        executionFunctions[1] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.executeBatch.selector,
            functionId: EXECUTE_BATCH_HOOK_FUNCTION_ID,
            isPreHook: true,
            isPostHook: false
        });

        PluginManifest memory manifest;
        return manifest;
    }

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

    function _installGlobalInputs(GlobalTokenLockInput[] memory inputs, uint256 accountNonce) internal {
        for (uint256 i = 0; i < inputs.length; ++i) {
            GlobalTokenLockInput memory input = inputs[i];

            require(input.signers.length > 0, "Global input signers must be > 0");

            _accountData[msg.sender].globalTokenLockData[accountNonce][input.token] = input.signers;

            emit GlobalTokenLock(msg.sender, input.token, input.signers);
        }
    }

    function _installIndividualInputs(IndividualTokenLockInput[] memory inputs, uint256 accountNonce) internal {
        for (uint256 i = 0; i < inputs.length; ++i) {
            IndividualTokenLockInput memory input = inputs[i];

            require(input.signers.length > 0, "Individual input signers must be >0");

            for (uint256 j = 0; j < input.tokenIdsToLock.length; ++j) {
                _accountData[msg.sender].individualTokenLockData[accountNonce][input.token][input.tokenIdsToLock[j]]
                = input.signers;
            }
        }
    }

    function _getUninstallTypedDataHash(address account, uint256 accountNonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(UNINSTALL_TYPEHASH, account, accountNonce));
        return _hashTypedDataV4(structHash);
    }
}
