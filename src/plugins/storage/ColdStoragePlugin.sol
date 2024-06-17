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
/// TODO: Handle approve as well
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

    // TODO: Consider a more explicit way to allow "all but N" token locks
    address public constant MAGIC_UNLOCK_SIGNER = address(0x4546b);

    uint8 public constant EXECUTE_HOOK_FUNCTION_ID = 0;
    uint8 public constant EXECUTE_BATCH_HOOK_FUNCTION_ID = 1;

    bytes32 private constant UNINSTALL_TYPEHASH =
        keccak256("Uninstall(address account,uint256 accountInstallNonce)");
    bytes32 private constant ALLOW_TRANSFER_TYPEHASH = keccak256(
        "AllowTransfer(address from,address to,address token,uint256 tokenId,uint256 accountTransferNonce)"
    );

    bytes4 private constant SAFE_TRANSFER_FROM_ONE_SELECTOR = 0x42842e0e;
    bytes4 private constant SAFE_TRANSFER_FROM_WITH_DATA_SIG = 0xb88d4fde;

    // State
    mapping(address account => uint256 installNonce) internal _accountInstallNonce;
    mapping(address account => mapping(address token => uint256 tokenNonce)) internal _accountTransferNonce;

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

        // Check signatures, they must be passed in order
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

    // TODO Consider not needing a signature for the sender, if they are an approved signer
    function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        if (EXECUTE_HOOK_FUNCTION_ID == functionId) {
            _handleExecute(data);
        } else if (EXECUTE_BATCH_HOOK_FUNCTION_ID == functionId) {} else {
            revert("Invalid functionId");
        }
    }

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

    /// In order:
    ///     1. Check if the token ID is individually UNLOCKED using the magic unlock signer.
    ///         - Yes: return an empty array
    ///         - No: Continue
    ///     2. Check if the token is individually locked
    ///         - Yes: return the array of signers
    ///         - No: Continue
    ///     3. Return the array of global signers (empty if unlocked)
    function _getTokenLockSigners(uint256 accountInstallNonce, address tokenAddress, uint256 tokenId)
        internal
        view
        returns (address[] memory)
    {
        address[] storage individualSigners =
            _accountData[msg.sender].individualTokenLockData[accountInstallNonce][tokenAddress][tokenId];
        uint256 individualLockLength = individualSigners.length;

        if (1 == individualLockLength) {
            if (MAGIC_UNLOCK_SIGNER == individualSigners[0]) {
                return new address[](0);
            }
        }

        if (0 < individualLockLength) {
            return individualSigners;
        }

        return _accountData[msg.sender].globalTokenLockData[accountInstallNonce][tokenAddress];
    }

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

    function _handleExecute(bytes calldata data) internal {
        (address target,, bytes memory innerCallData) = abi.decode(data[4:], (address, uint256, bytes));

        bytes4 selector = bytes4(innerCallData);

        if (IERC721.transferFrom.selector == selector) {
            uint256 tokenId = _extractTokenIdFromTransfer(innerCallData);
            address[] memory signers = _getTransferSigners(target, tokenId);
            if (0 == signers.length) {
                return; // Token is not locked
            }

            // bytes[] memory signatures = abi.decode()

            bytes memory encodedSignatures;

            // The offset of the signature is the length of the entire transferFrom call
            // So, we add the length of the call to the inner call data pointer.
            // This means that encodedSignatures is a pointer to the length of the signatures.
            assembly {
                encodedSignatures := add(innerCallData, 0x84)
            }

            //TODO verify signatures
        } else if (SAFE_TRANSFER_FROM_ONE_SELECTOR == selector) {}
    }

    function _getTransferSigners(address token, uint256 tokenId) internal view returns (address[] memory) {
        return _getTokenLockSigners(_accountInstallNonce[msg.sender], token, tokenId);
    }

    /// Assembly procedure:
    ///     1. The memory layout of the data parameter is (for all transfer functions):
    ///         - 0x00: length
    ///         - 0x20: function selector
    ///         - 0x24: from address
    ///         - 0x44: to address
    ///         - 0x64: token ID
    ///     2. Load the token ID from memory (offset 0x64)
    function _extractTokenIdFromTransfer(bytes memory data) internal pure returns (uint256 tokenId) {
        // This short-circuits if data passed isn't big enough to stop potentially undefined behavior
        require(data.length >= 0x84, "Invalid data length");
        assembly ("memory-safe") {
            tokenId := mload(add(data, 0x64))
        }
    }
}
