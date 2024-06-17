// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IPlugin, PluginManifest, ManifestExecutionHook, PluginMetadata} from "../interfaces/IPlugin.sol";
import {BasePlugin} from "./BasePlugin.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";

/// @title Cold Storage Plugin
/// @author ERC-6900 Authors
/// @notice This plugin allows modular accounts to add additional restrictions on transferring certain NFTs
contract ColdStoragePlugin is BasePlugin {
    using EnumerableSet for EnumerableSet.UintSet;

    struct ColdStorageStruct {
        address guardian;
        address isApprovedFor;
    }

    struct ToStoreStruct {
        address guardian;
        address nft;
        uint256 tokenId;
    }

    string public constant NAME = "Cold Storage Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    bytes4 internal constant _SAFE_TRANSFER_FROM_SELECTOR =
        bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
    bytes4 internal constant _SAFE_TRANSFER_FROM_WITH_DATA_SELECTOR =
        bytes4(keccak256("safeTransferFrom(address,address,uint256,bytes)"));

    mapping(address account => mapping(address nft => EnumerableSet.UintSet tokenIds)) internal _coldStorage;
    mapping(bytes32 id => ColdStorageStruct) public coldStorage;
    mapping(address guardian => uint256 nonce) public nonces;

    error ActionNotAllowed();
    error AlreadyInColdStorage();
    error NotGuardian();
    error SelectorNotAllowed();

    function addToColdStorage(address nft, uint256 tokenId, address guardian) external {
        bytes32 id = encodeId(msg.sender, nft, tokenId);
        ColdStorageStruct storage cs = coldStorage[id];
        if (cs.guardian != address(0)) {
            revert AlreadyInColdStorage();
        }
        _coldStorage[msg.sender][nft].add(tokenId);
        cs.guardian = guardian;
    }

    function unlock(address account, address nft, uint256 tokenId, address isApprovedFor, bytes calldata signature)
        external
    {
        bytes32 id = encodeId(account, nft, tokenId);
        ColdStorageStruct storage cs = coldStorage[id];
        address guardian = cs.guardian;
        if (
            guardian != msg.sender
                || SignatureChecker.isValidSignatureNow(
                    guardian,
                    encodeSignatureDigest(account, nft, tokenId, isApprovedFor, nonces[guardian]++),
                    signature
                )
        ) {
            revert NotGuardian();
        }
        cs.isApprovedFor = isApprovedFor;
    }

    function _checkColdStorage(address nft, bytes memory callData) internal view {
        bytes4 selector = bytes4(callData);
        if (selector == IERC721.setApprovalForAll.selector && _coldStorage[msg.sender][nft].length() > 0) {
            revert ActionNotAllowed();
        }
        if (selector == IERC721.approve.selector) {
            address to;
            uint256 tokenId;
            assembly {
                // callData = 32b length | 4b selector | 32b to | 32b tokenId
                to := mload(add(callData, 36))
                tokenId := mload(add(callData, 68))
            }
            bytes32 id = encodeId(msg.sender, nft, tokenId);
            if (coldStorage[id].isApprovedFor != to) {
                revert ActionNotAllowed();
            }
        } else if (
            selector == IERC721.transferFrom.selector || selector == _SAFE_TRANSFER_FROM_SELECTOR
                || selector == _SAFE_TRANSFER_FROM_WITH_DATA_SELECTOR
        ) {
            address to;
            uint256 tokenId;
            assembly {
                // callData = 32b length | 4b selector | 32b from | 32b to | 32b tokenId
                to := mload(add(callData, 68))
                tokenId := mload(add(callData, 100))
            }
            bytes32 id = encodeId(msg.sender, nft, tokenId);
            if (coldStorage[id].isApprovedFor != to) {
                revert ActionNotAllowed();
            }
        }
    }

    function preExecutionHook(uint8, bytes calldata data) external view returns (bytes memory) {
        bytes calldata topLevelCallData;
        bytes4 topLevelSelector;

        topLevelSelector = bytes4(data[52:56]);
        if (topLevelSelector == IAccountExecute.executeUserOp.selector) {
            topLevelCallData = data[56:];
            topLevelSelector = bytes4(topLevelCallData);
        } else {
            topLevelCallData = data[52:];
        }

        if (topLevelSelector == IStandardExecutor.execute.selector) {
            address token = address(uint160(uint256(bytes32(topLevelCallData[4:36]))));

            bytes calldata executeCalldata;
            uint256 offset = uint256(bytes32(topLevelCallData[68:100]));

            assembly {
                let relativeOffset := add(add(topLevelCallData.offset, offset), 4)
                executeCalldata.offset := add(relativeOffset, 32)
                executeCalldata.length := calldataload(relativeOffset)
            }

            _checkColdStorage(token, executeCalldata);
        } else if (topLevelSelector == IStandardExecutor.executeBatch.selector) {
            Call[] memory calls = abi.decode(topLevelCallData[4:], (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                _checkColdStorage(calls[i].target, calls[i].data);
            }
        }
        return "";
    }

    function encodeId(address account, address nft, uint256 tokenId) public pure returns (bytes32) {
        return keccak256(abi.encode(account, nft, tokenId));
    }

    function encodeSignatureDigest(
        address account,
        address nft,
        uint256 tokenId,
        address isApprovedFor,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(account, nft, tokenId, isApprovedFor, nonce));
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        ToStoreStruct[] memory toStore = abi.decode(data, (ToStoreStruct[]));
        for (uint256 i = 0; i < toStore.length; i++) {
            _coldStorage[msg.sender][toStore[i].nft].add(toStore[i].tokenId);
            coldStorage[encodeId(msg.sender, toStore[i].nft, toStore[i].tokenId)] =
                ColdStorageStruct({guardian: toStore[i].guardian, isApprovedFor: address(0)});
        }
    }

    /// @inheritdoc IPlugin
    /// @dev Accounts are expected to provide all the necessary data to remove the restrictions
    function onUninstall(bytes calldata data) external override {
        ToStoreStruct[] memory toStore = abi.decode(data, (ToStoreStruct[]));
        for (uint256 i = 0; i < toStore.length; i++) {
            _coldStorage[msg.sender][toStore[i].nft].remove(toStore[i].tokenId);
            delete coldStorage[encodeId(msg.sender, toStore[i].nft, toStore[i].tokenId)];
        }
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        // TODO: think it will be more efficient to attach hooks to `transfer.selector` etc
        // in execute and executeBatch, instead of calling hooks associated with those selectors, call them based
        // on selectors of msg.data[:4]
        manifest.executionHooks = new ManifestExecutionHook[](2);
        manifest.executionHooks[0] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.execute.selector,
            functionId: 0,
            isPreHook: true,
            isPostHook: false,
            requireUOContext: false
        });
        manifest.executionHooks[1] = ManifestExecutionHook({
            executionSelector: IStandardExecutor.executeBatch.selector,
            functionId: 0,
            isPreHook: true,
            isPostHook: false,
            requireUOContext: false
        });

        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;
        return metadata;
    }
}
