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
import {IPlugin} from "../../interfaces/IPlugin.sol";
import {BasePlugin, IERC165} from "../BasePlugin.sol";
import {IColdStoragePlugin} from "./IColdStoragePlugin.sol";

/// @title Cold Storage Plugin
/// @author ERC-6900 Authors
/// @dev There is a limitation, you can't lock "all except N" tokens. TODO: Evaluate this since we're
/// using an install nonce, it could be doable.
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

    struct GlobalTokenLockInput {
        address token;
        address[] signers;
    }

    struct IndividualTokenLockInput {
        address token;
        uint256[] tokenIdsToLock;
        address[] signers;
    }

    mapping(address account => uint256 installNonce) internal _accountInstallNonce;
    mapping(address account => mapping(uint256 installNonce => mapping(address nftAddress => address[] signers)))
        internal _globalTokenLockData;
    mapping(
        address account
            => mapping(
                uint256 installNonce
                    => mapping(address nftAddress => mapping(uint256 tokenId => address[] signers))
            )
    ) internal _individualTokenLockData;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        uint256 accountNonce = ++_accountInstallNonce[msg.sender];

        (GlobalTokenLockInput[] memory globalInputs, IndividualTokenLockInput[] memory individualInputs) =
            abi.decode(data, (GlobalTokenLockInput[], IndividualTokenLockInput[]));

        // Start with global token locks
        _installGlobalInputs(globalInputs, accountNonce);

        // Continue with individual token locks
        _installIndividualInputs(individualInputs, accountNonce);
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata) external override {}

    function setIndividualTokenLock(address tokenAddress, uint256 tokenId, bool locked) external override {}

    function setGlobalTokenLock(address tokenAddress, bool locked) external override {}

    function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
        external
        override
        returns (bytes memory)
    {}

    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external override {}
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

    function _installGlobalInputs(GlobalTokenLockInput[] memory inputs, uint256 accountNonce) internal {
        for (uint256 i = 0; i < inputs.length; ++i) {
            GlobalTokenLockInput memory input = inputs[i];

            require(input.signers.length > 0, "Global input signers must be > 0");
            require(
                _globalTokenLockData[msg.sender][accountNonce][input.token].length == 0,
                "Global input cannot override existing global input, remove it first"
            ); // This is to prevent doubles in the array for uninstallation

            _globalTokenLockData[msg.sender][accountNonce][input.token] = input.signers;
        }
    }

    function _installIndividualInputs(IndividualTokenLockInput[] memory inputs, uint256 accountNonce) internal {
        for (uint256 i = 0; i < inputs.length; ++i) {
            IndividualTokenLockInput memory input = inputs[i];

            require(input.signers.length > 0, "Individual input signers must be >0");
            require(
                _globalTokenLockData[msg.sender][accountNonce][input.token].length == 0,
                "Individual input cannot override global lock"
            );

            for (uint256 j = 0; j < input.tokenIdsToLock.length; ++j) {
                _individualTokenLockData[msg.sender][accountNonce][input.token][input.tokenIdsToLock[j]] =
                    input.signers;
            }
        }
    }
}
