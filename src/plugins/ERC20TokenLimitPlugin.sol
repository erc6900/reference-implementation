// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SetValue, AssociatedLinkedListSet, AssociatedLinkedListSetLib} from "@modular-account-libs/libraries/AssociatedLinkedListSetLib.sol";

import {PluginManifest, PluginMetadata} from "../interfaces/IPlugin.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {BasePlugin, IERC165} from "./BasePlugin.sol";

/// @title ERC20 Token Limit Plugin
/// @author ERC-6900 Authors
/// @notice This plugin supports an ERC20 token spend limit. This should be combined with a contract whitelist
/// plugin to make sure that token transfers not tracked by the plugin don't happen.
/// Note: this plugin is opinionated on what selectors can be called for token contracts to guard against weird
/// edge cases like DAI. You wouldn't be able to use uni v2 pairs directly as the pair contract is also the LP
/// token contract
contract ERC20TokenLimitPlugin is BasePlugin, IExecutionHook {
    using UserOperationLib for PackedUserOperation;
    using EnumerableSet for EnumerableSet.AddressSet;
    using AssociatedLinkedListSetLib for AssociatedLinkedListSet;

    struct ERC20SpendLimit {
        address token;
        uint256[] limits;
    }

    string internal constant _NAME = "ERC20 Token Limit Plugin";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "ERC-6900 Authors";

    mapping(uint8 functionId => mapping(address token => mapping(address account => uint256 limit))) public limits;
    AssociatedLinkedListSet internal _tokenList;

    error ExceededTokenLimit();
    error ExceededNumberOfEntities();
    error SelectorNotAllowed();

    function getTokensForAccount(address account) external view returns (address[] memory tokens) {
        SetValue[] memory set = _tokenList.getAll(account);
        tokens = new address[](set.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i] = address(bytes20(bytes32(SetValue.unwrap(set[i]))));
        }
        return tokens;
    }

    function updateLimits(uint8 functionId, address token, uint256 newLimit) external {
        _tokenList.tryAdd(msg.sender, SetValue.wrap(bytes30(bytes20(token))));
        limits[functionId][token][msg.sender] = newLimit;
    }

    function _decrementLimit(uint8 functionId, address token, bytes memory innerCalldata) internal {
        bytes4 selector;
        uint256 spend;
        assembly {
            selector := mload(add(innerCalldata, 32)) // 0:32 is arr len, 32:36 is selector
            spend := mload(add(innerCalldata, 68)) // 36:68 is recipient, 68:100 is spend
        }
        // transfer.selector = 0xa9059cbb. Using `transfer.selector` causes solhint to throw a warning
        if (selector == 0xa9059cbb || selector == IERC20.approve.selector) {
            uint256 limit = limits[functionId][token][msg.sender];
            if (spend > limit) {
                revert ExceededTokenLimit();
            }
            limits[functionId][token][msg.sender] = limit - spend;
        } else {
            revert SelectorNotAllowed();
        }
    }

    /// @inheritdoc IExecutionHook
    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        if (selector == IStandardExecutor.execute.selector) {
            (address token,, bytes memory innerCalldata) = abi.decode(callData, (address, uint256, bytes));
            if (_tokenList.contains(msg.sender, SetValue.wrap(bytes30(bytes20(token))))) {
                _decrementLimit(functionId, token, innerCalldata);
            }
        } else if (selector == IStandardExecutor.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                if (_tokenList.contains(msg.sender, SetValue.wrap(bytes30(bytes20(calls[i].target))))) {
                    _decrementLimit(functionId, calls[i].target, calls[i].data);
                }
            }
        }

        return "";
    }

    /// @inheritdoc IExecutionHook
    function postExecutionHook(uint8, bytes calldata) external pure override {
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (uint8 startFunctionId, ERC20SpendLimit[] memory spendLimits) = abi.decode(data, (uint8, ERC20SpendLimit[]));

        if (startFunctionId + spendLimits.length > type(uint8).max) {
            revert ExceededNumberOfEntities();
        }

        for (uint8 i = 0; i < spendLimits.length; i++) {
            _tokenList.tryAdd(msg.sender, SetValue.wrap(bytes30(bytes20(spendLimits[i].token))));
            for (uint256 j = 0; j < spendLimits[i].limits.length; j++) {
                limits[i + startFunctionId][spendLimits[i].token][msg.sender] = spendLimits[i].limits[j];
            }
        }
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        (address token, uint8 functionId) = abi.decode(data, (address, uint8));
        delete limits[functionId][token][msg.sender];
    }

    /// @inheritdoc IPlugin
    // solhint-disable-next-line no-empty-blocks
    function pluginManifest() external pure override returns (PluginManifest memory) {}

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;

        metadata.permissionRequest = new string[](1);
        metadata.permissionRequest[0] = "erc20-token-limit";
        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
