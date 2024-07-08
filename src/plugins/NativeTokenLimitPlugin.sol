// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@eth-infinitism/account-abstraction/core/UserOperationLib.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {PluginManifest, PluginMetadata} from "../interfaces/IPlugin.sol";
import {IStandardExecutor, Call} from "../interfaces/IStandardExecutor.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";
import {IExecutionHook} from "../interfaces/IExecutionHook.sol";
import {IValidationHook} from "../interfaces/IValidationHook.sol";
import {BasePlugin, IERC165} from "./BasePlugin.sol";

/// @title Native Token Limit Plugin
/// @author ERC-6900 Authors
/// @notice This plugin supports a single total native token spend limit.
/// It tracks a total spend limit across UserOperation gas limits and native token transfers.
/// If a paymaster is used, UO gas would not cause the limit to decrease.

contract NativeTokenLimitPlugin is BasePlugin, IExecutionHook, IValidationHook {
    using UserOperationLib for PackedUserOperation;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    string public constant NAME = "Native Token Limit";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    mapping(uint256 funcIds => mapping(address account => uint256 limit)) public limits;

    error ExceededNativeTokenLimit();
    error ExceededNumberOfEntities();

    function updateLimits(uint8 functionId, uint256 newLimit) external {
        limits[functionId][msg.sender] = newLimit;
    }

    /// @inheritdoc IValidationHook
    function preUserOpValidationHook(uint8 functionId, PackedUserOperation calldata userOp, bytes32)
        external
        returns (uint256)
    {
        // Decrease limit only if no paymaster is used
        if (userOp.paymasterAndData.length == 0) {
            uint256 vgl = UserOperationLib.unpackVerificationGasLimit(userOp);
            uint256 cgl = UserOperationLib.unpackCallGasLimit(userOp);
            uint256 totalGas = userOp.preVerificationGas + vgl + cgl;
            uint256 usage = totalGas * UserOperationLib.unpackMaxFeePerGas(userOp);

            uint256 limit = limits[functionId][msg.sender];
            if (usage > limit) {
                revert ExceededNativeTokenLimit();
            }
            limits[functionId][msg.sender] = limit - usage;
        }
        return 0;
    }

    /// @inheritdoc IExecutionHook
    function preExecutionHook(uint8 functionId, address, uint256, bytes calldata data)
        external
        override
        returns (bytes memory)
    {
        return _checkAndDecrementLimit(functionId, data);
    }

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external override {
        (uint8 startFunctionId, uint256[] memory spendLimits) = abi.decode(data, (uint8, uint256[]));

        if (startFunctionId + spendLimits.length > type(uint8).max) {
            revert ExceededNumberOfEntities();
        }

        for (uint256 i = 0; i < spendLimits.length; i++) {
            limits[i + startFunctionId][msg.sender] = spendLimits[i];
        }
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external override {
        // This is the highest functionId that's being used by the account
        uint8 functionId = abi.decode(data, (uint8));
        for (uint256 i = 0; i < functionId; i++) {
            delete limits[i][msg.sender];
        }
    }

    /// @inheritdoc IExecutionHook
    function postExecutionHook(uint8, bytes calldata) external pure override {
        revert NotImplemented();
    }

    // No implementation, no revert
    // Runtime spends no account gas, and we check native token spend limits in exec hooks
    function preRuntimeValidationHook(uint8 functionId, address, uint256, bytes calldata) external pure override {
        // silence warnings
        (functionId);
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        // silence warnings
        PluginManifest memory manifest;
        return manifest;
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        metadata.permissionRequest = new string[](2);
        metadata.permissionRequest[0] = "native-token-limit";
        metadata.permissionRequest[1] = "gas-limit";
        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override(BasePlugin, IERC165) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _checkAndDecrementLimit(uint8 functionId, bytes calldata data) internal returns (bytes memory) {
        (bytes4 selector, bytes memory callData) = _getSelectorAndCalldata(data);

        uint256 value;
        // Get value being sent
        if (selector == IStandardExecutor.execute.selector) {
            (, value) = abi.decode(callData, (address, uint256));
        } else if (selector == IStandardExecutor.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData, (Call[]));
            for (uint256 i = 0; i < calls.length; i++) {
                value += calls[i].value;
            }
        }

        uint256 limit = limits[functionId][msg.sender];
        if (value > limit) {
            revert ExceededNativeTokenLimit();
        }
        limits[functionId][msg.sender] = limit - value;

        return "";
    }
}
