// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IPlugin, PluginManifest, PluginMetadata} from "../interfaces/IPlugin.sol";

/// @title Base contract for plugins
/// @dev Implements ERC-165 to support IPlugin's interface, which is a requirement
/// for plugin installation. This also ensures that plugin interactions cannot
/// happen via the standard execution funtions `execute` and `executeBatch`.
abstract contract BasePlugin is ERC165, IPlugin {
    error NotImplemented();

    /// @inheritdoc IPlugin
    function onInstall(bytes calldata data) external virtual {
        (data);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function onUninstall(bytes calldata data) external virtual {
        (data);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function preUserOpValidationHook(UserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256)
    {
        (userOp, userOpHash);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash)
        external
        virtual
        returns (uint256)
    {
        (userOp, userOpHash);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function preRuntimeValidationHook(address sender, uint256 value, bytes calldata data) external virtual {
        (sender, value, data);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function validateRuntime(address sender, uint256 value, bytes calldata data) external virtual {
        (sender, value, data);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function preExecutionHook(address sender, uint256 value, bytes calldata data)
        external
        virtual
        returns (bytes memory)
    {
        (sender, value, data);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function postExecutionHook(bytes calldata preExecHookData) external virtual {
        (preExecHookData);
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function pluginManifest() external pure virtual returns (PluginManifest memory) {
        revert NotImplemented();
    }

    /// @inheritdoc IPlugin
    function pluginMetadata() external pure virtual returns (PluginMetadata memory);

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }
}
