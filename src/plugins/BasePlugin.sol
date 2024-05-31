// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ERC165, IERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IPlugin} from "../interfaces/IPlugin.sol";

/// @title Base contract for plugins
/// @dev Implements ERC-165 to support IPlugin's interface, which is a requirement
/// for plugin installation. This also ensures that plugin interactions cannot
/// happen via the standard execution funtions `execute` and `executeBatch`.
abstract contract BasePlugin is ERC165, IPlugin {
    error NotImplemented();

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
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }
}
