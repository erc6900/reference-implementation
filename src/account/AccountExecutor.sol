// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";

abstract contract AccountExecutor {
    error PluginExecutionDenied(address plugin);

    /// @dev If the target is a plugin (as determined by its support for the IPlugin interface), revert.
    /// This prevents the modular account from calling plugins (both installed and uninstalled) outside
    /// of the normal flow (via execution functions installed on the account), which could lead to data
    /// inconsistencies and unexpected behavior.
    /// @param target The address of the contract to call.
    /// @param value The value to send with the call.
    /// @param data The call data.
    /// @return result The return data of the call, or the error message from the call if call reverts.
    function _exec(address target, uint256 value, bytes memory data) internal returns (bytes memory result) {
        if (ERC165Checker.supportsInterface(target, type(IPlugin).interfaceId)) {
            revert PluginExecutionDenied(target);
        }

        bool success;
        (success, result) = target.call{value: value}(data);

        if (!success) {
            // Directly bubble up revert messages
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
