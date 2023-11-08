// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

interface IPluginExecutor {
    /// @notice Method from calls made from plugins.
    /// @param data The call data for the call.
    /// @return The return data from the call.
    function executeFromPlugin(bytes calldata data) external payable returns (bytes memory);

    /// @notice Method from calls made from plugins.
    /// @dev If the target is a plugin, the call SHOULD revert.
    /// @param target The target of the external contract to be called.
    /// @param value The value to pass.
    /// @param data The data to pass.
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory);
}
