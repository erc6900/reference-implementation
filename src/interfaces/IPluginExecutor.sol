// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

interface IPluginExecutor {
    /// @notice Executes a call from a plugin to another plugin.
    /// @dev Permissions must be granted to the calling plugin for the call to go through.
    /// @param data calldata to send to the plugin
    /// @return The result of the call
    function executeFromPlugin(bytes calldata data) external payable returns (bytes memory);

    /// @notice Executes a call from a plugin to a non-plugin address.
    /// @dev Permissions must be granted to the calling plugin for the call to go through.
    /// @param target address of the target to call
    /// @param value value to send with the call
    /// @param data calldata to send to the target
    /// @return The result of the call
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory);
}
