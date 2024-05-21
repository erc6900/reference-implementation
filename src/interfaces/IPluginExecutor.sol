// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

interface IPluginExecutor {
    /// @notice Execute a call from a plugin to another plugin, via an execution function installed on the account.
    /// @dev Plugins are not allowed to call native functions on the account. Permissions must be granted to the
    /// calling plugin for the call to go through.
    /// @param data The calldata to send to the plugin.
    /// @return The return data from the call.
    function executeFromPlugin(bytes calldata data) external payable returns (bytes memory);

    /// @notice Execute a call from a plugin to a non-plugin address.
    /// @dev If the target is a plugin, the call SHOULD revert. Permissions must be granted to the calling plugin
    /// for the call to go through.
    /// @param target The address to be called.
    /// @param value The value to send with the call.
    /// @param data The calldata to send to the target.
    /// @return The return data from the call.
    function executeFromPluginExternal(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory);

    /// @notice Execute a call using a specified runtime validation, as given in the first 21 bytes of
    /// `authorization`.
    /// @param data The calldata to send to the account.
    /// @param authorization The authorization data to use for the call. The first 21 bytes specifies which runtime
    /// validation to use, and the rest is sent as a parameter to runtime validation.
    function executeWithAuthorization(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory);
}
