// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {IPlugin} from "./IPlugin.sol";

interface IExecutionHook is IPlugin {
    /// @notice Run the pre execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param data If hook requires UO context, data is abi.encode(PackedUserOperation), else its
    /// abi.encodePacked(sender, value, calldata)
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preExecutionHook(uint8 functionId, bytes calldata data) external returns (bytes memory);

    /// @notice Run the post execution hook specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param preExecHookData The context returned by its associated pre execution hook.
    function postExecutionHook(uint8 functionId, bytes calldata preExecHookData) external;
}
