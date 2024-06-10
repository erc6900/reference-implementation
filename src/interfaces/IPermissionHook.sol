// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IExecutionHook} from "./IExecutionHook.sol";

interface IPermissionHook is IExecutionHook {
    /// @notice Run the pre execution permission hook specified by the `functionId`, passing in the whole user
    /// operation.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param uo The packed user operation
    /// @return Context to pass to a post execution hook, if present. An empty bytes array MAY be returned.
    function preUserOpExecutionHook(uint8 functionId, PackedUserOperation calldata uo)
        external
        returns (bytes memory);
}
