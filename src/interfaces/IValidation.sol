// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IPlugin} from "./IPlugin.sol";

interface IValidation is IPlugin {
    /// @notice Run the user operation validationFunction specified by the `functionId`.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param userOp The user operation.
    /// @param userOpHash The user operation hash.
    /// @return Packed validation data for validAfter (6 bytes), validUntil (6 bytes), and authorizer (20 bytes).
    function validateUserOp(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256);

    /// @notice Run the runtime validationFunction specified by the `functionId`.
    /// @dev To indicate the entire call should revert, the function MUST revert.
    /// @param functionId An identifier that routes the call to different internal implementations, should there be
    /// more than one.
    /// @param sender The caller address.
    /// @param value The call value.
    /// @param data The calldata sent.
    function validateRuntime(uint8 functionId, address sender, uint256 value, bytes calldata data) external;
}
