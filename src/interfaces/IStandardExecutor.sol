// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.25;

struct Call {
    // The target address for the account to call.
    address target;
    // The value to send with the call.
    uint256 value;
    // The calldata for the call.
    bytes data;
}

interface IStandardExecutor {
    /// @notice Standard execute method.
    /// @dev If the target is a plugin, the call SHOULD revert.
    /// @param target The target address for the account to call.
    /// @param value The value to send with the call.
    /// @param data The calldata for the call.
    /// @return The return data from the call.
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);

    /// @notice Standard executeBatch method.
    /// @dev If the target is a plugin, the call SHOULD revert. If any of the calls revert, the entire batch MUST
    /// revert.
    /// @param calls The array of calls.
    /// @return An array containing the return data from the calls.
    function executeBatch(Call[] calldata calls) external payable returns (bytes[] memory);

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
