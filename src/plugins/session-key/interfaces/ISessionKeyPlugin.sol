// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface ISessionKeyPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_TEMPORARY_OWNER,
        USER_OP_VALIDATION_TEMPORARY_OWNER
    }
    
    /// @notice This event is emitted when a temporary owner is added to the account.
    /// @param account The account whose temporary owner is updated.
    /// @param tempOwner The address of the temporary owner.
    /// @param selector The selector of the function that the temporary owner is allowed to call.
    /// @param _after The time after which the owner is valid.
    /// @param _until The time until which the owner is valid.
    event TemporaryOwnerAdded(address indexed account, address indexed tempOwner, bytes4 selector, uint48 _after, uint48 _until);

    /// @notice This event is emitted when a temporary owner is removed from the account.
    /// @param account The account whose temporary owner is updated.
    /// @param tempOwner The address of the temporary owner.
    /// @param selector The selector of the function that the temporary owner is allowed to call.

    event TemporaryOwnerRemoved(address indexed account, address indexed tempOwner, bytes4 selector);

    error NotAuthorized();
    error WrongTimeRangeForSession();

    /// @notice Add a temporary owner to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    /// @param _after The time after which the owner is valid.
    /// @param _until The time until which the owner is valid.
    function addTemporaryOwner(address tempOwner, bytes4 allowedSelector, uint48 _after, uint48 _until) external;

    /// @notice Remove a temporary owner from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    function removeTemporaryOwner(address tempOwner, bytes4 allowedSelector) external;

    /// @notice Get Session data for a given account and temporary owner.
    /// @param account The account to get session data for.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    function getSessionDuration(address account, address tempOwner, bytes4 allowedSelector) external view 
    returns (uint48 _after, uint48 _until);
}
