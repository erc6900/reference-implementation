// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface ISessionKeyPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_TEMPORARY_OWNER,
        USER_OP_VALIDATION_TEMPORARY_OWNER
    }
    
    /// @notice This event is emitted when a temporary owner is added to the account.
    /// @param account The account whose ownership changed.
    /// @param owner The address of the temporary owner.
    /// @param _after The time after which the owner is valid.
    /// @param _until The time until which the owner is valid.
    event TemporaryOwnerAdded(address indexed account, address indexed owner, uint48 _after, uint48 _until);
    event TemporaryOwnerRemoved(address indexed account, address indexed owner);

    error NotAuthorized();
    error WrongTimeRangeForSession();

    /// @notice Add a temporary owner to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwner The address of the temporary owner.
    /// @param _after The time after which the owner is valid.
    /// @param _until The time until which the owner is valid.
    function addTemporaryOwner(
        address tempOwner,
        uint48 _after,
        uint48 _until
    ) external;

    /// @notice Remove a temporary owner from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwner The address of the temporary owner.
    function removeTemporaryOwner(address tempOwner) external;

    /// @notice Get Session data for a given account and temporary owner.
    /// @param account The account to get session data for.
    /// @param tempOwner The address of the temporary owner.
    function getSessionDuration(address account, address tempOwner) external view returns (uint48 _after, uint48 _until);
}
