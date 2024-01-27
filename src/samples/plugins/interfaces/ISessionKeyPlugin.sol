// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface IModularSessionKeyPlugin {
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
    event SessionKeyAdded(
        address indexed account, address indexed tempOwner, bytes4 selector, uint48 _after, uint48 _until
    );

    /// @notice This event is emitted when a temporary owner is removed from the account.
    /// @param account The account whose temporary owner is updated.
    /// @param tempOwner The address of the temporary owner.
    /// @param selector The selector of the function that the temporary owner is allowed to call.
    event SessionKeyRemoved(address indexed account, address indexed tempOwner, bytes4 selector);

    /// @notice This event is emitted when temporary owners are added to the account.
    /// @param account The account whose temporary owners are updated.
    /// @param tempOwners The addresses of the temporary owners.
    /// @param selectors The selectors of the functions that the temporary owners are allowed to call.
    /// @param _afters The times after which the owners are valid.
    /// @param _untils The times until which the owners are valid.
    event SessionKeysAdded(
        address indexed account,
        address[] indexed tempOwners,
        bytes4[] selectors,
        uint48[] _afters,
        uint48[] _untils
    );

    /// @notice This event is emitted when temporary owners are removed from the account.
    /// @param account The account whose temporary owners are updated.
    /// @param tempOwners The addresses of the temporary owners.
    /// @param selectors The selectors of the functions that the temporary owners are allowed to call.
    event SessionKeysRemoved(address indexed account, address[] indexed tempOwners, bytes4[] selectors);

    error NotAuthorized();
    error WrongTimeRangeForSession();
    error WrongDataLength();

    /// @notice Add a temporary owner to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account. The function selector installed by a child session key plugin
    /// is passed as a parameter, which enforces its own permissions on the calls it can make.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    /// @param _after The time after which the owner is valid.
    /// @param _until The time until which the owner is valid.
    function addSessionKey(address tempOwner, bytes4 allowedSelector, uint48 _after, uint48 _until) external;

    /// @notice Remove a temporary owner from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    function removeSessionKey(address tempOwner, bytes4 allowedSelector) external;

    /// @notice Add temporary owners to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwners The addresses of the temporary owners.
    /// @param allowedSelectors The selectors of the functions that the temporary owners are allowed to call.
    /// @param _afters The times after which the owners are valid.
    /// @param _untils The times until which the owners are valid.
    function addSessionKeyBatch(
        address[] calldata tempOwners,
        bytes4[] calldata allowedSelectors,
        uint48[] calldata _afters,
        uint48[] calldata _untils
    ) external;

    /// @notice Remove temporary owners from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tempOwners The addresses of the temporary owners.
    /// @param allowedSelectors The selectors of the functions that the temporary owners are allowed to call.
    function removeSessionKeyBatch(address[] calldata tempOwners, bytes4[] calldata allowedSelectors) external;

    /// @notice Get Session data for a given account and temporary owner.
    /// @param account The account to get session data for.
    /// @param tempOwner The address of the temporary owner.
    /// @param allowedSelector The selector of the function that the temporary owner is allowed to call.
    function getSessionDuration(address account, address tempOwner, bytes4 allowedSelector)
        external
        view
        returns (uint48 _after, uint48 _until);
}
