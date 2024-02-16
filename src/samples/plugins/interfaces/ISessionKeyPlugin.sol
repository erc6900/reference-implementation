// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface IModularSessionKeyPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_TEMPORARY_OWNER,
        USER_OP_VALIDATION_TEMPORARY_OWNER
    }

    /// @notice This event is emitted when a session key is added to the account.
    /// @param account The account whose session key is updated.
    /// @param sessionKey The address of the session key.
    /// @param selector The selector of the function that the session key is allowed to call.
    /// @param validAfter The time after which the owner is valid.
    /// @param validUntil The time until which the owner is valid.
    event SessionKeyAdded(
        address indexed account, address indexed sessionKey, bytes4 selector, uint48 validAfter, uint48 validUntil
    );

    /// @notice This event is emitted when a session key is removed from the account.
    /// @param account The account whose session key is updated.
    /// @param sessionKey The address of the session key.
    /// @param selector The selector of the function that the session key is allowed to call.
    event SessionKeyRemoved(address indexed account, address indexed sessionKey, bytes4 selector);

    /// @notice This event is emitted when session keys are added to the account.
    /// @param account The account whose session keys are updated.
    /// @param sessionKeys The addresses of the session keys.
    /// @param selectors The selectors of the functions that the session keys are allowed to call.
    /// @param validAfters The times after which the owners are valid.
    /// @param validUntils The times until which the owners are valid.
    event SessionKeysAdded(
        address indexed account,
        address[] sessionKeys,
        bytes4[] selectors,
        uint48[] validAfters,
        uint48[] validUntils
    );

    /// @notice This event is emitted when session keys are removed from the account.
    /// @param account The account whose session keys are updated.
    /// @param sessionKeys The addresses of the session keys.
    /// @param selectors The selectors of the functions that the session keys are allowed to call.
    event SessionKeysRemoved(address indexed account, address[] sessionKeys, bytes4[] selectors);

    error InvalidSignature();
    error NotAuthorized();
    error WrongTimeRangeForSession();
    error WrongDataLength();

    /// @notice Add a session key to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account. The function selector installed by a child session key plugin
    /// is passed as a parameter, which enforces its own permissions on the calls it can make.
    /// @param sessionKey The address of the session key.
    /// @param allowedSelector The selector of the function that the session key is allowed to call.
    /// @param validAfter The time after which the owner is valid.
    /// @param validUntil The time until which the owner is valid.
    function addSessionKey(address sessionKey, bytes4 allowedSelector, uint48 validAfter, uint48 validUntil)
        external;

    /// @notice Remove a session key from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param sessionKey The address of the session key.
    /// @param allowedSelector The selector of the function that the session key is allowed to call.
    function removeSessionKey(address sessionKey, bytes4 allowedSelector) external;

    /// @notice Add session keys to the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param sessionKeys The addresses of the session keys.
    /// @param allowedSelectors The selectors of the functions that the session keys are allowed to call.
    /// @param validAfters The times after which the owners are valid.
    /// @param validUntils The times until which the owners are valid.
    function addSessionKeyBatch(
        address[] calldata sessionKeys,
        bytes4[] calldata allowedSelectors,
        uint48[] calldata validAfters,
        uint48[] calldata validUntils
    ) external;

    /// @notice Remove session keys from the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param sessionKeys The addresses of the session keys.
    /// @param allowedSelectors The selectors of the functions that the session keys are allowed to call.
    function removeSessionKeyBatch(address[] calldata sessionKeys, bytes4[] calldata allowedSelectors) external;

    /// @notice Get Session data for a given account and session key.
    /// @param account The account to get session data for.
    /// @param sessionKey The address of the session key.
    /// @param allowedSelector The selector of the function that the session key is allowed to call.
    function getSessionDuration(address account, address sessionKey, bytes4 allowedSelector)
        external
        view
        returns (uint48 validAfter, uint48 validUntil);

    /// @notice Get all session keys and selectors for a given account.
    /// @param account The account to get session keys and selectors for.
    /// @return sessionKeys The addresses of the session keys.
    /// @return selectors The selectors of the functions that the session keys are allowed to call.
    function getSessionKeysAndSelectors(address account)
        external
        view
        returns (address[] memory sessionKeys, bytes4[] memory selectors);
}
