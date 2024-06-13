// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IValidation} from "../../interfaces/IValidation.sol";

interface IColdStoragePlugin is IValidation {
    /// @notice This event is emitted when a token ID is locked or unlocked.
    /// @param account The account associated with this token lock.
    /// @param tokenAddress The address of the token contract.
    /// @param tokenId The ID of the token of the new owner.
    /// @param locked True if the token is locked, false if it is unlocked.
    event TokenLockSet(
        address indexed account, address indexed tokenAddress, uint256 indexed tokenId, bool locked
    );

    /// @notice This event is emitted when a token address in its entirety is locked or unlocked.
    /// @param account The account associated with this token lock.
    /// @param tokenAddress The address of the token contract.
    /// @param locked True if the entire token contract is locked, false if it is unlocked.
    event TokenFullLockSet(address indexed account, address indexed tokenAddress, bool locked);

    /// @notice Locks or unlocks an individual token.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tokenAddress The address of the token to lock or unlock.
    /// @param tokenId The ID of the token to lock.
    /// @param locked Whether or not to lock the token.
    function setIndividualTokenLock(address tokenAddress, uint256 tokenId, bool locked) external;

    /// @notice Locks or unlocks an entire token address.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param tokenAddress The address of the token to lock or unlock.
    /// @param locked Whether or not to lock the token.
    function setFullTokenock(address tokenAddress, bool locked) external;
}
