// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

interface ISingleOwnerPlugin {
    enum FunctionId {
        RUNTIME_VALIDATION_OWNER_OR_SELF,
        USER_OP_VALIDATION_OWNER
    }

    /// @notice This event is emitted when ownership of the account changes.
    /// @param account The account whose ownership changed.
    /// @param previousOwner The address of the previous owner.
    /// @param newOwner The address of the new owner.
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    error NotAuthorized();

    /// @notice Transfer ownership of the account to `newOwner`.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param newOwner The address of the new owner.
    function transferOwnership(address newOwner) external;

    /// @notice Get the owner of the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @return The address of the owner.
    function owner() external view returns (address);

    /// @notice Get the owner of `account`.
    /// @dev This function is not installed on the account, and can be called by anyone.
    /// @param account The account to get the owner of.
    /// @return The address of the owner.
    function ownerOf(address account) external view returns (address);
}
