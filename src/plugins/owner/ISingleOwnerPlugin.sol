// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IValidation} from "../../interfaces/IValidation.sol";
import {Signer} from "../../validators/IStatelessValidator.sol";

interface ISingleOwnerPlugin is IValidation {
    enum FunctionId {
        VALIDATION_OWNER,
        SIG_VALIDATION
    }

    /// @notice This event is emitted when ownership of the account changes.
    /// @param account The account whose ownership changed.
    /// @param previousOwner The details of the previous owner.
    /// @param newOwner The details of the new owner.
    event OwnershipTransferred(address indexed account, Signer previousOwner, Signer newOwner);

    error NotAuthorized();

    /// @notice Transfer ownership of the account to `newOwner`.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param newOwner The details of the new owner.
    function transferOwnership(Signer calldata newOwner) external;

    /// @notice Get the owner of the account.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @return The details of the owner.
    function owner() external view returns (Signer memory);

    /// @notice Get the owner of `account`.
    /// @dev This function is not installed on the account, and can be called by anyone.
    /// @param account The account to get the owner of.
    /// @return The details of the owner.
    function ownerOf(address account) external view returns (Signer memory);
}
