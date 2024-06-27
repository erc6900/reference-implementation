// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IValidation} from "../../interfaces/IValidation.sol";

interface IEcdsaValidationPlugin is IValidation {
    /// @notice This event is emitted when Signer of the account's validation changes.
    /// @param account The account whose validation Signer changed.
    /// @param validationId The validationId for the account and the signer.
    /// @param previousSigner The address of the previous signer.
    /// @param newSigner The address of the new signer.
    event SignerTransferred(
        address indexed account, bytes32 validationId, address indexed previousSigner, address indexed newSigner
    );

    error NotAuthorized();

    /// @notice Transfer Signer of the account's validation to `newSigner`.
    /// @dev This function is installed on the account as part of plugin installation, and should
    /// only be called from an account.
    /// @param validationId The validationId for the account and the signer.
    /// @param newSigner The address of the new signer.
    function transferSigner(bytes32 validationId, address newSigner) external;

    /// @notice Get the signer of the `account`'s validation.
    /// @dev This function is not installed on the account, and can be called by anyone.
    /// @param validationId The validationId for the account and the signer.
    /// @param account The account to get the signer of.
    /// @return The address of the signer.
    function signerOf(bytes32 validationId, address account) external view returns (address);
}
