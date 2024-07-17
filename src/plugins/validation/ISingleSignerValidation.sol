// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IValidation} from "../../interfaces/IValidation.sol";

interface ISingleSignerValidation is IValidation {
    /// @notice This event is emitted when Signer of the account's validation changes.
    /// @param account The account whose validation Signer changed.
    /// @param entityId The entityId for the account and the signer.
    /// @param previousSigner The address of the previous signer.
    /// @param newSigner The address of the new signer.
    event SignerTransferred(
        address indexed account, uint32 indexed entityId, address previousSigner, address newSigner
    );

    error NotAuthorized();

    /// @notice Transfer Signer of the account's validation to `newSigner`.
    /// @param entityId The entityId for the account and the signer.
    /// @param newSigner The address of the new signer.
    function transferSigner(uint32 entityId, address newSigner) external;

    /// @notice Get the signer of the `account`'s validation.
    /// @param entityId The entityId for the account and the signer.
    /// @param account The account to get the signer of.
    /// @return The address of the signer.
    function signerOf(uint32 entityId, address account) external view returns (address);
}
