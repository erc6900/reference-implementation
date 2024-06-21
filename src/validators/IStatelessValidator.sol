// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

struct Signer {
    IStatelessValidator validator;
    /// data is passed as signedData to the validator
    bytes data;
}

interface IStatelessValidator {
    function validate(bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool isValid, bytes memory result);
}
