// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IPlugin} from "../interfaces/IPlugin.sol";

struct Signer {
    ISignatureValidator validator;
    bytes data;
}

interface ISignatureValidator {
    function validate(address account, bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool isValid, bytes memory result);
}
