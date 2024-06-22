// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {IStatelessValidator} from "./IStatelessValidator.sol";

contract Erc1271Validator is IStatelessValidator {
    function validate(bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        override
        returns (bool isValid, bytes memory)
    {
        if (signerData.length == 0) {
            isValid = false;
        } else {
            address expectedSigner = abi.decode(signerData, (address));

            isValid = SignatureChecker.isValidERC1271SignatureNow(expectedSigner, hash, signature);
        }
    }

    function encodeSignerData(address signer) external pure returns (bytes memory data) {
        data = abi.encode(signer);
    }
}
