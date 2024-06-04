// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {ISignatureValidator} from "./ISignatureValidator.sol";

contract ERC1271Validator is ISignatureValidator {
    /// @dev Code inherited from function `isValidERC1271SignatureNow` in
    /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/release-v5.0/contracts/utils/cryptography/SignatureChecker.sol
    function validate(address, bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool isValid, bytes memory result)
    {
        address signer = abi.decode(signerData, (address));

        (isValid, result) = signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));
        isValid = (
            isValid && result.length >= 32
                && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector)
        );
    }

    function encodeSignerData(address signer) external pure returns (bytes memory data) {
        data = abi.encode(signer);
    }
}
