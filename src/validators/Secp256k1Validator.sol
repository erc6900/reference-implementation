// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ISignatureValidator} from "./ISignatureValidator.sol";

contract Secp256k1Validator is ISignatureValidator {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    function validate(address, bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        pure
        returns (bool isValid, bytes memory result)
    {
        bytes32 messageHash = hash.toEthSignedMessageHash();
        address expectedSigner = abi.decode(signerData, (address));

        address signer = messageHash.recover(signature);
        isValid = signer == expectedSigner;
        result = abi.encode(signer);
    }

    function encodeSignerData(address signer) external pure returns (bytes memory data) {
        data = abi.encode(signer);
    }
}
