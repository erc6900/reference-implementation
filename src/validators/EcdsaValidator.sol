// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IStatelessValidator} from "./IStatelessValidator.sol";

contract EcdsaValidator is IStatelessValidator {
    using ECDSA for bytes32;

    /// @dev result always returns the correct singer of the signature.
    function validate(bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool isValid, bytes memory result)
    {
        address expectedSigner = abi.decode(signerData, (address));

        address signer = hash.recover(signature);
        isValid = signer == expectedSigner;
        result = abi.encode(signer);
    }

    function encodeSignerData(address signer) external pure returns (bytes memory data) {
        data = abi.encode(signer);
    }
}
