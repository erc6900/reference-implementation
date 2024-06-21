// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IStatelessValidator} from "./IStatelessValidator.sol";
import {WebAuthn} from "./WebAuthn.sol";

contract WebAuthnValidator is IStatelessValidator {
    using MessageHashUtils for bytes32;

    struct SignerData {
        ///  The x coordinate of the public key.
        uint256 x;
        /// The y coordinate of the public key.
        uint256 y;
    }

    function validate(bytes memory signerData, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool isValid, bytes memory result)
    {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 challengeLocation,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, uint256));
        SignerData memory signerDataDecoded = abi.decode(signerData, (SignerData));

        isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            challengeLocation,
            responseTypeLocation,
            r,
            s,
            signerDataDecoded.x,
            signerDataDecoded.y
        );
    }

    function encodeSignerData(SignerData calldata signerData) external pure returns (bytes memory data) {
        data = abi.encode(signerData);
    }
}
