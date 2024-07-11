// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {FunctionReference, ValidationConfig} from "../interfaces/IPluginManager.sol";

// Validation config is a packed representation of a validation function and flags for its configuration.
// Layout:
// 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA________________________ // Address
// 0x________________________________________BB______________________ // Function ID
// 0x__________________________________________CC____________________ // isGlobal
// 0x____________________________________________DD__________________ // isSignatureValidation
// 0x______________________________________________000000000000000000 // unused

library ValidationConfigLib {
    function pack(FunctionReference _validationFunction, bool _isGlobal, bool _isSignatureValidation)
        internal
        pure
        returns (ValidationConfig)
    {
        return ValidationConfig.wrap(
            bytes26(
                bytes26(FunctionReference.unwrap(_validationFunction))
                // isGlobal flag stored in the 25th byte
                | bytes26(bytes32(_isGlobal ? uint256(1) << 56 : 0))
                // isSignatureValidation flag stored in the 26th byte
                | bytes26(bytes32(_isSignatureValidation ? uint256(1) << 48 : 0))
            )
        );
    }

    function pack(address _plugin, uint32 _validationId, bool _isGlobal, bool _isSignatureValidation)
        internal
        pure
        returns (ValidationConfig)
    {
        return ValidationConfig.wrap(
            bytes26(
                // plugin address stored in the first 20 bytes
                bytes26(bytes20(_plugin))
                // validationId stored in the 21st - 24th byte
                | bytes26(bytes32(uint256(_validationId) << 168))
                // isGlobal flag stored in the 25th byte
                | bytes26(bytes32(_isGlobal ? uint256(1) << 56 : 0))
                // isSignatureValidation flag stored in the 26th byte
                | bytes26(bytes32(_isSignatureValidation ? uint256(1) << 48 : 0))
            )
        );
    }

    function unpackUnderlying(ValidationConfig config)
        internal
        pure
        returns (address _plugin, uint32 _validationId, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes26 configBytes = ValidationConfig.unwrap(config);
        _plugin = address(bytes20(configBytes));
        _validationId = uint32(bytes4(configBytes << 160));
        _isGlobal = uint8(configBytes[24]) == 1;
        _isSignatureValidation = uint8(configBytes[25]) == 1;
    }

    function unpack(ValidationConfig config)
        internal
        pure
        returns (FunctionReference _validationFunction, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes26 configBytes = ValidationConfig.unwrap(config);
        _validationFunction = FunctionReference.wrap(bytes24(configBytes));
        _isGlobal = uint8(configBytes[24]) == 1;
        _isSignatureValidation = uint8(configBytes[25]) == 1;
    }

    function plugin(ValidationConfig config) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(config)));
    }

    function validationId(ValidationConfig config) internal pure returns (uint32) {
        return uint32(bytes4(ValidationConfig.unwrap(config) << 160));
    }

    function functionReference(ValidationConfig config) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes24(ValidationConfig.unwrap(config)));
    }

    function isGlobal(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[24]) == 1;
    }

    function isSignatureValidation(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[25]) == 1;
    }
}
