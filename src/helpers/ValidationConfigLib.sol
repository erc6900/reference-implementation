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
            bytes23(
                bytes23(FunctionReference.unwrap(_validationFunction))
                // isGlobal flag stored in the 22nd byte
                | bytes23(bytes32(_isGlobal ? uint256(1) << 80 : 0))
                // isSignatureValidation flag stored in the 23rd byte
                | bytes23(bytes32(_isSignatureValidation ? uint256(1) << 72 : 0))
            )
        );
    }

    function pack(address _plugin, uint8 _functionId, bool _isGlobal, bool _isSignatureValidation)
        internal
        pure
        returns (ValidationConfig)
    {
        return ValidationConfig.wrap(
            bytes23(
                // plugin address stored in the first 20 bytes
                bytes23(bytes20(_plugin))
                // functionId stored in the 21st byte
                | bytes23(bytes32(uint256(_functionId) << 168))
                // isGlobal flag stored in the 22nd byte
                | bytes23(bytes32(_isGlobal ? uint256(1) << 80 : 0))
                // isSignatureValidation flag stored in the 23rd byte
                | bytes23(bytes32(_isSignatureValidation ? uint256(1) << 72 : 0))
            )
        );
    }

    function unpackUnderlying(ValidationConfig config)
        internal
        pure
        returns (address _plugin, uint8 _functionId, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes23 configBytes = ValidationConfig.unwrap(config);
        _plugin = address(bytes20(configBytes));
        _functionId = uint8(configBytes[20]);
        _isGlobal = uint8(configBytes[21]) == 1;
        _isSignatureValidation = uint8(configBytes[22]) == 1;
    }

    function unpack(ValidationConfig config)
        internal
        pure
        returns (FunctionReference _validationFunction, bool _isGlobal, bool _isSignatureValidation)
    {
        bytes23 configBytes = ValidationConfig.unwrap(config);
        _validationFunction = FunctionReference.wrap(bytes21(configBytes));
        _isGlobal = uint8(configBytes[21]) == 1;
        _isSignatureValidation = uint8(configBytes[22]) == 1;
    }

    function plugin(ValidationConfig config) internal pure returns (address) {
        return address(bytes20(ValidationConfig.unwrap(config)));
    }

    function functionId(ValidationConfig config) internal pure returns (uint8) {
        return uint8(ValidationConfig.unwrap(config)[20]);
    }

    function functionReference(ValidationConfig config) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes21(ValidationConfig.unwrap(config)));
    }

    function isGlobal(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[21]) == 1;
    }

    function isSignatureValidation(ValidationConfig config) internal pure returns (bool) {
        return uint8(ValidationConfig.unwrap(config)[22]) == 1;
    }
}
