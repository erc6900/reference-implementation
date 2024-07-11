// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {FunctionReference} from "../interfaces/IPluginManager.sol";

library FunctionReferenceLib {
    // Empty or unset function reference.
    FunctionReference internal constant _EMPTY_FUNCTION_REFERENCE = FunctionReference.wrap(bytes21(0));
    // Magic value for hooks that should always revert.
    FunctionReference internal constant _PRE_HOOK_ALWAYS_DENY = FunctionReference.wrap(bytes21(uint168(2)));

    function pack(address addr, uint8 validationId) internal pure returns (FunctionReference) {
        return FunctionReference.wrap(bytes21(bytes20(addr)) | bytes21(uint168(validationId)));
    }

    function unpack(FunctionReference fr) internal pure returns (address addr, uint8 validationId) {
        bytes21 underlying = FunctionReference.unwrap(fr);
        addr = address(bytes20(underlying));
        validationId = uint8(bytes1(underlying << 160));
    }

    function isEmpty(FunctionReference fr) internal pure returns (bool) {
        return FunctionReference.unwrap(fr) == bytes21(0);
    }

    function notEmpty(FunctionReference fr) internal pure returns (bool) {
        return FunctionReference.unwrap(fr) != bytes21(0);
    }

    function eq(FunctionReference a, FunctionReference b) internal pure returns (bool) {
        return FunctionReference.unwrap(a) == FunctionReference.unwrap(b);
    }

    function notEq(FunctionReference a, FunctionReference b) internal pure returns (bool) {
        return FunctionReference.unwrap(a) != FunctionReference.unwrap(b);
    }
}
