// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {FunctionReference} from "../../src/interfaces/IPluginManager.sol";

contract FunctionReferenceLibTest is Test {
    using FunctionReferenceLib for FunctionReference;

    function testFuzz_functionReference_packing(address addr, uint32 validationId) public {
        // console.log("addr: ", addr);
        // console.log("validationId: ", vm.toString(validationId));
        FunctionReference fr = FunctionReferenceLib.pack(addr, validationId);
        // console.log("packed: ", vm.toString(FunctionReference.unwrap(fr)));
        (address addr2, uint32 validationId2) = FunctionReferenceLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("validationId2: ", vm.toString(validationId2));
        assertEq(addr, addr2);
        assertEq(validationId, validationId2);
    }

    function testFuzz_functionReference_operators(FunctionReference a, FunctionReference b) public {
        assertTrue(a.eq(a));
        assertTrue(b.eq(b));

        if (FunctionReference.unwrap(a) == FunctionReference.unwrap(b)) {
            assertTrue(a.eq(b));
            assertTrue(b.eq(a));
            assertFalse(a.notEq(b));
            assertFalse(b.notEq(a));
        } else {
            assertTrue(a.notEq(b));
            assertTrue(b.notEq(a));
            assertFalse(a.eq(b));
            assertFalse(b.eq(a));
        }
    }
}
