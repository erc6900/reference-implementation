// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {FunctionReference} from "../../src/interfaces/IPluginManager.sol";

contract FunctionReferenceLibTest is Test {
    using FunctionReferenceLib for FunctionReference;

    function testFuzz_functionReference_packing(address addr, uint32 entityId) public {
        // console.log("addr: ", addr);
        // console.log("entityId: ", vm.toString(entityId));
        FunctionReference fr = FunctionReferenceLib.pack(addr, entityId);
        // console.log("packed: ", vm.toString(FunctionReference.unwrap(fr)));
        (address addr2, uint32 entityId2) = FunctionReferenceLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("entityId2: ", vm.toString(entityId2));
        assertEq(addr, addr2);
        assertEq(entityId, entityId2);
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
