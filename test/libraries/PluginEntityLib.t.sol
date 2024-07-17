// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {PluginEntityLib} from "../../src/helpers/PluginEntityLib.sol";
import {PluginEntity} from "../../src/interfaces/IPluginManager.sol";

contract PluginEntityLibTest is Test {
    using PluginEntityLib for PluginEntity;

    function testFuzz_pluginEntity_packing(address addr, uint32 entityId) public {
        // console.log("addr: ", addr);
        // console.log("entityId: ", vm.toString(entityId));
        PluginEntity fr = PluginEntityLib.pack(addr, entityId);
        // console.log("packed: ", vm.toString(PluginEntity.unwrap(fr)));
        (address addr2, uint32 entityId2) = PluginEntityLib.unpack(fr);
        // console.log("addr2: ", addr2);
        // console.log("entityId2: ", vm.toString(entityId2));
        assertEq(addr, addr2);
        assertEq(entityId, entityId2);
    }

    function testFuzz_pluginEntity_operators(PluginEntity a, PluginEntity b) public {
        assertTrue(a.eq(a));
        assertTrue(b.eq(b));

        if (PluginEntity.unwrap(a) == PluginEntity.unwrap(b)) {
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
