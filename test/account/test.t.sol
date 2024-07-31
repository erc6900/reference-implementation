// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";

contract TestA is Test {
    function test_A() public {
        address a;
        assembly {
            mstore(0x00, 0x5f5ff3)
            a := create2(0, 0x1d, 3, 0)
            pop(create2(0, 0x1d, 3, 0))
        }

        console.log(a);
        console.logBytes(a.code);
    }
}
