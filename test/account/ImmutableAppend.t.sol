// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract ImmutableAppendTest is AccountTestBase {
    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_success_getData() public {
        if (!vm.envOr("SMA_TEST", false)) {
            // this test isn't relevant at all for non-SMA, and is temporary.
            return;
        }

        bytes memory expectedArgs = abi.encodePacked(owner1);

        assertEq(keccak256(LibClone.argsOnERC1967(address(account1))), keccak256(expectedArgs));
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */
}
