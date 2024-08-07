// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {Call, IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {DirectCallModule} from "../mocks/modules/DirectCallModule.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract ImmutableAppendTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_success_getData() public {
        if (!vm.envBool("SMA_TEST")) {
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
