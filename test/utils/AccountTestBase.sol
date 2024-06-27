// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {OptimizedTest} from "./OptimizedTest.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {DefaultValidationFactoryFixture} from "../mocks/DefaultValidationFactoryFixture.sol";

/// @dev This contract handles common boilerplate setup for tests using UpgradeableModularAccount with
/// SingleOwnerPlugin.
abstract contract AccountTestBase is OptimizedTest {
    EntryPoint public entryPoint;
    address payable public beneficiary;
    SingleOwnerPlugin public singleOwnerPlugin;
    DefaultValidationFactoryFixture public factory;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;
    bytes32 public validationId;

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant DEFAULT_VALIDATION = 1;

    constructor() {
        entryPoint = new EntryPoint();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));

        singleOwnerPlugin = _deploySingleOwnerPlugin();
        // factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);
        factory = new DefaultValidationFactoryFixture(entryPoint, singleOwnerPlugin);

        (account1, validationId) = factory.createAccount(owner1, 0);
        vm.deal(address(account1), 100 ether);
    }

    function _transferOwnershipToTest() internal {
        // Transfer ownership to test contract for easier invocation.
        vm.prank(owner1);
        account1.executeWithAuthorization(
            abi.encodeCall(
                account1.execute,
                (
                    address(singleOwnerPlugin),
                    0,
                    abi.encodeCall(SingleOwnerPlugin.transferOwnership, (address(this)))
                )
            ),
            abi.encodePacked(validationId, DEFAULT_VALIDATION)
        );
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }
}
