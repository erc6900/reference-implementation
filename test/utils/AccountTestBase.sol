// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {OptimizedTest} from "./OptimizedTest.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";

/// @dev This contract handles common boilerplate setup for tests using UpgradeableModularAccount with
/// SingleOwnerPlugin.
abstract contract AccountTestBase is OptimizedTest {
    using FunctionReferenceLib for FunctionReference;

    EntryPoint public entryPoint;
    address payable public beneficiary;
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;

    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant DEFAULT_VALIDATION = 1;

    struct PreValidationHookData {
        uint8 index;
        bytes validationData;
    }

    constructor() {
        entryPoint = new EntryPoint();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));

        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        account1 = factory.createAccount(owner1, 0);
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
            _encodeSignature(
                FunctionReferenceLib.pack(
                    address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER)
                ),
                SELECTOR_ASSOCIATED_VALIDATION,
                ""
            )
        );
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }

    // helper function to encode a signature, according to the per-hook and per-validation data format.
    function _encodeSignature(
        FunctionReference validationFunction,
        uint8 defaultOrNot,
        PreValidationHookData[] memory preValidationHookData,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        bytes memory sig = abi.encodePacked(validationFunction, defaultOrNot);

        for (uint256 i = 0; i < preValidationHookData.length; ++i) {
            sig = abi.encodePacked(
                sig,
                _packValidationDataWithIndex(
                    preValidationHookData[i].index, preValidationHookData[i].validationData
                )
            );
        }

        // Index of the actual validation data is the length of the preValidationHooksRetrieved - aka
        // one-past-the-end
        sig = abi.encodePacked(sig, _packValidationDataWithIndex(255, validationData));

        return sig;
    }

    // overload for the case where there are no pre-validation hooks
    function _encodeSignature(
        FunctionReference validationFunction,
        uint8 defaultOrNot,
        bytes memory validationData
    ) internal pure returns (bytes memory) {
        PreValidationHookData[] memory emptyPreValidationHookData = new PreValidationHookData[](0);
        return _encodeSignature(validationFunction, defaultOrNot, emptyPreValidationHookData, validationData);
    }

    // helper function to pack validation data with an index, according to the sparse calldata segment spec.
    function _packValidationDataWithIndex(uint8 index, bytes memory validationData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(uint64(validationData.length), index, validationData);
    }
}
