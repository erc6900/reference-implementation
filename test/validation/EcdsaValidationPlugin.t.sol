// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {console} from "forge-std/Test.sol";
import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {EcdsaValidationPlugin} from "../../src/plugins/validation/EcdsaValidationPlugin.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";

import {OptimizedTest} from "../utils/OptimizedTest.sol";
import {EcdsaValidationFactoryFixture} from "../mocks/EcdsaValidationFactoryFixture.sol";

contract EcdsaValidationPluginTest is OptimizedTest {
    using MessageHashUtils for bytes32;

    EntryPoint public entryPoint;
    EcdsaValidationPlugin public ecdsaValidationPlugin;
    address payable public beneficiary;
    address public ethRecipient;

    address public owner1;
    uint256 public owner1Key;
    EcdsaValidationFactoryFixture public factory;
    UpgradeableModularAccount public account1;
    bytes32 public validationId1;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;
    uint8 public constant SELECTOR_ASSOCIATED_VALIDATION = 0;
    uint8 public constant DEFAULT_VALIDATION = 1;

    function setUp() public {
        entryPoint = new EntryPoint();
        (owner1, owner1Key) = makeAddrAndKey("owner1");
        beneficiary = payable(makeAddr("beneficiary"));
        ethRecipient = makeAddr("ethRecipient");

        ecdsaValidationPlugin = _deployEcdsaValidationPlugin();
        factory = new EcdsaValidationFactoryFixture(entryPoint, ecdsaValidationPlugin);

        (account1, validationId1) = factory.createAccount(owner1, 0);
        vm.deal(address(account1), 100 ether);
    }

    function test_userOpValidation() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(validationId1, DEFAULT_VALIDATION, r, s, v);
        console.log("in test");
        console.logBytes32(validationId1);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 1 wei);
    }

    // helper function to compress 2 gas values into a single bytes32
    function _encodeGas(uint256 g1, uint256 g2) internal pure returns (bytes32) {
        return bytes32(uint256((g1 << 128) + uint128(g2)));
    }
}
