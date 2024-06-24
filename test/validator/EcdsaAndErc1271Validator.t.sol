// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {ContractOwner} from "../mocks/ContractOwner.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

import {Signer} from "../../src/validators/IStatelessValidator.sol";
import {EcdsaValidator} from "../../src/validators/EcdsaValidator.sol";
import {Erc1271Validator} from "../../src/validators/Erc1271Validator.sol";
import {WebAuthnValidator} from "../../src/validators/WebAuthnValidator.sol";

contract EcdsaAndErc1271ValidatorTest is OptimizedTest {
    EcdsaValidator public ecdsaValidator;
    Erc1271Validator public erc1271Validator;

    ContractOwner public contractOwner;

    function setUp() public {
        ecdsaValidator = new EcdsaValidator();
        erc1271Validator = new Erc1271Validator();

        contractOwner = new ContractOwner();
    }

    function testFuzz_EcdsaValidator(string memory salt, bytes32 digest) public {
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        (bool isValid, bytes memory result) =
            ecdsaValidator.validate(abi.encode(signer), digest, abi.encodePacked(r, s, v));
        assertTrue(isValid);
        assertEq(abi.decode(result, (address)), signer);
    }

    function testFuzz_Erc1271Validator(bytes32 digest) public {
        bytes memory signature = contractOwner.sign(digest);

        (bool isValid, bytes memory result) =
            erc1271Validator.validate(abi.encode(address(contractOwner)), digest, signature);
        assertTrue(isValid);
        assertEq(result, "");
    }
}
