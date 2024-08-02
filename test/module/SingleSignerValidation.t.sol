// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {ContractOwner} from "../mocks/ContractOwner.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

contract SingleSignerValidationTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    address public ethRecipient;
    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account;

    ContractOwner public contractOwner;

    event ValidationInstalled(address indexed module, uint32 indexed entityId);

    function setUp() public {
        ethRecipient = makeAddr("ethRecipient");
        (owner2, owner2Key) = makeAddrAndKey("owner2");
        account = factory.createAccount(owner1, 0);
        vm.deal(address(account), 100 ether);

        contractOwner = new ContractOwner();
    }

    function test_userOpValidation() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
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
        userOp.signature = _encodeSignature(
            ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
            GLOBAL_VALIDATION,
            abi.encodePacked(r, s, v)
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 1 wei);
    }

    function test_runtimeValidate() public {
        vm.prank(owner1);
        account.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }

    function test_runtime_with2SameValidationInstalled() public {
        uint32 newEntityId = TEST_DEFAULT_VALIDATION_ENTITY_ID + 1;
        vm.prank(address(entryPoint));

        vm.expectEmit(true, true, true, true);
        emit ValidationInstalled(address(singleSignerValidation), newEntityId);
        account.installValidation(
            ValidationConfigLib.pack(address(singleSignerValidation), newEntityId, true, false),
            new bytes4[](0),
            abi.encode(newEntityId, owner2),
            new bytes[](0)
        );

        vm.prank(owner2);
        account.executeWithAuthorization(
            abi.encodeCall(UpgradeableModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidation), newEntityId), GLOBAL_VALIDATION, ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }

    function testFuzz_isValidSignatureForEOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        address accountAddr = address(account);

        vm.startPrank(accountAddr);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // sig check should fail
        assertEq(
            singleSignerValidation.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            bytes4(0xFFFFFFFF)
        );

        // transfer ownership to signer
        singleSignerValidation.transferSigner(TEST_DEFAULT_VALIDATION_ENTITY_ID, signer);
        assertEq(signer, singleSignerValidation.signers(TEST_DEFAULT_VALIDATION_ENTITY_ID, accountAddr));

        // sig check should pass
        assertEq(
            singleSignerValidation.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            _1271_MAGIC_VALUE
        );
    }

    function testFuzz_isValidSignatureForContractOwner(bytes32 digest) public {
        address accountAddr = address(account);
        vm.startPrank(accountAddr);
        singleSignerValidation.transferSigner(TEST_DEFAULT_VALIDATION_ENTITY_ID, address(contractOwner));
        bytes memory signature = contractOwner.sign(digest);
        assertEq(
            singleSignerValidation.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, signature
            ),
            _1271_MAGIC_VALUE
        );
    }
}
