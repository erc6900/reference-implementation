// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ReferenceModularAccount} from "../../../src/account/ReferenceModularAccount.sol";
import {ModuleEntityLib} from "../../../src/libraries/ModuleEntityLib.sol";
import {ValidationConfigLib} from "../../../src/libraries/ValidationConfigLib.sol";

import {ContractOwner} from "../../mocks/ContractOwner.sol";
import {AccountTestBase} from "../../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../../utils/TestConstants.sol";

contract SingleSignerValidationModuleTest is AccountTestBase {
    using MessageHashUtils for bytes32;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    address public ethRecipient;
    address public owner2;
    uint256 public owner2Key;
    ReferenceModularAccount public account;

    ContractOwner public contractOwner;

    event ValidationInstalled(address indexed module, uint32 indexed entityId);

    event SignerTransferred(
        address indexed account, uint32 indexed entityId, address indexed newSigner, address previousSigner
    ) anonymous;

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
            callData: abi.encodeCall(ReferenceModularAccount.execute, (ethRecipient, 1 wei, "")),
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
            ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID),
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
        account.executeWithRuntimeValidation(
            abi.encodeCall(ReferenceModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidationModule), TEST_DEFAULT_VALIDATION_ENTITY_ID),
                GLOBAL_VALIDATION,
                ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }

    function test_runtime_with2SameValidationInstalled() public {
        uint32 newEntityId = type(uint32).max - 1;
        vm.prank(address(entryPoint));

        vm.expectEmit(address(singleSignerValidationModule));
        emit SignerTransferred(address(account), newEntityId, owner2, address(0));
        vm.expectEmit(true, true, true, true);
        emit ValidationInstalled(address(singleSignerValidationModule), newEntityId);
        account.installValidation(
            ValidationConfigLib.pack(address(singleSignerValidationModule), newEntityId, true, false, false),
            new bytes4[](0),
            abi.encode(newEntityId, owner2),
            new bytes[](0)
        );

        vm.prank(owner2);
        account.executeWithRuntimeValidation(
            abi.encodeCall(ReferenceModularAccount.execute, (ethRecipient, 1 wei, "")),
            _encodeSignature(
                ModuleEntityLib.pack(address(singleSignerValidationModule), newEntityId), GLOBAL_VALIDATION, ""
            )
        );
        assertEq(ethRecipient.balance, 1 wei);
    }

    function testFuzz_isValidSignatureForEOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        address accountAddr = address(account);

        bytes32 replaySafeHash = singleSignerValidationModule.replaySafeHash(accountAddr, digest);

        vm.startPrank(accountAddr);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, replaySafeHash);

        // sig check should fail
        assertEq(
            singleSignerValidationModule.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            bytes4(0xFFFFFFFF)
        );

        // transfer ownership to signer
        singleSignerValidationModule.transferSigner(TEST_DEFAULT_VALIDATION_ENTITY_ID, signer);
        assertEq(signer, singleSignerValidationModule.signers(TEST_DEFAULT_VALIDATION_ENTITY_ID, accountAddr));

        // sig check should pass
        assertEq(
            singleSignerValidationModule.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            _1271_MAGIC_VALUE
        );
    }

    function testFuzz_isValidSignatureForContractOwner(bytes32 digest) public {
        address accountAddr = address(account);
        vm.startPrank(accountAddr);
        singleSignerValidationModule.transferSigner(TEST_DEFAULT_VALIDATION_ENTITY_ID, address(contractOwner));

        bytes32 replaySafeHash = singleSignerValidationModule.replaySafeHash(accountAddr, digest);

        bytes memory signature = contractOwner.sign(replaySafeHash);
        assertEq(
            singleSignerValidationModule.validateSignature(
                accountAddr, TEST_DEFAULT_VALIDATION_ENTITY_ID, address(this), digest, signature
            ),
            _1271_MAGIC_VALUE
        );
    }
}
