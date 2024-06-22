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

import {Signer, IStatelessValidator} from "../../src/validators/IStatelessValidator.sol";
import {EcdsaValidator} from "../../src/validators/EcdsaValidator.sol";
import {Erc1271Validator} from "../../src/validators/Erc1271Validator.sol";

contract SingleOwnerPluginTest is OptimizedTest {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    SingleOwnerPlugin public plugin;
    EntryPoint public entryPoint;
    EcdsaValidator public ecdsaValidator;
    Erc1271Validator public erc1271Validator;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public a;
    address public b;

    address public owner1;
    address public owner2;
    Signer public signer1;
    Signer public signer2;
    ContractOwner public contractOwner;

    // Event declarations (needed for vm.expectEmit)
    event OwnershipTransferred(address indexed account, Signer previousOwner, Signer newOwner);

    function setUp() public {
        plugin = _deploySingleOwnerPlugin();
        entryPoint = new EntryPoint();
        ecdsaValidator = new EcdsaValidator();
        erc1271Validator = new Erc1271Validator();

        a = makeAddr("a");
        b = makeAddr("b");
        owner1 = makeAddr("owner1");
        owner2 = makeAddr("owner2");
        contractOwner = new ContractOwner();

        signer1 = Signer(ecdsaValidator, abi.encode(owner1));
        signer2 = Signer(ecdsaValidator, abi.encode(owner2));
    }

    // Tests:
    // - uninitialized owner is zero address
    // - transferOwnership result is returned via owner afterwards
    // - transferOwnership emits OwnershipTransferred event
    // - owner() returns correct value after transferOwnership
    // - owner() does not return a different account's owner
    // - requireFromOwner succeeds when called by owner
    // - requireFromOwner reverts when called by non-owner

    function test_uninitializedOwner() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
    }

    function test_ownerInitialization() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));
    }

    function test_ownerInitializationEvent() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));

        Signer memory emptySigner;
        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, emptySigner, signer1);

        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));
    }

    function test_ownerMigration() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));
        plugin.transferOwnership(signer2);
        assertEq(owner2, _getAccountOwnerAddress(plugin, address(a)));
    }

    function test_ownerMigrationEvents() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
        Signer memory emptySigner;

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, emptySigner, signer1);

        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, signer1, signer2);

        plugin.transferOwnership(signer2);
        assertEq(owner2, _getAccountOwnerAddress(plugin, address(a)));
    }

    function test_ownerForSender() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));
        vm.startPrank(b);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(b)));
        plugin.transferOwnership(signer2);
        assertEq(owner2, _getAccountOwnerAddress(plugin, address(b)));
    }

    function test_requireOwner() public {
        vm.startPrank(a);
        assertEq(address(0), _getAccountOwnerAddress(plugin, address(a)));
        plugin.transferOwnership(signer1);
        assertEq(owner1, _getAccountOwnerAddress(plugin, address(a)));
        plugin.validateRuntime(uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), owner1, 0, "", "");

        vm.startPrank(b);
        vm.expectRevert(ISingleOwnerPlugin.NotAuthorized.selector);
        plugin.validateRuntime(uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), owner1, 0, "", "");
    }

    function testFuzz_validateUserOpSig(string memory salt, PackedUserOperation memory userOp) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        vm.startPrank(a);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash.toEthSignedMessageHash());

        // sig cannot cover the whole userop struct since userop struct has sig field
        userOp.signature = abi.encodePacked(r, s, v);

        // sig check should fail
        uint256 success =
            plugin.validateUserOp(uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), userOp, userOpHash);
        assertEq(success, 1);

        // transfer ownership to signer
        plugin.transferOwnership(Signer(ecdsaValidator, abi.encode(signer)));
        assertEq(signer, _getAccountOwnerAddress(plugin, address(a)));

        // sig check should pass
        success = plugin.validateUserOp(uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER), userOp, userOpHash);
        assertEq(success, 0);
    }

    function testFuzz_isValidSignatureForEOAOwner(string memory salt, bytes32 digest) public {
        // range bound the possible set of priv keys
        (address signer, uint256 privateKey) = makeAddrAndKey(salt);

        vm.startPrank(a);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // sig check should fail
        assertEq(
            plugin.validateSignature(
                uint8(ISingleOwnerPlugin.FunctionId.SIG_VALIDATION),
                address(this),
                digest,
                abi.encodePacked(r, s, v)
            ),
            bytes4(0xFFFFFFFF)
        );

        // transfer ownership to signer
        plugin.transferOwnership(Signer(ecdsaValidator, abi.encode(signer)));
        assertEq(signer, _getAccountOwnerAddress(plugin, address(a)));

        // sig check should pass
        assertEq(
            plugin.validateSignature(
                uint8(ISingleOwnerPlugin.FunctionId.SIG_VALIDATION),
                address(this),
                digest,
                abi.encodePacked(r, s, v)
            ),
            _1271_MAGIC_VALUE
        );
    }

    function testFuzz_isValidSignatureForContractOwner(bytes32 digest) public {
        vm.startPrank(a);
        plugin.transferOwnership(Signer(erc1271Validator, abi.encode(address(contractOwner))));
        bytes memory signature = contractOwner.sign(digest);
        assertEq(
            plugin.validateSignature(
                uint8(ISingleOwnerPlugin.FunctionId.SIG_VALIDATION), address(this), digest, signature
            ),
            _1271_MAGIC_VALUE
        );
    }
}
