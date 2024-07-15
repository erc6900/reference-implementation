// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {ContractOwner} from "../mocks/ContractOwner.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";
import {TEST_DEFAULT_OWNER_FUNCTION_ID} from "../utils/TestConstants.sol";

contract SingleOwnerPluginTest is OptimizedTest {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    SingleOwnerPlugin public plugin;
    EntryPoint public entryPoint;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    address public a;
    address public b;

    address public owner1;
    address public owner2;
    ContractOwner public contractOwner;

    // Event declarations (needed for vm.expectEmit)
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        plugin = _deploySingleOwnerPlugin();
        entryPoint = new EntryPoint();

        a = makeAddr("a");
        b = makeAddr("b");
        owner1 = makeAddr("owner1");
        owner2 = makeAddr("owner2");
        contractOwner = new ContractOwner();
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
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
    }

    function test_ownerInitialization() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
    }

    function test_ownerInitializationEvent() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, address(0), owner1);

        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
    }

    function test_ownerMigration() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner2);
        assertEq(owner2, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
    }

    function test_ownerMigrationEvents() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, address(0), owner1);

        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));

        vm.expectEmit(true, true, true, true);
        emit OwnershipTransferred(a, owner1, owner2);

        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner2);
        assertEq(owner2, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
    }

    function test_ownerForSender() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        vm.startPrank(b);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, b));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner2);
        assertEq(owner2, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, b));
    }

    function test_requireOwner() public {
        vm.startPrank(a);
        assertEq(address(0), plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, owner1);
        assertEq(owner1, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));
        plugin.validateRuntime(a, TEST_DEFAULT_OWNER_FUNCTION_ID, owner1, 0, "", "");

        vm.startPrank(b);
        vm.expectRevert(SingleOwnerPlugin.NotAuthorized.selector);
        plugin.validateRuntime(b, TEST_DEFAULT_OWNER_FUNCTION_ID, owner1, 0, "", "");
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
        uint256 success = plugin.validateUserOp(TEST_DEFAULT_OWNER_FUNCTION_ID, userOp, userOpHash);
        assertEq(success, 1);

        // transfer ownership to signer
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, signer);
        assertEq(signer, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));

        // sig check should pass
        success = plugin.validateUserOp(TEST_DEFAULT_OWNER_FUNCTION_ID, userOp, userOpHash);
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
                a, TEST_DEFAULT_OWNER_FUNCTION_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            bytes4(0xFFFFFFFF)
        );

        // transfer ownership to signer
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, signer);
        assertEq(signer, plugin.owners(TEST_DEFAULT_OWNER_FUNCTION_ID, a));

        // sig check should pass
        assertEq(
            plugin.validateSignature(
                a, TEST_DEFAULT_OWNER_FUNCTION_ID, address(this), digest, abi.encodePacked(r, s, v)
            ),
            _1271_MAGIC_VALUE
        );
    }

    function testFuzz_isValidSignatureForContractOwner(bytes32 digest) public {
        vm.startPrank(a);
        plugin.transferOwnership(TEST_DEFAULT_OWNER_FUNCTION_ID, address(contractOwner));
        bytes memory signature = contractOwner.sign(digest);
        assertEq(
            plugin.validateSignature(a, TEST_DEFAULT_OWNER_FUNCTION_ID, address(this), digest, signature),
            _1271_MAGIC_VALUE
        );
    }
}
