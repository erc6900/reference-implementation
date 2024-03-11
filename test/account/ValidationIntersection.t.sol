// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {
    MockUserOpValidationWithPreHookPlugin,
    MockOnlyPreUserOpValidationHookPlugin,
    MockUserOpValidationPlugin
} from "../mocks/plugins/ValidationPluginMocks.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract ValidationIntersectionTest is OptimizedTest {
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    EntryPoint public entryPoint;

    address public owner1;
    uint256 public owner1Key;
    UpgradeableModularAccount public account1;
    MockUserOpValidationPlugin public uoPlugin;
    MockUserOpValidationWithPreHookPlugin public uoPvhPlugin;
    MockOnlyPreUserOpValidationHookPlugin public pvhPlugin;

    function setUp() public {
        entryPoint = new EntryPoint();
        owner1 = makeAddr("owner1");

        SingleOwnerPlugin singleOwnerPlugin = _deploySingleOwnerPlugin();
        MSCAFactoryFixture factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        account1 = factory.createAccount(owner1, 0);
        vm.deal(address(account1), 1 ether);

        uoPlugin = new MockUserOpValidationPlugin();
        uoPvhPlugin = new MockUserOpValidationWithPreHookPlugin();
        pvhPlugin = new MockOnlyPreUserOpValidationHookPlugin();

        vm.startPrank(address(owner1));
        account1.installPlugin({
            plugin: address(uoPlugin),
            manifestHash: keccak256(abi.encode(uoPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new address[](0)
        });
        account1.installPlugin({
            plugin: address(uoPvhPlugin),
            manifestHash: keccak256(abi.encode(uoPvhPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new address[](0)
        });
        account1.installPlugin({
            plugin: address(pvhPlugin),
            manifestHash: keccak256(abi.encode(pvhPlugin.pluginManifest())),
            pluginInstallData: "",
            dependencies: new address[](0)
        });
        vm.stopPrank();
    }

    function testFuzz_validationIntersect_single(uint256 validationData) public {
        uoPlugin.setValidationData(validationData);

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPlugin.foo.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, validationData);
    }

    function test_validationIntersect_authorizer_sigfail_validationFunction() public {
        uoPvhPlugin.setValidationData(
            _SIG_VALIDATION_FAILED,
            0 // returns OK
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_authorizer_sigfail_hook() public {
        uoPvhPlugin.setValidationData(
            0, // returns OK
            _SIG_VALIDATION_FAILED
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_timeBounds_intersect_1() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        uoPvhPlugin.setValidationData(
            _packValidationData(address(0), start1, end1), _packValidationData(address(0), start2, end2)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_timeBounds_intersect_2() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        uoPvhPlugin.setValidationData(
            _packValidationData(address(0), start2, end2), _packValidationData(address(0), start1, end1)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_revert_unexpectedAuthorizer() public {
        address badAuthorizer = makeAddr("badAuthorizer");

        uoPvhPlugin.setValidationData(
            0, // returns OK
            uint256(uint160(badAuthorizer)) // returns an aggregator, which preValidation hooks are not allowed to
                // do.
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnexpectedAggregator.selector, address(uoPvhPlugin), badAuthorizer
            )
        );
        account1.validateUserOp(userOp, uoHash, 1 wei);
    }

    function test_validationIntersect_validAuthorizer() public {
        address goodAuthorizer = makeAddr("goodAuthorizer");

        uoPvhPlugin.setValidationData(
            uint256(uint160(goodAuthorizer)), // returns a valid aggregator
            0 // returns OK
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(address(uint160(returnedValidationData)), goodAuthorizer);
    }

    function test_validationIntersect_authorizerAndTimeRange() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        address goodAuthorizer = makeAddr("goodAuthorizer");

        uoPvhPlugin.setValidationData(
            _packValidationData(goodAuthorizer, start1, end1), _packValidationData(address(0), start2, end2)
        );

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(goodAuthorizer, start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksIntersect() public {
        uint48 start1 = uint48(10);
        uint48 end1 = uint48(20);

        uint48 start2 = uint48(15);
        uint48 end2 = uint48(25);

        uoPvhPlugin.setValidationData(
            0, // returns OK
            _packValidationData(address(0), start1, end1)
        );

        pvhPlugin.setValidationData(_packValidationData(address(0), start2, end2));

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksSigFail() public {
        uoPvhPlugin.setValidationData(
            0, // returns OK
            0 // returns OK
        );

        pvhPlugin.setValidationData(_SIG_VALIDATION_FAILED);

        UserOperation memory userOp;
        userOp.callData = bytes.concat(uoPvhPlugin.bar.selector);

        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function _unpackValidationData(uint256 validationData)
        internal
        pure
        returns (address authorizer, uint48 validAfter, uint48 validUntil)
    {
        authorizer = address(uint160(validationData));
        validUntil = uint48(validationData >> 160);
        if (validUntil == 0) {
            validUntil = type(uint48).max;
        }
        validAfter = uint48(validationData >> (48 + 160));
    }

    function _packValidationData(address authorizer, uint48 validAfter, uint48 validUntil)
        internal
        pure
        returns (uint256)
    {
        return uint160(authorizer) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }

    function _intersectTimeRange(uint48 validafter1, uint48 validuntil1, uint48 validafter2, uint48 validuntil2)
        internal
        pure
        returns (uint48 validAfter, uint48 validUntil)
    {
        if (validafter1 < validafter2) {
            validAfter = validafter2;
        } else {
            validAfter = validafter1;
        }
        if (validuntil1 > validuntil2) {
            validUntil = validuntil2;
        } else {
            validUntil = validuntil1;
        }
    }
}
