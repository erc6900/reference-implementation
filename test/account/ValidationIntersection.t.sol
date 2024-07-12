// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {PluginEntity, PluginEntityLib} from "../../src/helpers/PluginEntityLib.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {
    MockBaseUserOpValidationPlugin,
    MockUserOpValidation1HookPlugin,
    MockUserOpValidation2HookPlugin,
    MockUserOpValidationPlugin
} from "../mocks/plugins/ValidationPluginMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ValidationIntersectionTest is AccountTestBase {
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    MockUserOpValidationPlugin public noHookPlugin;
    MockUserOpValidation1HookPlugin public oneHookPlugin;
    MockUserOpValidation2HookPlugin public twoHookPlugin;

    PluginEntity public noHookValidation;
    PluginEntity public oneHookValidation;
    PluginEntity public twoHookValidation;

    function setUp() public {
        noHookPlugin = new MockUserOpValidationPlugin();
        oneHookPlugin = new MockUserOpValidation1HookPlugin();
        twoHookPlugin = new MockUserOpValidation2HookPlugin();

        noHookValidation = PluginEntityLib.pack({
            addr: address(noHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.USER_OP_VALIDATION)
        });

        oneHookValidation = PluginEntityLib.pack({
            addr: address(oneHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.USER_OP_VALIDATION)
        });

        twoHookValidation = PluginEntityLib.pack({
            addr: address(twoHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.USER_OP_VALIDATION)
        });

        vm.startPrank(address(entryPoint));
        account1.installPlugin({
            plugin: address(noHookPlugin),
            manifestHash: keccak256(abi.encode(noHookPlugin.pluginManifest())),
            pluginInstallData: ""
        });
        account1.installPlugin({
            plugin: address(oneHookPlugin),
            manifestHash: keccak256(abi.encode(oneHookPlugin.pluginManifest())),
            pluginInstallData: ""
        });
        // TODO: change with new install flow
        // temporary fix to add the pre-validation hook
        PluginEntity[] memory preValidationHooks = new PluginEntity[](1);
        preValidationHooks[0] = PluginEntityLib.pack({
            addr: address(oneHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.PRE_VALIDATION_HOOK_1)
        });
        bytes[] memory installDatas = new bytes[](1);
        account1.installValidation(
            ValidationConfigLib.pack(oneHookValidation, true, true),
            new bytes4[](0),
            bytes(""),
            abi.encode(preValidationHooks, installDatas),
            bytes("")
        );
        account1.installPlugin({
            plugin: address(twoHookPlugin),
            manifestHash: keccak256(abi.encode(twoHookPlugin.pluginManifest())),
            pluginInstallData: ""
        });
        // temporary fix to add the pre-validation hook
        preValidationHooks = new PluginEntity[](2);
        preValidationHooks[0] = PluginEntityLib.pack({
            addr: address(twoHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.PRE_VALIDATION_HOOK_1)
        });
        preValidationHooks[1] = PluginEntityLib.pack({
            addr: address(twoHookPlugin),
            entityId: uint32(MockBaseUserOpValidationPlugin.EntityId.PRE_VALIDATION_HOOK_2)
        });
        installDatas = new bytes[](2);
        account1.installValidation(
            ValidationConfigLib.pack(twoHookValidation, true, true),
            new bytes4[](0),
            bytes(""),
            abi.encode(preValidationHooks, installDatas),
            bytes("")
        );
        vm.stopPrank();
    }

    function testFuzz_validationIntersect_single(uint256 validationData) public {
        noHookPlugin.setValidationData(validationData);

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(noHookPlugin.foo.selector);
        userOp.signature = _encodeSignature(noHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, validationData);
    }

    function test_validationIntersect_authorizer_sigfail_validationFunction() public {
        oneHookPlugin.setValidationData(
            _SIG_VALIDATION_FAILED,
            0 // returns OK
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        // Down-cast to only check the authorizer
        assertEq(uint160(returnedValidationData), _SIG_VALIDATION_FAILED);
    }

    function test_validationIntersect_authorizer_sigfail_hook() public {
        oneHookPlugin.setValidationData(
            0, // returns OK
            _SIG_VALIDATION_FAILED
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
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

        oneHookPlugin.setValidationData(
            _packValidationData(address(0), start1, end1), _packValidationData(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
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

        oneHookPlugin.setValidationData(
            _packValidationData(address(0), start2, end2), _packValidationData(address(0), start1, end1)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_revert_unexpectedAuthorizer() public {
        address badAuthorizer = makeAddr("badAuthorizer");

        oneHookPlugin.setValidationData(
            0, // returns OK
            uint256(uint160(badAuthorizer)) // returns an aggregator, which preValidation hooks are not allowed to
                // do.
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.UnexpectedAggregator.selector,
                address(oneHookPlugin),
                MockBaseUserOpValidationPlugin.EntityId.PRE_VALIDATION_HOOK_1,
                badAuthorizer
            )
        );
        account1.validateUserOp(userOp, uoHash, 1 wei);
    }

    function test_validationIntersect_validAuthorizer() public {
        address goodAuthorizer = makeAddr("goodAuthorizer");

        oneHookPlugin.setValidationData(
            uint256(uint160(goodAuthorizer)), // returns a valid aggregator
            0 // returns OK
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
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

        oneHookPlugin.setValidationData(
            _packValidationData(goodAuthorizer, start1, end1), _packValidationData(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(oneHookPlugin.bar.selector);
        userOp.signature = _encodeSignature(oneHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
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

        twoHookPlugin.setValidationData(
            0, // returns OK
            _packValidationData(address(0), start1, end1),
            _packValidationData(address(0), start2, end2)
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookPlugin.baz.selector);
        userOp.signature = _encodeSignature(twoHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
        bytes32 uoHash = entryPoint.getUserOpHash(userOp);

        vm.prank(address(entryPoint));
        uint256 returnedValidationData = account1.validateUserOp(userOp, uoHash, 1 wei);

        assertEq(returnedValidationData, _packValidationData(address(0), start2, end1));
    }

    function test_validationIntersect_multiplePreValidationHooksSigFail() public {
        twoHookPlugin.setValidationData(
            0, // returns OK
            0, // returns OK
            _SIG_VALIDATION_FAILED
        );

        PackedUserOperation memory userOp;
        userOp.callData = bytes.concat(twoHookPlugin.baz.selector);

        userOp.signature = _encodeSignature(twoHookValidation, SELECTOR_ASSOCIATED_VALIDATION, "");
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
