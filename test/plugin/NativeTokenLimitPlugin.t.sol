// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {NativeTokenLimitPlugin} from "../../src/plugins/NativeTokenLimitPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {ExecutionHook} from "../../src/interfaces/IAccountLoupe.sol";
import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {PluginManifest} from "../../src/interfaces/IPlugin.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract NativeTokenLimitPluginTest is OptimizedTest {
    EntryPoint public entryPoint = new EntryPoint();
    address public recipient = address(1);
    address payable public bundler = payable(address(2));
    PluginManifest internal _m;
    MockPlugin public validationPlugin = new MockPlugin(_m);
    FunctionReference public validationFunction;

    UpgradeableModularAccount public acct;
    NativeTokenLimitPlugin public plugin = new NativeTokenLimitPlugin();
    uint256 public spendLimit = 10 ether;

    function setUp() public {
        // Set up a validator with hooks from the gas spend limit plugin attached

        MSCAFactoryFixture factory = new MSCAFactoryFixture(entryPoint, _deploySingleOwnerPlugin());

        acct = factory.createAccount(address(this), 0);

        vm.deal(address(acct), 10 ether);

        FunctionReference[] memory preValidationHooks = new FunctionReference[](1);
        preValidationHooks[0] = FunctionReferenceLib.pack(address(plugin), 0);

        ExecutionHook[] memory permissionHooks = new ExecutionHook[](1);
        permissionHooks[0] = ExecutionHook({
            hookFunction: FunctionReferenceLib.pack(address(plugin), 0),
            isPreHook: true,
            isPostHook: false,
            requireUOContext: false
        });

        uint256[] memory spendLimits = new uint256[](1);
        spendLimits[0] = spendLimit;

        bytes[] memory preValHooksInitDatas = new bytes[](1);
        preValHooksInitDatas[0] = "";

        bytes[] memory permissionInitDatas = new bytes[](1);
        permissionInitDatas[0] = abi.encode(spendLimits);

        vm.prank(address(acct));
        acct.installValidation(
            FunctionReferenceLib.pack(address(validationPlugin), 0),
            true,
            new bytes4[](0),
            new bytes(0),
            abi.encode(preValidationHooks, preValHooksInitDatas),
            abi.encode(permissionHooks, permissionInitDatas)
        );

        validationFunction = FunctionReferenceLib.pack(address(validationPlugin), 0);
    }

    function _getExecuteWithValue(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(UpgradeableModularAccount.execute, (recipient, value, ""));
    }

    function _getPackedUO(uint256 gas1, uint256 gas2, uint256 gas3, uint256 gasPrice, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory uo)
    {
        uo = PackedUserOperation({
            sender: address(acct),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(UpgradeableModularAccount.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(gas1))) | bytes32(uint256(gas2)),
            preVerificationGas: gas3,
            gasFees: bytes32(uint256(uint128(gasPrice))),
            paymasterAndData: "",
            signature: abi.encodePacked(FunctionReferenceLib.pack(address(validationPlugin), 0), uint8(1))
        });
    }

    function test_userOp_gasLimit() public {
        vm.startPrank(address(entryPoint));

        // uses 10e - 200000 of gas
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        uint256 result = acct.validateUserOp(
            _getPackedUO(100000, 100000, 10 ether - 400000, 1, _getExecuteWithValue(0)), bytes32(0), 0
        );
        assertEq(plugin.limits(address(acct), 0), 200000);

        uint256 expected = uint256(type(uint48).max) << 160;
        assertEq(result, expected);

        // uses 200k + 1 wei of gas
        vm.expectRevert(NativeTokenLimitPlugin.ExceededNativeTokenLimit.selector);
        result = acct.validateUserOp(_getPackedUO(100000, 100000, 1, 1, _getExecuteWithValue(0)), bytes32(0), 0);
    }

    function test_userOp_executeLimit() public {
        vm.startPrank(address(entryPoint));

        // uses 5e of native tokens
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether)), bytes32(0));
        assertEq(plugin.limits(address(acct), 0), 5 ether);

        // uses 5e + 1wei of native tokens
        vm.expectRevert(
            abi.encodePacked(
                UpgradeableModularAccount.PreExecHookReverted.selector,
                abi.encode(
                    address(plugin),
                    uint8(0),
                    abi.encodePacked(NativeTokenLimitPlugin.ExceededNativeTokenLimit.selector)
                )
            )
        );
        acct.executeUserOp(_getPackedUO(0, 0, 0, 0, _getExecuteWithValue(5 ether + 1)), bytes32(0));
    }

    function test_userOp_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        acct.executeUserOp(
            _getPackedUO(0, 0, 0, 0, abi.encodeCall(IStandardExecutor.executeBatch, (calls))), bytes32(0)
        );
        assertEq(plugin.limits(address(acct), 0), 10 ether - 6 ether - 100001);
        assertEq(recipient.balance, 6 ether + 100001);
    }

    function test_userOp_combinedExecLimit_success() public {
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(100000, 100000, 100000, 1, _getExecuteWithValue(5 ether));
        entryPoint.handleOps(uos, bundler);

        assertEq(plugin.limits(address(acct), 0), 5 ether - 300000);
        assertEq(recipient.balance, 5 ether);
    }

    function test_userOp_combinedExecBatchLimit_success() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100000, data: ""});

        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(200000, 200000, 200000, 1, abi.encodeCall(IStandardExecutor.executeBatch, (calls)));
        entryPoint.handleOps(uos, bundler);

        assertEq(plugin.limits(address(acct), 0), 10 ether - 6 ether - 700001);
        assertEq(recipient.balance, 6 ether + 100001);
    }

    function test_userOp_combinedExecLimit_failExec() public {
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(100000, 100000, 100000, 1, _getExecuteWithValue(10 ether));
        entryPoint.handleOps(uos, bundler);

        assertEq(plugin.limits(address(acct), 0), 10 ether - 300000);
        assertEq(recipient.balance, 0);
    }

    function test_runtime_executeLimit() public {
        assertEq(plugin.limits(address(acct), 0), 10 ether);
        acct.executeWithAuthorization(
            _getExecuteWithValue(5 ether), abi.encodePacked(validationFunction, uint8(1))
        );
        assertEq(plugin.limits(address(acct), 0), 5 ether);
    }

    function test_runtime_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] = Call({target: recipient, value: 1, data: ""});
        calls[1] = Call({target: recipient, value: 1 ether, data: ""});
        calls[2] = Call({target: recipient, value: 5 ether + 100000, data: ""});

        assertEq(plugin.limits(address(acct), 0), 10 ether);
        acct.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)), abi.encodePacked(validationFunction, uint8(1))
        );
        assertEq(plugin.limits(address(acct), 0), 4 ether - 100001);
    }
}
