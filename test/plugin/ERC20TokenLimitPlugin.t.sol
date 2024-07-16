// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {ERC20TokenLimitPlugin} from "../../src/plugins/ERC20TokenLimitPlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {ExecutionHook} from "../../src/interfaces/IAccountLoupe.sol";
import {FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {PluginManifest} from "../../src/interfaces/IPlugin.sol";
import {ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract ERC20TokenLimitPluginTest is AccountTestBase {
    address public recipient = address(1);
    MockERC20 public erc20;
    address payable public bundler = payable(address(2));
    PluginManifest internal _m;
    MockPlugin public validationPlugin = new MockPlugin(_m);
    FunctionReference public validationFunction;

    UpgradeableModularAccount public acct;
    ERC20TokenLimitPlugin public plugin = new ERC20TokenLimitPlugin();
    uint256 public spendLimit = 10 ether;

    function setUp() public {
        // Set up a validator with hooks from the erc20 spend limit plugin attached
        MSCAFactoryFixture factory = new MSCAFactoryFixture(entryPoint, _deploySingleOwnerPlugin());

        acct = factory.createAccount(address(this), 0);

        erc20 = new MockERC20();
        erc20.mint(address(acct), 10 ether);

        ExecutionHook[] memory permissionHooks = new ExecutionHook[](1);
        permissionHooks[0] = ExecutionHook({
            hookFunction: FunctionReferenceLib.pack(address(plugin), 0),
            isPreHook: true,
            isPostHook: false
        });

        // arr idx 0 => functionId of 0 has that spend
        uint256[] memory limits = new uint256[](1);
        limits[0] = spendLimit;

        ERC20TokenLimitPlugin.ERC20SpendLimit[] memory limit = new ERC20TokenLimitPlugin.ERC20SpendLimit[](1);
        limit[0] = ERC20TokenLimitPlugin.ERC20SpendLimit({token: address(erc20), limits: limits});

        bytes[] memory permissionInitDatas = new bytes[](1);
        permissionInitDatas[0] = abi.encode(uint8(0), limit);

        vm.prank(address(acct));
        acct.installValidation(
            ValidationConfigLib.pack(address(validationPlugin), 0, true, true),
            new bytes4[](0),
            new bytes(0),
            new bytes(0),
            abi.encode(permissionHooks, permissionInitDatas)
        );

        validationFunction = FunctionReferenceLib.pack(address(validationPlugin), 0);
    }

    function _getPackedUO(bytes memory callData) internal view returns (PackedUserOperation memory uo) {
        uo = PackedUserOperation({
            sender: address(acct),
            nonce: 0,
            initCode: "",
            callData: abi.encodePacked(UpgradeableModularAccount.executeUserOp.selector, callData),
            accountGasLimits: bytes32(bytes16(uint128(200000))) | bytes32(uint256(200000)),
            preVerificationGas: 200000,
            gasFees: bytes32(uint256(uint128(0))),
            paymasterAndData: "",
            signature: _encodeSignature(FunctionReferenceLib.pack(address(validationPlugin), 0), 1, "")
        });
    }

    function _getExecuteWithSpend(uint256 value) internal view returns (bytes memory) {
        return abi.encodeCall(
            UpgradeableModularAccount.execute,
            (address(erc20), 0, abi.encodeCall(IERC20.transfer, (recipient, value)))
        );
    }

    function test_userOp_executeLimit() public {
        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(_getExecuteWithSpend(5 ether)), bytes32(0));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 5 ether);
    }

    function test_userOp_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.transfer, (recipient, 5 ether + 100000))
        });

        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(abi.encodeCall(IStandardExecutor.executeBatch, (calls))), bytes32(0));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether - 6 ether - 100001);
    }

    function test_userOp_executeBatch_approveAndTransferLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 5 ether + 100000))
        });

        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        acct.executeUserOp(_getPackedUO(abi.encodeCall(IStandardExecutor.executeBatch, (calls))), bytes32(0));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether - 6 ether - 100001);
    }

    function test_userOp_executeBatch_approveAndTransferLimit_fail() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 9 ether + 100000))
        });

        vm.startPrank(address(entryPoint));
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        PackedUserOperation[] memory uos = new PackedUserOperation[](1);
        uos[0] = _getPackedUO(abi.encodeCall(IStandardExecutor.executeBatch, (calls)));
        entryPoint.handleOps(uos, bundler);
        // no spend consumed
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
    }

    function test_runtime_executeLimit() public {
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        acct.executeWithAuthorization(
            _getExecuteWithSpend(5 ether),
            _encodeSignature(FunctionReferenceLib.pack(address(validationPlugin), 0), 1, "")
        );
        assertEq(plugin.limits(0, address(erc20), address(acct)), 5 ether);
    }

    function test_runtime_executeBatchLimit() public {
        Call[] memory calls = new Call[](3);
        calls[0] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.approve, (recipient, 1 wei))});
        calls[1] =
            Call({target: address(erc20), value: 0, data: abi.encodeCall(IERC20.transfer, (recipient, 1 ether))});
        calls[2] = Call({
            target: address(erc20),
            value: 0,
            data: abi.encodeCall(IERC20.approve, (recipient, 5 ether + 100000))
        });

        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether);
        acct.executeWithAuthorization(
            abi.encodeCall(IStandardExecutor.executeBatch, (calls)),
            _encodeSignature(FunctionReferenceLib.pack(address(validationPlugin), 0), 1, "")
        );
        assertEq(plugin.limits(0, address(erc20), address(acct)), 10 ether - 6 ether - 100001);
    }
}
