// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {BasePlugin} from "../../src/plugins/BasePlugin.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {BaseSessionKeyPlugin} from "../../src/plugins/session-key/BaseSessionKeyPlugin.sol";
import {ISessionKeyPlugin} from "../../src/plugins/session-key/interfaces/ISessionKeyPlugin.sol";
import {TokenSessionKeyPlugin} from "../../src/plugins/session-key/TokenSessionKeyPlugin.sol";
import {ITokenSessionKeyPlugin} from "../../src/plugins/session-key/interfaces/ITokenSessionKeyPlugin.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {MockERC20} from "../mocks/MockERC20.sol";

contract SessionKeyPluginTest is Test {
    using ECDSA for bytes32;
    using FunctionReferenceLib for address;

    SingleOwnerPlugin public ownerPlugin;
    BaseSessionKeyPlugin public baseSessionKeyPlugin;
    TokenSessionKeyPlugin public tokenSessionKeyPlugin;
    EntryPoint public entryPoint;
    MSCAFactoryFixture public factory;
    UpgradeableModularAccount public account;

    MockERC20 public mockERC20impl;
    MockERC20 public mockERC20;
    address public mockEmptyERC20Addr;

    address public owner;
    uint256 public ownerKey;

    address public maliciousOwner;

    address public tempOwner;
    uint256 public tempOwnerKey;

    address payable public beneficiary;

    uint256 public constant CALL_GAS_LIMIT = 150000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 3600000;

    bytes4 public constant TRANSFERFROM_SESSIONKEY_SELECTOR = ITokenSessionKeyPlugin.transferFromSessionKey.selector;

    // Event declarations (needed for vm.expectEmit)
    event UserOperationRevertReason(
        bytes32 indexed userOpHash,
        address indexed sender,
        uint256 nonce,
        bytes revertReason
    );
    event TemporaryOwnerAdded(
        address indexed account,
        address indexed tempOwner,
        bytes4 allowedSelector,
        uint48 _after,
        uint48 _until
    );
    event TemporaryOwnerRemoved(address indexed account, address indexed tempOwner, bytes4 allowedSelector);

    function setUp() public {
        ownerPlugin = new SingleOwnerPlugin();
        baseSessionKeyPlugin = new BaseSessionKeyPlugin();
        tokenSessionKeyPlugin = new TokenSessionKeyPlugin();

        entryPoint = new EntryPoint();
        factory = new MSCAFactoryFixture(entryPoint, ownerPlugin);
        mockERC20impl = new MockERC20("Mock", "MCK");

        // Etching MockERC20 code into hardcoded address at TokenSessionKeyPlugin
        mockEmptyERC20Addr = tokenSessionKeyPlugin.TARGET_ERC20_CONTRACT();
        bytes memory code = address(mockERC20impl).code;
        vm.etch(mockEmptyERC20Addr, code);
        mockERC20 = MockERC20(mockEmptyERC20Addr);

        (owner, ownerKey) = makeAddrAndKey("owner");
        (maliciousOwner, ) = makeAddrAndKey("maliciousOwner");
        (tempOwner, tempOwnerKey) = makeAddrAndKey("tempOwner");

        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);
        vm.deal(owner, 10 ether);

        // Here, SingleOwnerPlugin already installed in factory
        account = factory.createAccount(owner, 0);

        // Mint Mock ERC20 Tokens to account
        mockERC20.mint(address(account), 1 ether);
        // Fund the account with some ether
        vm.deal(address(account), 1 ether);

        vm.startPrank(owner);
        FunctionReference[] memory baseSessionDependency = new FunctionReference[](2);
        baseSessionDependency[0] = address(ownerPlugin).pack(
            uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        baseSessionDependency[1] = address(ownerPlugin).pack(
            uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );

        bytes32 baseSessionKeyManifestHash = keccak256(abi.encode(baseSessionKeyPlugin.pluginManifest()));

        account.installPlugin({
            plugin: address(baseSessionKeyPlugin),
            manifestHash: baseSessionKeyManifestHash,
            pluginInitData: "",
            dependencies: baseSessionDependency,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        FunctionReference[] memory tokenSessionDependency = new FunctionReference[](2);
        tokenSessionDependency[0] = address(baseSessionKeyPlugin).pack(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER)
        );
        tokenSessionDependency[1] = address(baseSessionKeyPlugin).pack(
            uint8(ISessionKeyPlugin.FunctionId.RUNTIME_VALIDATION_TEMPORARY_OWNER)
        );
        bytes32 tokenSessionKeyManifestHash =
            keccak256(abi.encode(tokenSessionKeyPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(tokenSessionKeyPlugin),
            manifestHash: tokenSessionKeyManifestHash,
            pluginInitData: "",
            dependencies: tokenSessionDependency,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
        vm.stopPrank();

        vm.startPrank(address(account));
        mockERC20.approve(address(account), 1 ether);

        vm.expectEmit(true, true, true, true);
        emit TemporaryOwnerAdded(address(account), tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR, 0, 2);
        baseSessionKeyPlugin.addTemporaryOwner(tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR, 0, 2);
        
        (uint48 _after, uint48 _until) = 
            baseSessionKeyPlugin.getSessionDuration(address(account), tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR);
        
        assertEq(_after, 0);
        assertEq(_until, 2);
        vm.stopPrank();
    }

    function test_sessionKey_userOp() public {
        UserOperation[] memory userOps = new UserOperation[](1);

        (, UserOperation memory userOp) = _constructUserOp(address(mockERC20), address(account), beneficiary, 1 ether);
        userOps[0] = userOp;
        
        entryPoint.handleOps(userOps, beneficiary);
        
        assertEq(mockERC20.balanceOf(address(account)), 0);
        assertEq(mockERC20.balanceOf(beneficiary), 1 ether);
    }

    function test_sessionKey_runtime() public {
        vm.prank(address(tempOwner));
        TokenSessionKeyPlugin(address(account)).transferFromSessionKey(
            address(mockERC20), address(account), beneficiary, 1 ether
        );

        assertEq(mockERC20.balanceOf(address(account)), 0);
        assertEq(mockERC20.balanceOf(beneficiary), 1 ether);
    }

    function test_sessionKey_removeTempOwner() public {
        vm.startPrank(address(account));
        
        vm.expectEmit(true, true, true, true);
        emit TemporaryOwnerRemoved(address(account), tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR);
        baseSessionKeyPlugin.removeTemporaryOwner(tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR);
        
        vm.stopPrank();
        
        (uint48 _after, uint48 _until) = 
            baseSessionKeyPlugin.getSessionDuration(address(account), tempOwner, TRANSFERFROM_SESSIONKEY_SELECTOR);
        assertEq(_after, 0);
        assertEq(_until, 0);

        // Check if tempOwner can still send user operations
        vm.startPrank(address(tempOwner));

        bytes memory revertReason = abi.encodeWithSelector(
            BasePlugin.NotImplemented.selector
        );
        vm.expectRevert(abi.encodeWithSelector(
            UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
            address(baseSessionKeyPlugin),
            ISessionKeyPlugin.FunctionId.RUNTIME_VALIDATION_TEMPORARY_OWNER,
            revertReason
        ));
        TokenSessionKeyPlugin(address(account)).transferFromSessionKey(
            address(mockERC20), address(account), beneficiary, 1 ether
        );
    }

    function test_sessionKey_invalidContractFails() public {
        address wrongERC20Contract = makeAddr("wrongERC20Contract");
        (bytes32 userOpHash, UserOperation memory userOp) =
            _constructUserOp(address(wrongERC20Contract), address(account), beneficiary, 1 ether);
        
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        bytes memory revertCallData = abi.encodeWithSelector(
            tokenSessionKeyPlugin.TRANSFERFROM_SELECTOR(),
            address(account),
            beneficiary,
            1 ether
        );
        bytes memory revertReason = abi.encodeWithSelector(
            UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
            address(tokenSessionKeyPlugin),
            address(wrongERC20Contract),
            0,
            revertCallData
        );
        vm.expectEmit(true, true, true, true);
        emit UserOperationRevertReason(userOpHash, address(account), 0, revertReason);
        
        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_sessionKey_unregisteredTempOwnerFails() public {
        vm.prank(address(maliciousOwner));
        bytes memory revertReason = abi.encodeWithSelector(
            BasePlugin.NotImplemented.selector
        );

        vm.expectRevert(abi.encodeWithSelector(
            UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
            address(baseSessionKeyPlugin),
            ISessionKeyPlugin.FunctionId.RUNTIME_VALIDATION_TEMPORARY_OWNER,
            revertReason
        ));
        TokenSessionKeyPlugin(address(account)).transferFromSessionKey(
            address(mockERC20), address(account), beneficiary, 1 ether
        );
    }

    function test_sessionKey_invalidSessionDurationFails() public {
        // Move block.timestamp to 12345
        vm.warp(12345);

        vm.startPrank(address(tempOwner));

        bytes memory revertReason = abi.encodeWithSelector(
            ISessionKeyPlugin.WrongTimeRangeForSession.selector
        );

        vm.expectRevert(abi.encodeWithSelector(
            UpgradeableModularAccount.RuntimeValidationFunctionReverted.selector,
            address(baseSessionKeyPlugin),
            ISessionKeyPlugin.FunctionId.RUNTIME_VALIDATION_TEMPORARY_OWNER,
            revertReason
        ));
        TokenSessionKeyPlugin(address(account)).transferFromSessionKey(
            address(mockERC20), address(account), beneficiary, 1 ether
    );
    }

    // Internal Function
    function _constructUserOp(address targetContract, address from, address to, uint256 amount) internal view
    returns (bytes32, UserOperation memory) {
        bytes memory userOpCallData =  abi.encodeCall(
            TokenSessionKeyPlugin.transferFromSessionKey,
            (targetContract, from, to, amount)
        );

        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: userOpCallData,
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(tempOwnerKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        return (userOpHash, userOp);
    }
}

