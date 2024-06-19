// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {console} from "forge-std/Test.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {PluginManagerInternals} from "../../src/account/PluginManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/helpers/FunctionReferenceLib.sol";
import {IPlugin, PluginManifest} from "../../src/interfaces/IPlugin.sol";
import {IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {Call} from "../../src/interfaces/IStandardExecutor.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {TokenReceiverPlugin} from "../../src/plugins/TokenReceiverPlugin.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";

import {Counter} from "../mocks/Counter.sol";
import {ComprehensivePlugin} from "../mocks/plugins/ComprehensivePlugin.sol";
import {MockPlugin} from "../mocks/MockPlugin.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract UpgradeableModularAccountTest is AccountTestBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    TokenReceiverPlugin public tokenReceiverPlugin;

    // A separate account and owner that isn't deployed yet, used to test initcode
    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account2;

    address public ethRecipient;
    Counter public counter;
    PluginManifest public manifest;

    FunctionReference public ownerValidation;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;

    event PluginInstalled(address indexed plugin, bytes32 manifestHash, FunctionReference[] dependencies);
    event PluginUninstalled(address indexed plugin, bool indexed callbacksSucceeded);
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        tokenReceiverPlugin = _deployTokenReceiverPlugin();

        (owner2, owner2Key) = makeAddrAndKey("owner2");

        // Compute counterfactual address
        account2 = UpgradeableModularAccount(payable(factory.getAddress(owner2, 0)));
        vm.deal(address(account2), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
        counter = new Counter();
        counter.increment(); // amoritze away gas cost of zero->nonzero transition

        ownerValidation = FunctionReferenceLib.pack(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER)
        );
    }

    function test_deployAccount() public {
        factory.createAccount(owner2, 0);
    }

    function test_postDeploy_ethSend() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
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
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_basicUserOp_withInitCode() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner2, 0))),
            callData: abi.encodeCall(
                UpgradeableModularAccount.execute,
                (address(singleOwnerPlugin), 0, abi.encodeCall(SingleOwnerPlugin.transferOwnership, (owner2)))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 2),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    function test_standardExecuteEthSend_withInitcode() public {
        address payable recipient = payable(makeAddr("recipient"));

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account2),
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner2, 0))),
            callData: abi.encodeCall(UpgradeableModularAccount.execute, (recipient, 1 wei, "")),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner2Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(recipient.balance, 1 wei);
    }

    function test_debug_upgradeableModularAccount_storageAccesses() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
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
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        vm.record();
        entryPoint.handleOps(userOps, beneficiary);
        _printStorageReadsAndWrites(address(account2));
    }

    function test_contractInteraction() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                UpgradeableModularAccount.execute, (address(counter), 0, abi.encodeCall(counter.increment, ()))
            ),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
    }

    function test_batchExecute() public {
        // Performs both an eth send and a contract interaction with counter
        Call[] memory calls = new Call[](2);
        calls[0] = Call({target: ethRecipient, value: 1 wei, data: ""});
        calls[1] = Call({target: address(counter), value: 0, data: abi.encodeCall(counter.increment, ())});

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(UpgradeableModularAccount.executeBatch, (calls)),
            accountGasLimits: _encodeGas(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
            preVerificationGas: 0,
            gasFees: _encodeGas(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(ownerValidation, SELECTOR_ASSOCIATED_VALIDATION, r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_installPlugin() public {
        vm.startPrank(address(entryPoint));

        bytes32 manifestHash = keccak256(abi.encode(tokenReceiverPlugin.pluginManifest()));

        vm.expectEmit(true, true, true, true);
        emit PluginInstalled(address(tokenReceiverPlugin), manifestHash, new FunctionReference[](0));
        IPluginManager(account1).installPlugin({
            plugin: address(tokenReceiverPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(uint48(1 days)),
            dependencies: new FunctionReference[](0)
        });

        address[] memory plugins = IAccountLoupe(account1).getInstalledPlugins();
        assertEq(plugins.length, 2);
        assertEq(plugins[0], address(singleOwnerPlugin));
        assertEq(plugins[1], address(tokenReceiverPlugin));
    }

    function test_installPlugin_ExecuteFromPlugin_PermittedExecSelectorNotInstalled() public {
        vm.startPrank(address(entryPoint));

        PluginManifest memory m;
        m.permittedExecutionSelectors = new bytes4[](1);
        m.permittedExecutionSelectors[0] = IPlugin.onInstall.selector;

        MockPlugin mockPluginWithBadPermittedExec = new MockPlugin(m);
        bytes32 manifestHash = keccak256(abi.encode(mockPluginWithBadPermittedExec.pluginManifest()));

        IPluginManager(account1).installPlugin({
            plugin: address(mockPluginWithBadPermittedExec),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_invalidManifest() public {
        vm.startPrank(address(entryPoint));

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account1).installPlugin({
            plugin: address(tokenReceiverPlugin),
            manifestHash: bytes32(0),
            pluginInstallData: abi.encode(uint48(1 days)),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_interfaceNotSupported() public {
        vm.startPrank(address(entryPoint));

        address badPlugin = address(1);
        vm.expectRevert(
            abi.encodeWithSelector(PluginManagerInternals.PluginInterfaceNotSupported.selector, address(badPlugin))
        );
        IPluginManager(account1).installPlugin({
            plugin: address(badPlugin),
            manifestHash: bytes32(0),
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    function test_installPlugin_alreadyInstalled() public {
        vm.startPrank(address(entryPoint));

        bytes32 manifestHash = keccak256(abi.encode(tokenReceiverPlugin.pluginManifest()));
        IPluginManager(account1).installPlugin({
            plugin: address(tokenReceiverPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(uint48(1 days)),
            dependencies: new FunctionReference[](0)
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                PluginManagerInternals.PluginAlreadyInstalled.selector, address(tokenReceiverPlugin)
            )
        );
        IPluginManager(account1).installPlugin({
            plugin: address(tokenReceiverPlugin),
            manifestHash: manifestHash,
            pluginInstallData: abi.encode(uint48(1 days)),
            dependencies: new FunctionReference[](0)
        });
    }

    function test_uninstallPlugin_default() public {
        vm.startPrank(address(entryPoint));

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));
        IPluginManager(account1).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);
        IPluginManager(account1).uninstallPlugin({plugin: address(plugin), config: "", pluginUninstallData: ""});
        address[] memory plugins = IAccountLoupe(account1).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(singleOwnerPlugin));
    }

    function test_uninstallPlugin_manifestParameter() public {
        vm.startPrank(address(entryPoint));

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes memory serializedManifest = abi.encode(plugin.pluginManifest());
        bytes32 manifestHash = keccak256(serializedManifest);
        IPluginManager(account1).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        vm.expectEmit(true, true, true, true);
        emit PluginUninstalled(address(plugin), true);
        IPluginManager(account1).uninstallPlugin({
            plugin: address(plugin),
            config: serializedManifest,
            pluginUninstallData: ""
        });
        address[] memory plugins = IAccountLoupe(account1).getInstalledPlugins();
        assertEq(plugins.length, 1);
        assertEq(plugins[0], address(singleOwnerPlugin));
    }

    function test_uninstallPlugin_invalidManifestFails() public {
        vm.startPrank(address(entryPoint));

        ComprehensivePlugin plugin = new ComprehensivePlugin();
        bytes memory serializedManifest = abi.encode(plugin.pluginManifest());
        bytes32 manifestHash = keccak256(serializedManifest);
        IPluginManager(account1).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Attempt to uninstall with a blank manifest
        PluginManifest memory blankManifest;

        vm.expectRevert(abi.encodeWithSelector(PluginManagerInternals.InvalidPluginManifest.selector));
        IPluginManager(account1).uninstallPlugin({
            plugin: address(plugin),
            config: abi.encode(blankManifest),
            pluginUninstallData: ""
        });
        address[] memory plugins = IAccountLoupe(account1).getInstalledPlugins();
        assertEq(plugins.length, 2);
        assertEq(plugins[0], address(singleOwnerPlugin));
        assertEq(plugins[1], address(plugin));
    }

    function _installPluginWithExecHooks() internal returns (MockPlugin plugin) {
        vm.startPrank(address(entryPoint));

        plugin = new MockPlugin(manifest);
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        IPluginManager(account1).installPlugin({
            plugin: address(plugin),
            manifestHash: manifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        vm.stopPrank();
    }

    function test_upgradeToAndCall() public {
        vm.startPrank(address(entryPoint));
        UpgradeableModularAccount account3 = new UpgradeableModularAccount(entryPoint);
        bytes32 slot = account3.proxiableUUID();

        // account has impl from factory
        assertEq(
            address(factory.accountImplementation()), address(uint160(uint256(vm.load(address(account1), slot))))
        );
        account1.upgradeToAndCall(address(account3), bytes(""));
        // account has new impl
        assertEq(address(account3), address(uint160(uint256(vm.load(address(account1), slot)))));
    }

    function test_transferOwnership() public {
        assertEq(singleOwnerPlugin.ownerOf(address(account1)), owner1);

        vm.prank(address(entryPoint));
        account1.execute(
            address(singleOwnerPlugin), 0, abi.encodeCall(SingleOwnerPlugin.transferOwnership, (owner2))
        );

        assertEq(singleOwnerPlugin.ownerOf(address(account1)), owner2);
    }

    function test_isValidSignature() public {
        bytes32 message = keccak256("hello world");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, message);

        // singleOwnerPlugin.ownerOf(address(account1));

        bytes memory signature = abi.encodePacked(
            address(singleOwnerPlugin), uint8(ISingleOwnerPlugin.FunctionId.SIG_VALIDATION), r, s, v
        );

        bytes4 validationResult = IERC1271(address(account1)).isValidSignature(message, signature);

        assertEq(validationResult, bytes4(0x1626ba7e));
    }

    // Internal Functions

    function _printStorageReadsAndWrites(address addr) internal {
        (bytes32[] memory accountReads, bytes32[] memory accountWrites) = vm.accesses(addr);
        for (uint256 i = 0; i < accountWrites.length; i++) {
            bytes32 valWritten = vm.load(addr, accountWrites[i]);
            // solhint-disable-next-line no-console
            console.log(
                string.concat("write loc: ", vm.toString(accountWrites[i]), " val: ", vm.toString(valWritten))
            );
        }

        for (uint256 i = 0; i < accountReads.length; i++) {
            bytes32 valRead = vm.load(addr, accountReads[i]);
            // solhint-disable-next-line no-console
            console.log(string.concat("read: ", vm.toString(accountReads[i]), " val: ", vm.toString(valRead)));
        }
    }
}
