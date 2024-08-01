// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {console} from "forge-std/Test.sol";

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ModuleManagerInternals} from "../../src/account/ModuleManagerInternals.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {ExecutionDataView, IAccountLoupe} from "../../src/interfaces/IAccountLoupe.sol";
import {ExecutionManifest} from "../../src/interfaces/IExecution.sol";
import {IModuleManager} from "../../src/interfaces/IModuleManager.sol";
import {Call} from "../../src/interfaces/IStandardExecutor.sol";

import {TokenReceiverModule} from "../../src/modules/TokenReceiverModule.sol";
import {SingleSignerValidation} from "../../src/modules/validation/SingleSignerValidation.sol";

import {Counter} from "../mocks/Counter.sol";

import {MockModule} from "../mocks/MockModule.sol";
import {ComprehensiveModule} from "../mocks/modules/ComprehensiveModule.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";

contract UpgradeableModularAccountTest is AccountTestBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    TokenReceiverModule public tokenReceiverModule;

    // A separate account and owner that isn't deployed yet, used to test initcode
    address public owner2;
    uint256 public owner2Key;
    UpgradeableModularAccount public account2;

    address public ethRecipient;
    Counter public counter;
    ExecutionManifest internal _manifest;

    event ExecutionInstalled(address indexed module, ExecutionManifest manifest);
    event ExecutionUninstalled(address indexed module, bool onUninstallSucceeded, ExecutionManifest manifest);
    event ReceivedCall(bytes msgData, uint256 msgValue);

    function setUp() public {
        tokenReceiverModule = _deployTokenReceiverModule();

        (owner2, owner2Key) = makeAddrAndKey("owner2");

        // Compute counterfactual address
        account2 = UpgradeableModularAccount(payable(factory.getAddress(owner2, 0)));
        vm.deal(address(account2), 100 ether);

        ethRecipient = makeAddr("ethRecipient");
        vm.deal(ethRecipient, 1 wei);
        counter = new Counter();
        counter.increment(); // amoritze away gas cost of zero->nonzero transition
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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
                (
                    address(singleSignerValidation),
                    0,
                    abi.encodeCall(SingleSignerValidation.transferSigner, (TEST_DEFAULT_VALIDATION_ENTITY_ID, owner2))
                )
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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

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
        userOp.signature = _encodeSignature(_signerValidation, GLOBAL_VALIDATION, abi.encodePacked(r, s, v));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);

        assertEq(counter.number(), 2);
        assertEq(ethRecipient.balance, 2 wei);
    }

    function test_installExecution() public {
        vm.startPrank(address(entryPoint));

        vm.expectEmit(true, true, true, true);
        emit ExecutionInstalled(address(tokenReceiverModule), tokenReceiverModule.executionManifest());
        IModuleManager(account1).installExecution({
            module: address(tokenReceiverModule),
            manifest: tokenReceiverModule.executionManifest(),
            moduleInstallData: abi.encode(uint48(1 days))
        });

        ExecutionDataView memory data =
            IAccountLoupe(account1).getExecutionData(TokenReceiverModule.onERC721Received.selector);
        assertEq(data.module, address(tokenReceiverModule));
    }

    function test_installExecution_PermittedCallSelectorNotInstalled() public {
        vm.startPrank(address(entryPoint));

        ExecutionManifest memory m;

        MockModule mockModuleWithBadPermittedExec = new MockModule(m);

        IModuleManager(account1).installExecution({
            module: address(mockModuleWithBadPermittedExec),
            manifest: mockModuleWithBadPermittedExec.executionManifest(),
            moduleInstallData: ""
        });
    }

    function test_installExecution_interfaceNotSupported() public {
        vm.startPrank(address(entryPoint));

        address badModule = address(1);
        vm.expectRevert(
            abi.encodeWithSelector(ModuleManagerInternals.ModuleInterfaceNotSupported.selector, address(badModule))
        );

        ExecutionManifest memory m;

        IModuleManager(account1).installExecution({module: address(badModule), manifest: m, moduleInstallData: ""});
    }

    function test_installExecution_alreadyInstalled() public {
        ExecutionManifest memory m = tokenReceiverModule.executionManifest();

        vm.prank(address(entryPoint));
        IModuleManager(account1).installExecution({
            module: address(tokenReceiverModule),
            manifest: m,
            moduleInstallData: abi.encode(uint48(1 days))
        });

        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(
                ModuleManagerInternals.ExecutionFunctionAlreadySet.selector,
                TokenReceiverModule.onERC721Received.selector
            )
        );
        IModuleManager(account1).installExecution({
            module: address(tokenReceiverModule),
            manifest: m,
            moduleInstallData: abi.encode(uint48(1 days))
        });
    }

    function test_uninstallExecution_default() public {
        vm.startPrank(address(entryPoint));

        ComprehensiveModule module = new ComprehensiveModule();
        IModuleManager(account1).installExecution({
            module: address(module),
            manifest: module.executionManifest(),
            moduleInstallData: ""
        });

        vm.expectEmit(true, true, true, true);
        emit ExecutionUninstalled(address(module), true, module.executionManifest());
        IModuleManager(account1).uninstallExecution({
            module: address(module),
            manifest: module.executionManifest(),
            moduleUninstallData: ""
        });

        ExecutionDataView memory data = IAccountLoupe(account1).getExecutionData(module.foo.selector);
        assertEq(data.module, address(0));
    }

    function _installExecutionWithExecHooks() internal returns (MockModule module) {
        vm.startPrank(address(entryPoint));

        module = new MockModule(_manifest);

        IModuleManager(account1).installExecution({
            module: address(module),
            manifest: module.executionManifest(),
            moduleInstallData: ""
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
        assertEq(singleSignerValidation.signers(TEST_DEFAULT_VALIDATION_ENTITY_ID, address(account1)), owner1);

        vm.prank(address(entryPoint));
        account1.execute(
            address(singleSignerValidation),
            0,
            abi.encodeCall(SingleSignerValidation.transferSigner, (TEST_DEFAULT_VALIDATION_ENTITY_ID, owner2))
        );

        assertEq(singleSignerValidation.signers(TEST_DEFAULT_VALIDATION_ENTITY_ID, address(account1)), owner2);
    }

    function test_isValidSignature() public {
        bytes32 message = keccak256("hello world");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, message);

        // singleSignerValidation.ownerOf(address(account1));

        bytes memory signature =
            abi.encodePacked(address(singleSignerValidation), TEST_DEFAULT_VALIDATION_ENTITY_ID, r, s, v);

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
