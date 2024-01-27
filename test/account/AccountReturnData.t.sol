// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {Call} from "../../src/interfaces/IStandardExecutor.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {
    RegularResultContract,
    ResultCreatorPlugin,
    ResultConsumerPlugin
} from "../mocks/plugins/ReturnDataPluginMocks.sol";
import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

// Tests all the different ways that return data can be read from plugins through an account
contract AccountReturnDataTest is OptimizedTest {
    EntryPoint public entryPoint; // Just to be able to construct the factory
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;

    RegularResultContract public regularResultContract;
    ResultCreatorPlugin public resultCreatorPlugin;
    ResultConsumerPlugin public resultConsumerPlugin;

    UpgradeableModularAccount public account;

    function setUp() public {
        entryPoint = new EntryPoint();
        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        regularResultContract = new RegularResultContract();
        resultCreatorPlugin = new ResultCreatorPlugin();
        resultConsumerPlugin = new ResultConsumerPlugin(resultCreatorPlugin, regularResultContract);

        // Create an account with "this" as the owner, so we can execute along the runtime path with regular
        // solidity semantics
        account = factory.createAccount(address(this), 0);

        // Add the result creator plugin to the account
        bytes32 resultCreatorManifestHash = keccak256(abi.encode(resultCreatorPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(resultCreatorPlugin),
            manifestHash: resultCreatorManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
        // Add the result consumer plugin to the account
        bytes32 resultConsumerManifestHash = keccak256(abi.encode(resultConsumerPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(resultConsumerPlugin),
            manifestHash: resultConsumerManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Tests the ability to read the result of plugin execution functions via the account's fallback
    function test_returnData_fallback() public {
        bytes32 result = ResultCreatorPlugin(address(account)).foo();

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of contracts called via IStandardExecutor.execute
    function test_returnData_singular_execute() public {
        bytes memory returnData =
            account.execute(address(regularResultContract), 0, abi.encodeCall(RegularResultContract.foo, ()));

        bytes32 result = abi.decode(returnData, (bytes32));

        assertEq(result, keccak256("bar"));
    }

    // Tests the ability to read the results of multiple contract calls via IStandardExecutor.executeBatch
    function test_returnData_executeBatch() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.foo, ())
        });
        calls[1] = Call({
            target: address(regularResultContract),
            value: 0,
            data: abi.encodeCall(RegularResultContract.bar, ())
        });

        bytes[] memory returnDatas = account.executeBatch(calls);

        bytes32 result1 = abi.decode(returnDatas[0], (bytes32));
        bytes32 result2 = abi.decode(returnDatas[1], (bytes32));

        assertEq(result1, keccak256("bar"));
        assertEq(result2, keccak256("foo"));
    }

    // Tests the ability to read data via executeFromPlugin routing to fallback functions
    function test_returnData_execFromPlugin_fallback() public {
        bool result = ResultConsumerPlugin(address(account)).checkResultEFPFallback(keccak256("bar"));

        assertTrue(result);
    }

    // Tests the ability to read data via executeFromPluginExternal
    function test_returnData_execFromPlugin_execute() public {
        bool result = ResultConsumerPlugin(address(account)).checkResultEFPExternal(
            address(regularResultContract), keccak256("bar")
        );

        assertTrue(result);
    }
}
