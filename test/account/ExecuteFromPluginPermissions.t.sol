// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {console} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";

import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {Counter} from "../mocks/Counter.sol";
import {ResultCreatorPlugin} from "../mocks/plugins/ReturnDataPluginMocks.sol";
import {EFPCallerPlugin, EFPCallerPluginAnyExternal} from "../mocks/plugins/ExecFromPluginPermissionsMocks.sol";
import {OptimizedTest} from "../utils/OptimizedTest.sol";

contract ExecuteFromPluginPermissionsTest is OptimizedTest {
    Counter public counter1;
    Counter public counter2;
    Counter public counter3;
    ResultCreatorPlugin public resultCreatorPlugin;

    EntryPoint public entryPoint; // Just to be able to construct the factory
    SingleOwnerPlugin public singleOwnerPlugin;
    MSCAFactoryFixture public factory;
    UpgradeableModularAccount public account;

    EFPCallerPlugin public efpCallerPlugin;
    EFPCallerPluginAnyExternal public efpCallerPluginAnyExternal;

    function setUp() public {
        // Initialize the interaction targets
        counter1 = new Counter();
        counter2 = new Counter();
        counter3 = new Counter();
        resultCreatorPlugin = new ResultCreatorPlugin();

        // Initialize the contracts needed to use the account.
        entryPoint = new EntryPoint();
        singleOwnerPlugin = _deploySingleOwnerPlugin();
        factory = new MSCAFactoryFixture(entryPoint, singleOwnerPlugin);

        // Initialize the EFP caller plugins, which will attempt to use the permissions system to authorize calls.
        efpCallerPlugin = new EFPCallerPlugin();
        efpCallerPluginAnyExternal = new EFPCallerPluginAnyExternal();

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
        // Add the EFP caller plugin to the account
        bytes32 efpCallerManifestHash = keccak256(abi.encode(efpCallerPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPlugin),
            manifestHash: efpCallerManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });

        // Add the EFP caller plugin with any external permissions to the account
        bytes32 efpCallerAnyExternalManifestHash =
            keccak256(abi.encode(efpCallerPluginAnyExternal.pluginManifest()));
        account.installPlugin({
            plugin: address(efpCallerPluginAnyExternal),
            manifestHash: efpCallerAnyExternalManifestHash,
            pluginInstallData: "",
            dependencies: new FunctionReference[](0)
        });
    }

    // Report the addresses to be used in the address constants in ExecFromPluginPermissionsMocks.sol
    function test_getPermissionsTestAddresses() public view {
        // solhint-disable no-console
        console.log("counter1 address: %s", address(counter1));
        console.log("counter2 address: %s", address(counter2));
        console.log("counter3 address: %s", address(counter3));
        console.log("resultCreatorPlugin address: %s", address(resultCreatorPlugin));
        // solhint-enable no-console
    }

    function test_executeFromPluginAllowed() public {
        bytes memory result = EFPCallerPlugin(address(account)).useEFPPermissionAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_executeFromPluginNotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginNotPermitted.selector,
                address(efpCallerPlugin),
                ResultCreatorPlugin.bar.selector
            )
        );
        EFPCallerPlugin(address(account)).useEFPPermissionNotAllowed();
    }

    function test_executeFromPluginExternal_Allowed_IndividualSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter1(17);
        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter1();

        assertEq(retrievedNumber, 17);
    }

    function test_executeFromPluginExternal_NotAlowed_IndividualSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter1(17);

        // Call to increment should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter1),
                0,
                abi.encodePacked(Counter.increment.selector)
            )
        );
        EFPCallerPlugin(address(account)).incrementCounter1();

        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter1();

        assertEq(retrievedNumber, 17);
    }

    function test_executeFromPluginExternal_Allowed_AllSelectors() public {
        EFPCallerPlugin(address(account)).setNumberCounter2(17);
        EFPCallerPlugin(address(account)).incrementCounter2();
        uint256 retrievedNumber = EFPCallerPlugin(address(account)).getNumberCounter2();

        assertEq(retrievedNumber, 18);
    }

    function test_executeFromPluginExternal_NotAllowed_AllSelectors() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodeWithSelector(Counter.setNumber.selector, uint256(17))
            )
        );
        EFPCallerPlugin(address(account)).setNumberCounter3(17);

        // Call to increment should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodePacked(Counter.increment.selector)
            )
        );
        EFPCallerPlugin(address(account)).incrementCounter3();

        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ExecFromPluginExternalNotPermitted.selector,
                address(efpCallerPlugin),
                address(counter3),
                0,
                abi.encodePacked(bytes4(keccak256("number()")))
            )
        );
        EFPCallerPlugin(address(account)).getNumberCounter3();

        // Validate no state changes
        assert(counter3.number() == 0);
    }

    function test_executeFromPluginExternal_Allowed_AnyContract() public {
        // Run full workflow for counter 1

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodeCall(Counter.setNumber, (17))
        );
        uint256 retrievedNumber = counter1.number();
        assertEq(retrievedNumber, 17);

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodeCall(Counter.increment, ())
        );
        retrievedNumber = counter1.number();
        assertEq(retrievedNumber, 18);

        bytes memory result = EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter1), 0, abi.encodePacked(bytes4(keccak256("number()")))
        );
        retrievedNumber = abi.decode(result, (uint256));
        assertEq(retrievedNumber, 18);

        // Run full workflow for counter 2

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodeCall(Counter.setNumber, (17))
        );
        retrievedNumber = counter2.number();
        assertEq(retrievedNumber, 17);

        EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodeCall(Counter.increment, ())
        );
        retrievedNumber = counter2.number();
        assertEq(retrievedNumber, 18);

        result = EFPCallerPluginAnyExternal(address(account)).passthroughExecute(
            address(counter2), 0, abi.encodePacked(bytes4(keccak256("number()")))
        );
        retrievedNumber = abi.decode(result, (uint256));
        assertEq(retrievedNumber, 18);
    }
}
