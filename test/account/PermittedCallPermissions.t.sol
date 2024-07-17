// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {PermittedCallerPlugin} from "../mocks/plugins/PermittedCallMocks.sol";
import {ResultCreatorPlugin} from "../mocks/plugins/ReturnDataPluginMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PermittedCallPermissionsTest is AccountTestBase {
    ResultCreatorPlugin public resultCreatorPlugin;

    PermittedCallerPlugin public permittedCallerPlugin;

    function setUp() public {
        _transferOwnershipToTest();
        resultCreatorPlugin = new ResultCreatorPlugin();

        // Initialize the permitted caller plugins, which will attempt to use the permissions system to authorize
        // calls.
        permittedCallerPlugin = new PermittedCallerPlugin();

        // Add the result creator plugin to the account
        bytes32 resultCreatorManifestHash = keccak256(abi.encode(resultCreatorPlugin.pluginManifest()));
        vm.prank(address(entryPoint));
        account1.installPlugin({
            plugin: address(resultCreatorPlugin),
            manifestHash: resultCreatorManifestHash,
            pluginInstallData: ""
        });
        // Add the permitted caller plugin to the account
        bytes32 permittedCallerManifestHash = keccak256(abi.encode(permittedCallerPlugin.pluginManifest()));
        vm.prank(address(entryPoint));
        account1.installPlugin({
            plugin: address(permittedCallerPlugin),
            manifestHash: permittedCallerManifestHash,
            pluginInstallData: ""
        });
    }

    function test_permittedCall_Allowed() public {
        bytes memory result = PermittedCallerPlugin(address(account1)).usePermittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_permittedCall_NotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ValidationFunctionMissing.selector, ResultCreatorPlugin.bar.selector
            )
        );
        PermittedCallerPlugin(address(account1)).usePermittedCallNotAllowed();
    }
}
