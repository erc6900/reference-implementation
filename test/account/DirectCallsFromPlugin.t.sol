pragma solidity ^0.8.19;

import {DirectCallPlugin} from "../mocks/plugins/DirectCallPlugin.sol";
import {IPlugin, PluginManifest} from "../../src/interfaces/IPlugin.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DirectCallsFromPluginTest is AccountTestBase {
    DirectCallPlugin plugin;

    function setUp() public {
        plugin = new DirectCallPlugin();
    }

    function test_Fail_DirectCallPluginNotInstalled() external {
        vm.prank(address(plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallPluginUninstalled() external {
        _installPlugin();

        vm.prank(address(entryPoint));
        account1.uninstallPlugin(address(plugin), "", "");

        vm.prank(address(plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallPluginCallOtherSelector() external {
        _installPlugin();

        Call[] memory calls = new Call[](0);

        vm.prank(address(plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.executeBatch.selector));
        account1.executeBatch(calls);
    }

    function test_Pass_DirectCallFromPlugin_MockFlow() external {
        _installPlugin();

        vm.prank(address(plugin));
        account1.execute(address(0), 0, "");
    }

    function test_Pass_DirectCallFromPlugin_NormalFlow() external {
        _installPlugin();

        bytes memory encodedCall = abi.encodeCall(DirectCallPlugin.directCall, ());

        vm.prank(address(entryPoint));
        bytes memory result = account1.execute(address(plugin), 0, encodedCall);

        assertEq(abi.decode(result, (bytes)), abi.encode(plugin.getData()));
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _installPlugin() internal {
        bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        vm.prank(address(entryPoint));
        account1.installPlugin(address(plugin), manifestHash, "");
    }

    function _buildDirectCallDisallowedError(bytes4 selector) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            UpgradeableModularAccount.ExecFromPluginNotPermitted.selector, address(plugin), selector
        );
    }
}
