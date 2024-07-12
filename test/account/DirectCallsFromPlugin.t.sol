pragma solidity ^0.8.19;

import {DirectCallPlugin} from "../mocks/plugins/DirectCallPlugin.sol";
import {IPlugin, PluginManifest} from "../../src/interfaces/IPlugin.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib, FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DirectCallsFromPluginTest is AccountTestBase {
    DirectCallPlugin plugin;
    FunctionReference pluginFunctionReference;

    function setUp() public {
        plugin = new DirectCallPlugin();
        pluginFunctionReference = FunctionReferenceLib.pack(address(plugin), type(uint8).max);
    }

    function test_Fail_DirectCallPluginNotInstalled() external {
        vm.prank(address(plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallPluginUninstalled() external {
        _installPlugin();

        _uninstallPlugin();

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

    function test_Pass_DirectCallFromPluginPrank() external {
        _installPlugin();

        vm.prank(address(plugin));
        account1.execute(address(0), 0, "");
    }

    function test_Pass_DirectCallFromPluginCallback() external {
        _installPlugin();

        bytes memory encodedCall = abi.encodeCall(DirectCallPlugin.directCall, ());

        vm.prank(address(entryPoint));
        bytes memory result = account1.execute(address(plugin), 0, encodedCall);

        // the directCall() function in the plugin calls back into `execute()` with an encoded call back into the
        // plugin's getData() function.
        assertEq(abi.decode(result, (bytes)), abi.encode(plugin.getData()));
    }

    function test_Flow_DirectCallFromPluginSequence() external {
        // Install => Succeesfully call => uninstall => fail to call

        _installPlugin();

        vm.prank(address(plugin));
        account1.execute(address(0), 0, "");

        _uninstallPlugin();

        vm.prank(address(plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _installPlugin() internal {
        // bytes32 manifestHash = keccak256(abi.encode(plugin.pluginManifest()));

        // vm.prank(address(entryPoint));
        // account1.installPlugin(address(plugin), manifestHash, "");

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IStandardExecutor.execute.selector;

        vm.prank(address(entryPoint));
        account1.installValidation(pluginFunctionReference, false, selectors, "", "", "");
    }

    function _uninstallPlugin() internal {
        vm.prank(address(entryPoint));
        account1.uninstallValidation(
            pluginFunctionReference, "", abi.encode(new bytes[](0)), abi.encode(new bytes[](0))
        );
    }

    function _buildDirectCallDisallowedError(bytes4 selector) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            UpgradeableModularAccount.ExecFromPluginNotPermitted.selector, address(plugin), selector
        );
    }
}
