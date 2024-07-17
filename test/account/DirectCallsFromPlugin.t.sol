pragma solidity ^0.8.19;

import {DirectCallPlugin} from "../mocks/plugins/DirectCallPlugin.sol";
import {ExecutionHook} from "../../src/interfaces/IAccountLoupe.sol";
import {IStandardExecutor, Call} from "../../src/interfaces/IStandardExecutor.sol";
import {FunctionReferenceLib, FunctionReference} from "../../src/helpers/FunctionReferenceLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DirectCallsFromPluginTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    DirectCallPlugin internal _plugin;
    FunctionReference internal _pluginFunctionReference;

    function setUp() public {
        _plugin = new DirectCallPlugin();
        assertFalse(_plugin.preHookRan());
        assertFalse(_plugin.postHookRan());
        _pluginFunctionReference = FunctionReferenceLib.pack(address(_plugin), type(uint8).max);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Fail_DirectCallPluginNotInstalled() external {
        vm.prank(address(_plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallPluginUninstalled() external {
        _installPlugin();

        _uninstallPlugin();

        vm.prank(address(_plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallPluginCallOtherSelector() external {
        _installPlugin();

        Call[] memory calls = new Call[](0);

        vm.prank(address(_plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.executeBatch.selector));
        account1.executeBatch(calls);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Pass_DirectCallFromPluginPrank() external {
        _installPlugin();

        vm.prank(address(_plugin));
        account1.execute(address(0), 0, "");

        assertTrue(_plugin.preHookRan());
        assertTrue(_plugin.postHookRan());
    }

    function test_Pass_DirectCallFromPluginCallback() external {
        _installPlugin();

        bytes memory encodedCall = abi.encodeCall(DirectCallPlugin.directCall, ());

        vm.prank(address(entryPoint));
        bytes memory result = account1.execute(address(_plugin), 0, encodedCall);

        assertTrue(_plugin.preHookRan());
        assertTrue(_plugin.postHookRan());

        // the directCall() function in the _plugin calls back into `execute()` with an encoded call back into the
        // _plugin's getData() function.
        assertEq(abi.decode(result, (bytes)), abi.encode(_plugin.getData()));
    }

    function test_Flow_DirectCallFromPluginSequence() external {
        // Install => Succeesfully call => uninstall => fail to call

        _installPlugin();

        vm.prank(address(_plugin));
        account1.execute(address(0), 0, "");

        assertTrue(_plugin.preHookRan());
        assertTrue(_plugin.postHookRan());

        _uninstallPlugin();

        vm.prank(address(_plugin));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _installPlugin() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IStandardExecutor.execute.selector;

        ExecutionHook[] memory permissionHooks = new ExecutionHook[](1);
        bytes[] memory permissionHookInitDatas = new bytes[](1);

        permissionHooks[0] = ExecutionHook({
            hookFunction: FunctionReferenceLib.pack(address(_plugin), 0xff),
            isPreHook: true,
            isPostHook: true
        });

        bytes memory encodedPermissionHooks = abi.encode(permissionHooks, permissionHookInitDatas);

        vm.prank(address(entryPoint));

        ValidationConfig validationConfig = ValidationConfigLib.pack(_pluginFunctionReference, false, false);

        account1.installValidation(validationConfig, selectors, "", "", encodedPermissionHooks);
    }

    function _uninstallPlugin() internal {
        vm.prank(address(entryPoint));
        account1.uninstallValidation(
            _pluginFunctionReference, "", abi.encode(new bytes[](0)), abi.encode(new bytes[](1))
        );
    }

    function _buildDirectCallDisallowedError(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(UpgradeableModularAccount.ValidationFunctionMissing.selector, selector);
    }
}
