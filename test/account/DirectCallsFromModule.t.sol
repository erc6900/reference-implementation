pragma solidity ^0.8.19;

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {ExecutionHook} from "../../src/interfaces/IAccountLoupe.sol";
import {Call, IStandardExecutor} from "../../src/interfaces/IStandardExecutor.sol";
import {DirectCallModule} from "../mocks/modules/DirectCallModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract DirectCallsFromModuleTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    DirectCallModule internal _module;
    ModuleEntity internal _moduleEntity;

    function setUp() public {
        _module = new DirectCallModule();
        assertFalse(_module.preHookRan());
        assertFalse(_module.postHookRan());
        _moduleEntity = ModuleEntityLib.pack(address(_module), type(uint32).max);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Fail_DirectCallModuleNotInstalled() external {
        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallModuleUninstalled() external {
        _installModule();

        _uninstallModule();

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallModuleCallOtherSelector() external {
        _installModule();

        Call[] memory calls = new Call[](0);

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.executeBatch.selector));
        account1.executeBatch(calls);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Pass_DirectCallFromModulePrank() external {
        _installModule();

        vm.prank(address(_module));
        account1.execute(address(0), 0, "");

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());
    }

    function test_Pass_DirectCallFromModuleCallback() external {
        _installModule();

        bytes memory encodedCall = abi.encodeCall(DirectCallModule.directCall, ());

        vm.prank(address(entryPoint));
        bytes memory result = account1.execute(address(_module), 0, encodedCall);

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());

        // the directCall() function in the _module calls back into `execute()` with an encoded call back into the
        // _module's getData() function.
        assertEq(abi.decode(result, (bytes)), abi.encode(_module.getData()));
    }

    function test_Flow_DirectCallFromModuleSequence() external {
        // Install => Succeesfully call => uninstall => fail to call

        _installModule();

        vm.prank(address(_module));
        account1.execute(address(0), 0, "");

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());

        _uninstallModule();

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IStandardExecutor.execute.selector));
        account1.execute(address(0), 0, "");
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _installModule() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IStandardExecutor.execute.selector;

        ExecutionHook[] memory permissionHooks = new ExecutionHook[](1);
        bytes[] memory permissionHookInitDatas = new bytes[](1);

        permissionHooks[0] = ExecutionHook({hookFunction: _moduleEntity, isPreHook: true, isPostHook: true});

        bytes memory encodedPermissionHooks = abi.encode(permissionHooks, permissionHookInitDatas);

        vm.prank(address(entryPoint));

        ValidationConfig validationConfig = ValidationConfigLib.pack(_moduleEntity, false, false);

        account1.installValidation(validationConfig, selectors, "", "", encodedPermissionHooks);
    }

    function _uninstallModule() internal {
        vm.prank(address(entryPoint));
        account1.uninstallValidation(_moduleEntity, "", abi.encode(new bytes[](0)), abi.encode(new bytes[](1)));
    }

    function _buildDirectCallDisallowedError(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(UpgradeableModularAccount.ValidationFunctionMissing.selector, selector);
    }
}
