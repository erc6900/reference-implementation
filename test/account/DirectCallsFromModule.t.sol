// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ReferenceModularAccount} from "../../src/account/ReferenceModularAccount.sol";

import {HookConfigLib} from "../../src/helpers/HookConfigLib.sol";
import {ModuleEntity, ModuleEntityLib} from "../../src/helpers/ModuleEntityLib.sol";
import {ValidationConfig, ValidationConfigLib} from "../../src/helpers/ValidationConfigLib.sol";
import {Call, IModularAccount} from "../../src/interfaces/IModularAccount.sol";
import {DirectCallModule} from "../mocks/modules/DirectCallModule.sol";

import {AccountTestBase} from "../utils/AccountTestBase.sol";

import {DIRECT_CALL_VALIDATION_ENTITYID} from "../../src/helpers/Constants.sol";

contract DirectCallsFromModuleTest is AccountTestBase {
    using ValidationConfigLib for ValidationConfig;

    DirectCallModule internal _module;
    ModuleEntity internal _moduleEntity;

    event ValidationUninstalled(address indexed module, uint32 indexed entityId, bool onUninstallSucceeded);

    function setUp() public {
        _module = new DirectCallModule();
        assertFalse(_module.preHookRan());
        assertFalse(_module.postHookRan());
        _moduleEntity = ModuleEntityLib.pack(address(_module), DIRECT_CALL_VALIDATION_ENTITYID);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Fail_DirectCallModuleNotInstalled() external {
        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IModularAccount.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallModuleUninstalled() external {
        _installValidation();

        _uninstallValidation();

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IModularAccount.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_Fail_DirectCallModuleCallOtherSelector() external {
        _installValidation();

        Call[] memory calls = new Call[](0);

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IModularAccount.executeBatch.selector));
        account1.executeBatch(calls);
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Pass_DirectCallFromModulePrank() external {
        _installValidation();

        vm.prank(address(_module));
        account1.execute(address(0), 0, "");

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());
    }

    function test_Pass_DirectCallFromModuleCallback() external {
        _installValidation();

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

        _installValidation();

        vm.prank(address(_module));
        account1.execute(address(0), 0, "");

        assertTrue(_module.preHookRan());
        assertTrue(_module.postHookRan());

        _uninstallValidation();

        vm.prank(address(_module));
        vm.expectRevert(_buildDirectCallDisallowedError(IModularAccount.execute.selector));
        account1.execute(address(0), 0, "");
    }

    function test_directCallsFromEOA() external {
        address extraOwner = makeAddr("extraOwner");

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IModularAccount.execute.selector;

        vm.prank(address(entryPoint));

        account1.installValidation(
            ValidationConfigLib.pack(extraOwner, DIRECT_CALL_VALIDATION_ENTITYID, false, false),
            selectors,
            "",
            new bytes[](0)
        );

        vm.prank(extraOwner);
        account1.execute(makeAddr("dead"), 0, "");
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _installValidation() internal {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = IModularAccount.execute.selector;

        bytes[] memory hooks = new bytes[](1);
        hooks[0] = abi.encodePacked(
            HookConfigLib.packExecHook({_hookFunction: _moduleEntity, _hasPre: true, _hasPost: true}),
            hex"00" // onInstall data
        );

        vm.prank(address(entryPoint));

        ValidationConfig validationConfig = ValidationConfigLib.pack(_moduleEntity, false, false);

        account1.installValidation(validationConfig, selectors, "", hooks);
    }

    function _uninstallValidation() internal {
        (address module, uint32 entityId) = ModuleEntityLib.unpack(_moduleEntity);
        vm.prank(address(entryPoint));
        vm.expectEmit(true, true, true, true);
        emit ValidationUninstalled(module, entityId, true);
        account1.uninstallValidation(_moduleEntity, "", new bytes[](1));
    }

    function _buildDirectCallDisallowedError(bytes4 selector) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ReferenceModularAccount.ValidationFunctionMissing.selector, selector);
    }
}
