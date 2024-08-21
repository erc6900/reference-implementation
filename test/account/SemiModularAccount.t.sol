// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {AccountTestBase} from "../utils/AccountTestBase.sol";
import {TEST_DEFAULT_VALIDATION_ENTITY_ID} from "../utils/TestConstants.sol";
import {SemiModularAccount} from "src/account/SemiModularAccount.sol";
import {ValidationConfig} from "src/helpers/ValidationConfigLib.sol";

import {console} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";

contract SemiModularAccountTest is AccountTestBase {
    SemiModularAccount internal _sma;

    address internal _other;

    function setUp() public {
        // This is separate from the equivalence testing framework (with the env boolean variable "SMA_TEST") with
        // the goal of testing specific SMA functionality, rather than equivalence. This is also why we deploy a
        // new account.
        SemiModularAccount impl = new SemiModularAccount(entryPoint);

        _other = address(0x4546b);

        bytes32 salt = bytes32(0);
        bytes memory immutables = abi.encodePacked(address(owner1));
        (bool alreadyDeployed, address instance) =
            LibClone.createDeterministicERC1967(address(impl), immutables, salt);

        assertFalse(alreadyDeployed);

        _sma = SemiModularAccount(payable(instance));
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Negatives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Fail_InitializeDisabled() external {
        ValidationConfig config;
        bytes4[] memory selectors;
        bytes memory installData;
        bytes[] memory hooks;

        vm.expectRevert(SemiModularAccount.InitializerDisabled.selector);
        _sma.initializeWithValidation(config, selectors, installData, hooks);
    }

    function test_Fail_AccessControl_Functions() external {
        vm.expectRevert(_buildDirectCallDisallowedError(SemiModularAccount.setFallbackSignerDisabled.selector));
        _sma.setFallbackSignerDisabled(true);

        vm.expectRevert(_buildDirectCallDisallowedError(SemiModularAccount.updateFallbackSigner.selector));
        _sma.updateFallbackSigner(address(0));
    }

    function test_Fail_ExecuteWithAuthorization_DisabledFallbackSigner() external {
        vm.prank(address(entryPoint));
        _sma.setFallbackSignerDisabled(true);

        vm.expectRevert(SemiModularAccount.FallbackSignerDisabled.selector);
        vm.prank(owner1);
        _executeWithFallbackSigner();
    }

    function test_Fail_ExecuteWithAuthorization_BytecodeOverriden() external {
        vm.prank(address(entryPoint));
        _sma.updateFallbackSigner(_other);

        vm.expectRevert(SemiModularAccount.FallbackSignerMismatch.selector);
        vm.prank(owner1);
        _executeWithFallbackSigner();
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Positives                                 */
    /* -------------------------------------------------------------------------- */

    function test_Pass_GetFallbackSigner_Bytecode() external {
        assertEq(_sma.getFallbackSigner(), owner1);
    }

    function test_Pass_GetFallbackSigner_Storage() external {
        vm.prank(address(entryPoint));
        _sma.updateFallbackSigner(_other);

        assertEq(_sma.getFallbackSigner(), _other);
    }

    function test_Pass_ExecuteWithAuthorization_FallbackSigner() external {
        vm.prank(owner1);
        _executeWithFallbackSigner();
    }

    /* -------------------------------------------------------------------------- */
    /*                                  Internals                                 */
    /* -------------------------------------------------------------------------- */

    function _executeWithFallbackSigner() internal {
        // _signerValidation is already the ModuleEntity for fallback validation
        _sma.executeWithAuthorization(
            abi.encodeCall(account1.execute, (address(owner1), 0, "")),
            _encodeSignature(_signerValidation, GLOBAL_VALIDATION, "")
        );
    }
}
