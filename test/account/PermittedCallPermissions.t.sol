// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";

import {PermittedCallerModule} from "../mocks/modules/PermittedCallMocks.sol";
import {ResultCreatorModule} from "../mocks/modules/ReturnDataModuleMocks.sol";
import {AccountTestBase} from "../utils/AccountTestBase.sol";

contract PermittedCallPermissionsTest is AccountTestBase {
    ResultCreatorModule public resultCreatorModule;

    PermittedCallerModule public permittedCallerModule;

    function setUp() public {
        _transferOwnershipToTest();
        resultCreatorModule = new ResultCreatorModule();

        // Initialize the permitted caller modules, which will attempt to use the permissions system to authorize
        // calls.
        permittedCallerModule = new PermittedCallerModule();

        // Add the result creator module to the account
        bytes32 resultCreatorManifestHash = keccak256(abi.encode(resultCreatorModule.moduleManifest()));
        vm.prank(address(entryPoint));
        account1.installModule({
            module: address(resultCreatorModule),
            manifestHash: resultCreatorManifestHash,
            moduleInstallData: ""
        });
        // Add the permitted caller module to the account
        bytes32 permittedCallerManifestHash = keccak256(abi.encode(permittedCallerModule.moduleManifest()));
        vm.prank(address(entryPoint));
        account1.installModule({
            module: address(permittedCallerModule),
            manifestHash: permittedCallerManifestHash,
            moduleInstallData: ""
        });
    }

    function test_permittedCall_Allowed() public {
        bytes memory result = PermittedCallerModule(address(account1)).usePermittedCallAllowed();
        bytes32 actual = abi.decode(result, (bytes32));

        assertEq(actual, keccak256("bar"));
    }

    function test_permittedCall_NotAllowed() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                UpgradeableModularAccount.ValidationFunctionMissing.selector, ResultCreatorModule.bar.selector
            )
        );
        PermittedCallerModule(address(account1)).usePermittedCallNotAllowed();
    }
}
