// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExternalCallPermission,
    PluginManifest
} from "../../../src/interfaces/IPlugin.sol";
import {IPluginExecutor} from "../../../src/interfaces/IPluginExecutor.sol";

import {BaseTestPlugin} from "./BaseTestPlugin.sol";
import {ResultCreatorPlugin} from "./ReturnDataPluginMocks.sol";
import {Counter} from "../Counter.sol";

contract EFPCallerPlugin is BaseTestPlugin {
    // Store the counters as immutables, and use the view -> pure cast to get the manifest
    // solhint-disable private-vars-leading-underscore, immutable-vars-naming
    address immutable private counter1;
    address immutable private counter2;
    address immutable private counter3;
    // solhint-enable private-vars-leading-underscore, immutable-vars-naming

    constructor(address _counter1, address _counter2, address _counter3) {
        counter1 = _counter1;
        counter2 = _counter2;
        counter3 = _counter3;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function _getManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](11);
        manifest.executionFunctions[0] = this.useEFPPermissionAllowed.selector;
        manifest.executionFunctions[1] = this.useEFPPermissionNotAllowed.selector;
        manifest.executionFunctions[2] = this.setNumberCounter1.selector;
        manifest.executionFunctions[3] = this.getNumberCounter1.selector;
        manifest.executionFunctions[4] = this.incrementCounter1.selector;
        manifest.executionFunctions[5] = this.setNumberCounter2.selector;
        manifest.executionFunctions[6] = this.getNumberCounter2.selector;
        manifest.executionFunctions[7] = this.incrementCounter2.selector;
        manifest.executionFunctions[8] = this.setNumberCounter3.selector;
        manifest.executionFunctions[9] = this.getNumberCounter3.selector;
        manifest.executionFunctions[10] = this.incrementCounter3.selector;

        manifest.validationFunctions = new ManifestAssociatedFunction[](11);

        ManifestFunction memory alwaysAllowValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0,
            dependencyIndex: 0
        });

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.validationFunctions[i] = ManifestAssociatedFunction({
                executionSelector: manifest.executionFunctions[i],
                associatedFunction: alwaysAllowValidationFunction
            });
        }

        // Request permission only for "foo", but not "bar", from ResultCreatorPlugin
        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        // Request permission for:
        // - `setNumber` and `number` on counter 1
        // - All selectors on counter 2
        // - None on counter 3
        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](2);

        bytes4[] memory selectorsCounter1 = new bytes4[](2);
        selectorsCounter1[0] = Counter.setNumber.selector;
        selectorsCounter1[1] = bytes4(keccak256("number()")); // Public vars don't automatically get exported
            // selectors

        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: counter1,
            permitAnySelector: false,
            selectors: selectorsCounter1
        });

        manifest.permittedExternalCalls[1] = ManifestExternalCallPermission({
            externalAddress: counter2,
            permitAnySelector: true,
            selectors: new bytes4[](0)
        });

        return manifest;
    }

    function _castToPure(function() internal view returns (PluginManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (PluginManifest memory) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        return _castToPure(_getManifest)();
    }

    // The manifest requested access to use the plugin-defined method "foo"
    function useEFPPermissionAllowed() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));
    }

    // The manifest has not requested access to use the plugin-defined method "bar", so this should revert.
    function useEFPPermissionNotAllowed() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.bar, ()));
    }

    // Should be allowed
    function setNumberCounter1(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should be allowed
    function getNumberCounter1() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should not be allowed
    function incrementCounter1() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }

    // Should be allowed
    function setNumberCounter2(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should be allowed
    function getNumberCounter2() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should be allowed
    function incrementCounter2() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter2, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }

    // Should not be allowed
    function setNumberCounter3(uint256 number) external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodeWithSelector(Counter.setNumber.selector, number)
        );
    }

    // Should not be allowed
    function getNumberCounter3() external returns (uint256) {
        bytes memory returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodePacked(bytes4(keccak256("number()")))
        );

        return abi.decode(returnData, (uint256));
    }

    // Should not be allowed
    function incrementCounter3() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter3, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }
}

contract EFPCallerPluginAnyExternal is BaseTestPlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.passthroughExecute.selector;

        manifest.validationFunctions = new ManifestAssociatedFunction[](1);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.passthroughExecute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permitAnyExternalAddress = true;

        return manifest;
    }

    function passthroughExecute(address target, uint256 value, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        return IPluginExecutor(msg.sender).executeFromPluginExternal(target, value, data);
    }
}
