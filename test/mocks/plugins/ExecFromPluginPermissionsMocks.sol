// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    ManifestExternalCallPermission,
    ManifestExecutionHook,
    PluginManifest,
    ManifestExecutionFunction
} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {IPluginExecutor} from "../../../src/interfaces/IPluginExecutor.sol";
import {IPlugin} from "../../../src/interfaces/IPlugin.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {FunctionReference} from "../../../src/libraries/FunctionReferenceLib.sol";

import {ResultCreatorPlugin} from "./ReturnDataPluginMocks.sol";
import {Counter} from "../Counter.sol";

// Hardcode the counter addresses from ExecuteFromPluginPermissionsTest to be able to have a pure plugin manifest
// easily
address constant counter1 = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
address constant counter2 = 0x2e234DAe75C793f67A35089C9d99245E1C58470b;
address constant counter3 = 0xF62849F9A0B5Bf2913b396098F7c7019b51A820a;

contract EFPCallerPlugin is BasePlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](11);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.useEFPPermissionAllowed.selector, new string[](0));
        manifest.executionFunctions[1] =
            ManifestExecutionFunction(this.useEFPPermissionNotAllowed.selector, new string[](0));
        manifest.executionFunctions[2] =
            ManifestExecutionFunction(this.setNumberCounter1.selector, new string[](0));
        manifest.executionFunctions[3] =
            ManifestExecutionFunction(this.getNumberCounter1.selector, new string[](0));
        manifest.executionFunctions[4] =
            ManifestExecutionFunction(this.incrementCounter1.selector, new string[](0));
        manifest.executionFunctions[5] =
            ManifestExecutionFunction(this.setNumberCounter2.selector, new string[](0));
        manifest.executionFunctions[6] =
            ManifestExecutionFunction(this.getNumberCounter2.selector, new string[](0));
        manifest.executionFunctions[7] =
            ManifestExecutionFunction(this.incrementCounter2.selector, new string[](0));
        manifest.executionFunctions[8] =
            ManifestExecutionFunction(this.setNumberCounter3.selector, new string[](0));
        manifest.executionFunctions[9] =
            ManifestExecutionFunction(this.getNumberCounter3.selector, new string[](0));
        manifest.executionFunctions[10] =
            ManifestExecutionFunction(this.incrementCounter3.selector, new string[](0));

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](11);

        ManifestFunction memory alwaysAllowValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
            functionId: 0,
            dependencyIndex: 0
        });

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.runtimeValidationFunctions[i] = ManifestAssociatedFunction({
                executionSelector: manifest.executionFunctions[i].selector,
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

contract EFPCallerPluginAnyExternal is BasePlugin {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.passthroughExecute.selector, new string[](0));

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.passthroughExecute.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permitAnyExternalContract = true;

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

// Create pre and post permitted call hooks for calling ResultCreatorPlugin.foo via `executeFromPlugin`
contract EFPPermittedCallHookPlugin is BasePlugin {
    bool public preExecHookCalled;
    bool public postExecHookCalled;

    function preExecutionHook(uint8, address, uint256, bytes calldata) external override returns (bytes memory) {
        preExecHookCalled = true;
        return "context for post exec hook";
    }

    function postExecutionHook(uint8, bytes calldata preExecHookData) external override {
        require(
            keccak256(preExecHookData) == keccak256("context for post exec hook"), "Invalid pre exec hook data"
        );
        postExecHookCalled = true;
    }

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction(this.performEFPCall.selector, new string[](0));

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.performEFPCall.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permittedCallHooks = new ManifestExecutionHook[](1);
        manifest.permittedCallHooks[0] = ManifestExecutionHook({
            executionSelector: ResultCreatorPlugin.foo.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permittedExecutionSelectors = new bytes4[](1);
        manifest.permittedExecutionSelectors[0] = ResultCreatorPlugin.foo.selector;

        return manifest;
    }

    function performEFPCall() external returns (bytes memory) {
        return IPluginExecutor(msg.sender).executeFromPlugin(abi.encodeCall(ResultCreatorPlugin.foo, ()));
    }
}

// Creates pre and post permitted call hooks for `executeFromPluginExternal`
contract EFPExternalPermittedCallHookPlugin is BasePlugin {
    bool public preExecHookCalled;
    bool public postExecHookCalled;

    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function preExecutionHook(uint8, address, uint256, bytes calldata) external override returns (bytes memory) {
        preExecHookCalled = true;
        return "context for post exec hook";
    }

    function postExecutionHook(uint8, bytes calldata preExecHookData) external override {
        require(
            keccak256(preExecHookData) == keccak256("context for post exec hook"), "Invalid pre exec hook data"
        );
        postExecHookCalled = true;
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction(this.performIncrement.selector, new string[](0));

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.performIncrement.selector,
            associatedFunction: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.RUNTIME_VALIDATION_ALWAYS_ALLOW,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permittedCallHooks = new ManifestExecutionHook[](1);
        manifest.permittedCallHooks[0] = ManifestExecutionHook({
            executionSelector: IPluginExecutor.executeFromPluginExternal.selector,
            preExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            }),
            postExecHook: ManifestFunction({
                functionType: ManifestAssociatedFunctionType.SELF,
                functionId: 0,
                dependencyIndex: 0
            })
        });

        manifest.permitAnyExternalContract = true;

        return manifest;
    }

    function performIncrement() external {
        IPluginExecutor(msg.sender).executeFromPluginExternal(
            counter1, 0, abi.encodeWithSelector(Counter.increment.selector)
        );
    }
}
