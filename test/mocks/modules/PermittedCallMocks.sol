// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ExecutionManifest, IExecution, ManifestExecutionFunction} from "../../../src/interfaces/IExecution.sol";
import {ModuleMetadata} from "../../../src/interfaces/IModule.sol";

import {BaseModule} from "../../../src/modules/BaseModule.sol";
import {ResultCreatorModule} from "./ReturnDataModuleMocks.sol";

contract PermittedCallerModule is IExecution, BaseModule {
    function onInstall(bytes calldata) external override {}

    function onUninstall(bytes calldata) external override {}

    function executionManifest() external pure override returns (ExecutionManifest memory) {
        ExecutionManifest memory manifest;

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0].executionSelector = this.usePermittedCallAllowed.selector;
        manifest.executionFunctions[1].executionSelector = this.usePermittedCallNotAllowed.selector;

        for (uint256 i = 0; i < manifest.executionFunctions.length; i++) {
            manifest.executionFunctions[i].isPublic = true;
        }

        return manifest;
    }

    function moduleMetadata() external pure override returns (ModuleMetadata memory) {}

    // The manifest requested access to use the module-defined method "foo"
    function usePermittedCallAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorModule(msg.sender).foo());
    }

    // The manifest has not requested access to use the module-defined method "bar", so this should revert.
    function usePermittedCallNotAllowed() external view returns (bytes memory) {
        return abi.encode(ResultCreatorModule(msg.sender).bar());
    }
}
