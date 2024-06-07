// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.22;

// import {BasePlugin} from "../../src/plugins/BasePlugin.sol";
// import {PluginManifest, PluginMetadata} from "../../src/interfaces/IPlugin.sol";

// /// @title Simple User Op Gas Plugin
// /// @author ERC6900 Authors
// /// @notice This plugin ensures that UOs can only use a certain amount of gas. This pre execution hook attaches
// /// itself to account native functions only
// /// @dev The limits enforced by this plugin is an absolute amount.
// contract UserOpGasPlugin is BasePlugin {
//     string internal constant _NAME = "Simple User Op Gas Plugin";
//     string internal constant _VERSION = "1.0.0";
//     string internal constant _AUTHOR = "ERC6900 Authors";

//     mapping(address => uint256) gasLimits;

//     // Constants used in the manifest for owner plugin
//     uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION = 0;
//     uint256 internal constant _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION = 1;

//     function updateLimits(uint256 amountToAdd) external {
//         gasLimits[msg.sender] += amountToAdd;
//     }

//     // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
//     // ┃    Plugin interface functions    ┃
//     // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

//     /// @inheritdoc BasePlugin
//     function onUninstall(bytes calldata) external override {
//         delete gasLimits[msg.sender];
//     }

//     /// @inheritdoc BasePlugin
//     function preExecutionHook(uint8 functionId, address sender, uint256 value, bytes calldata data)
//         external
//         override
//         returns (uint256)
//     {}

//     /// @inheritdoc BasePlugin
//     function pluginManifest() external pure override returns (PluginManifest memory) {
//         PluginManifest memory manifest;

//         manifest.dependencyInterfaceIds = new bytes4[](2);
//         manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION] =
//             type(IPlugin).interfaceId;
//         manifest.dependencyInterfaceIds[_MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION] =
//             type(IPlugin).interfaceId;

//         manifest.executionFunctions = new bytes4[](1);
//         manifest.executionFunctions[0] = this.updateLimits.selector;

//         ManifestFunction memory sessionKeyUserOpValidationFunction = ManifestFunction({
//             functionType: ManifestAssociatedFunctionType.SELF,
//             functionId: uint8(FunctionId.USER_OP_VALIDATION_SESSION_KEY),
//             dependencyIndex: 0 // Unused.
//         });
//         ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
//             functionType: ManifestAssociatedFunctionType.DEPENDENCY,
//             functionId: 0, // unused since it's a dependency
//             dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_USER_OP_VALIDATION
//         });

//         manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](5);
//         manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
//             executionSelector: this.executeWithSessionKey.selector,
//             associatedFunction: sessionKeyUserOpValidationFunction
//         });
//         manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
//             executionSelector: this.addSessionKey.selector,
//             associatedFunction: ownerUserOpValidationFunction
//         });
//         manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
//             executionSelector: this.removeSessionKey.selector,
//             associatedFunction: ownerUserOpValidationFunction
//         });
//         manifest.userOpValidationFunctions[3] = ManifestAssociatedFunction({
//             executionSelector: this.rotateSessionKey.selector,
//             associatedFunction: ownerUserOpValidationFunction
//         });
//         manifest.userOpValidationFunctions[4] = ManifestAssociatedFunction({
//             executionSelector: this.updateKeyPermissions.selector,
//             associatedFunction: ownerUserOpValidationFunction
//         });

//         // Session keys are only expected to be used for user op validation, so no runtime validation functions
// are
//         // set over executeWithSessionKey, and pre runtime hook will always deny.
//         ManifestFunction memory ownerRuntimeValidationFunction = ManifestFunction({
//             functionType: ManifestAssociatedFunctionType.DEPENDENCY,
//             functionId: 0, // unused since it's a dependency
//             dependencyIndex: _MANIFEST_DEPENDENCY_INDEX_OWNER_RUNTIME_VALIDATION
//         });

//         manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](4);
//         manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
//             executionSelector: this.addSessionKey.selector,
//             associatedFunction: ownerRuntimeValidationFunction
//         });
//         manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
//             executionSelector: this.removeSessionKey.selector,
//             associatedFunction: ownerRuntimeValidationFunction
//         });
//         manifest.runtimeValidationFunctions[2] = ManifestAssociatedFunction({
//             executionSelector: this.rotateSessionKey.selector,
//             associatedFunction: ownerRuntimeValidationFunction
//         });
//         manifest.runtimeValidationFunctions[3] = ManifestAssociatedFunction({
//             executionSelector: this.updateKeyPermissions.selector,
//             associatedFunction: ownerRuntimeValidationFunction
//         });

//         manifest.preRuntimeValidationHooks = new ManifestAssociatedFunction[](1);
//         manifest.preRuntimeValidationHooks[0] = ManifestAssociatedFunction({
//             executionSelector: this.executeWithSessionKey.selector,
//             associatedFunction: ManifestFunction({
//                 functionType: ManifestAssociatedFunctionType.PRE_HOOK_ALWAYS_DENY,
//                 functionId: 0,
//                 dependencyIndex: 0
//             })
//         });

//         manifest.permitAnyExternalAddress = true;
//         manifest.canSpendNativeToken = true;

//         return manifest;
//     }

//     /// @inheritdoc BasePlugin
//     function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
//         PluginMetadata memory metadata;
//         metadata.name = _NAME;
//         metadata.version = _VERSION;
//         metadata.author = _AUTHOR;

//         // Permission strings
//         string memory modifySessionKeys = "Modify Session Keys";
//         string memory modifySessionKeyPermissions = "Modify Session Key Permissions";

//         // Permission descriptions
//         metadata.permissionDescriptors = new SelectorPermission[](4);
//         metadata.permissionDescriptors[0] = SelectorPermission({
//             functionSelector: this.addSessionKey.selector,
//             permissionDescription: modifySessionKeys
//         });
//         metadata.permissionDescriptors[1] = SelectorPermission({
//             functionSelector: this.removeSessionKey.selector,
//             permissionDescription: modifySessionKeys
//         });
//         metadata.permissionDescriptors[2] = SelectorPermission({
//             functionSelector: this.rotateSessionKey.selector,
//             permissionDescription: modifySessionKeys
//         });
//         metadata.permissionDescriptors[3] = SelectorPermission({
//             functionSelector: this.updateKeyPermissions.selector,
//             permissionDescription: modifySessionKeyPermissions
//         });

//         return metadata;
//     }

//     /// @inheritdoc BasePlugin
//     function _onInstall(bytes calldata data) internal override isNotInitialized(msg.sender) {
//         (uint256 _gasLimit) = abi.decode(data, (uint256));

//         require(_gasLimit > 0);

//         gasLimits[msg.sender] = _gasLimit;
//     }

//     /// @inheritdoc BasePlugin
//     function _isInitialized(address account) internal view override returns (bool) {
//         return gasLimits[account] > 0;
//     }
// }
