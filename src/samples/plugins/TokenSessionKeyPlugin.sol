// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission,
    ManifestExternalCallPermission
} from "../../interfaces/IPlugin.sol";
import {BasePlugin} from "../../plugins/BasePlugin.sol";
import {ModularSessionKeyPlugin} from "./ModularSessionKeyPlugin.sol";
import {ITokenSessionKeyPlugin} from "./interfaces/ITokenSessionKeyPlugin.sol";
import {IModularSessionKeyPlugin} from "./interfaces/ISessionKeyPlugin.sol";
import {IPluginExecutor} from "../../interfaces/IPluginExecutor.sol";

/// @title Token Session Key Plugin
/// @author Decipher ERC-6900 Team
/// @notice This plugin acts as a 'child plugin' for ModularSessionKeyPlugin.
/// It implements the logic for session keys that are allowed to call ERC20
/// transferFrom function. It allows for session key owners to access MSCA
/// with `transferFromSessionKey` function, which calls `executeFromPluginExternal`
/// function in PluginExecutor contract.
/// The target ERC20 contract and the selector for transferFrom function are hardcoded
/// in this plugin, since the pluginManifest function requires the information of
/// permitted external calls not to be changed in the future. For other child session
/// key plugins, there can be a set of permitted external calls according to the
/// specific needs.
contract TokenSessionKeyPlugin is BasePlugin, ITokenSessionKeyPlugin {
    string public constant NAME = "Token Session Key Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Decipher ERC-6900 Team";

    // Mock address of target ERC20 contract
    address public constant TARGET_ERC20_CONTRACT = 0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD;
    bytes4 public constant TRANSFERFROM_SELECTOR =
        bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ITokenSessionKeyPlugin
    function transferFromSessionKey(address target, address from, address to, uint256 amount)
        external
        returns (bytes memory returnData)
    {
        bytes memory data = abi.encodeWithSelector(TRANSFERFROM_SELECTOR, from, to, amount);
        returnData = IPluginExecutor(msg.sender).executeFromPluginExternal(target, 0, data);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata data) external override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](1);
        manifest.executionFunctions[0] = this.transferFromSessionKey.selector;

        ManifestFunction memory tempOwnerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused
            dependencyIndex: 0 // Used as first index
        });
        ManifestFunction memory tempOwnerRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: 0, // Unused
            dependencyIndex: 1 // Used as second index
        });

        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.transferFromSessionKey.selector,
            associatedFunction: tempOwnerUserOpValidationFunction
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](1);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.transferFromSessionKey.selector,
            associatedFunction: tempOwnerRuntimeValidationFunction
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(IModularSessionKeyPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(IModularSessionKeyPlugin).interfaceId;

        bytes4[] memory permittedExternalSelectors = new bytes4[](1);
        permittedExternalSelectors[0] = TRANSFERFROM_SELECTOR;

        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](1);
        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: TARGET_ERC20_CONTRACT,
            permitAnySelector: false,
            selectors: permittedExternalSelectors
        });

        return manifest;
    }

    /// @inheritdoc BasePlugin
    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ITokenSessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }
}
