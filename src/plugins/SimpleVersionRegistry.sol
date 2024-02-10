// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {IVersionRegistry} from "../interfaces/IVersionRegistry.sol";
import {Version, decodeVersion} from "../helpers/VersionDecoder.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";

/// @title VersionRegistry for plugins
/// @notice This contract serves as a registry for version information of various plugins.
contract VersionRegistry is IVersionRegistry {
    Version private latestVersion;

    /// @dev Address of the contract owner or authorized entity for version management.
    address private owner;

    /// @dev Mapping from plugin address to its version information.
    mapping(address => Version) private pluginVersions;

    error NotCalledByOwner();
    error InvalidVersion();

    /// @notice Constructor sets the initial owner of the contract.
    constructor() {
        owner = msg.sender;
    }

    /// @notice Modifier to restrict certain functions to the contract owner only.
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotCalledByOwner();
        }
        _;
    }

    /// @inheritdoc IVersionRegistry
    function registerPlugin(address plugin) external onlyOwner {
        string memory versionString = IPlugin(plugin).pluginMetadata().version;
        Version memory newVersion = decodeVersion(versionString);

        if (
            (newVersion.major < latestVersion.major)
                || (newVersion.major == latestVersion.major && newVersion.minor < latestVersion.minor)
        ) {
            revert InvalidVersion();
        }

        pluginVersions[plugin] = newVersion;
        latestVersion = newVersion;
    }

    /// @inheritdoc IVersionRegistry
    function getPluginVersion(address plugin) external view returns (Version memory) {
        return pluginVersions[plugin];
    }

    /// @notice Checks if there is a newer version available for a plugin.
    /// @param plugin The address of the plugin.
    /// @return isNewVersionAvailable A boolean indicating whether a newer version is available.
    function isNewVersionAvailable(address plugin) external view returns (bool) {
        Version memory pluginVersion = pluginVersions[plugin];

        return (latestVersion.major > pluginVersion.major)
            || (latestVersion.major == pluginVersion.major && latestVersion.minor > pluginVersion.minor)
            || (
                latestVersion.major == pluginVersion.major && latestVersion.minor == pluginVersion.minor
                    && latestVersion.patch > pluginVersion.patch
            );
    }

    /// @inheritdoc IVersionRegistry
    function isPluginCompatible(address oldPlugin, address newPlugin) external view returns (bool) {
        Version memory oldPluginVersion = pluginVersions[oldPlugin];
        Version memory newPluginVersion = pluginVersions[newPlugin];

        return (
            oldPluginVersion.major == newPluginVersion.major && oldPluginVersion.minor == newPluginVersion.minor
                && oldPluginVersion.patch != newPluginVersion.patch
        );
    }
}
