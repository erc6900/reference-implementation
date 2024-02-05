// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {IVersionRegistry} from "../interfaces/IVersionRegistry.sol";
import {Version, decodeVersion} from "../helpers/VersionDecoder.sol";
import {IPlugin} from "../interfaces/IPlugin.sol";

/// @title VersionRegistry for plugins
/// @notice This contract serves as a registry for version information of various plugins.
contract VersionRegistry is IVersionRegistry {
    /// @dev Mapping from plugin address to its version information.
    mapping(address => Version) private pluginVersions;
    Version private latestVersion;

    /// @dev Address of the contract owner or authorized entity for version management.
    address private owner;

    /// @notice Constructor sets the initial owner of the contract.
    constructor() {
        owner = msg.sender;
    }

    /// @notice Modifier to restrict certain functions to the contract owner only.
    modifier onlyOwner() {
        require(msg.sender == owner, "VersionRegistry: Caller is not the plugin owner");
        _;
    }

    /// @inheritdoc IVersionRegistry
    function registerPlugin(address plugin) external onlyOwner {
        string memory versionString = IPlugin(plugin).pluginMetadata().version;
        Version memory newVersion = decodeVersion(versionString);

        if (
            (newVersion.major < latestVersion.major)
            || (newVersion.major == latestVersion.major && newVersion.minor < latestVersion.minor)
            || (newVersion.major == latestVersion.major && newVersion.minor == latestVersion.minor && newVersion.patch < latestVersion.patch)
        ) {
            revert("VersionRegistry: New version must be higher than the current latest version");
        }

        pluginVersions[plugin] = newVersion;
        latestVersion = newVersion;
    }

    /// @inheritdoc IVersionRegistry
    function getPluginVersion(address plugin) external view returns (Version memory) {
        return pluginVersions[plugin];
    }

    /// @inheritdoc IVersionRegistry
    function isNewVersionAvailable(address plugin) external view returns (bool) {
        Version memory pluginVersion = pluginVersions[plugin];

        return (latestVersion.major > pluginVersion.major)
            || (latestVersion.major == pluginVersion.major && latestVersion.minor > pluginVersion.minor)
            || (
                latestVersion.major == pluginVersion.major && latestVersion.minor == pluginVersion.minor
                    && latestVersion.patch > pluginVersion.patch
            );
    }
}
