// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

/// @title VersionRegistry for plugins
/// @notice This contract serves as a registry for version information of various plugins.
contract VersionRegistry {
    struct Version {
        uint8 major;
        uint8 minor;
        uint8 patch;
    }

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

    /// @notice Registers a plugin with its version information.
    /// @dev This function can be called by the contract owner or authorized entity only.
    /// @param plugin The address of the plugin to be registered.
    /// @param major The major version number of the plugin.
    /// @param minor The minor version number of the plugin.
    /// @param patch The patch version number of the plugin.
    function registerPlugin(address plugin, uint8 major, uint8 minor, uint8 patch) external onlyOwner {
        Version memory newVersion = Version(major, minor, patch);

        require(
            (newVersion.major > latestVersion.major) ||
            (newVersion.major == latestVersion.major && newVersion.minor > latestVersion.minor) ||
            (newVersion.major == latestVersion.major && newVersion.minor == latestVersion.minor && newVersion.patch > latestVersion.patch),
            "VersionRegistry: New version must be higher than the current latest version"
        );

        pluginVersions[plugin] = newVersion;
        latestVersion = newVersion;
    }

    /// @notice Retrieves the version information of a registered plugin.
    /// @param plugin The address of the plugin whose version information is being queried.
    /// @return The version information of the specified plugin.
    function getPluginVersion(address plugin) external view returns (Version memory) {
        return pluginVersions[plugin];
    }

    /// @notice Checks if there is a newer version available for a plugin.
    /// @param plugin The address of the plugin.
    /// @return isNewVersionAvailable A boolean indicating whether a newer version is available.
    function isNewVersionAvailable(address plugin) external view returns (bool) {
        Version memory pluginVersion = pluginVersions[plugin];

        return (latestVersion.major > pluginVersion.major) || 
               (latestVersion.major == pluginVersion.major && latestVersion.minor > pluginVersion.minor) || 
               (latestVersion.major == pluginVersion.major && latestVersion.minor == pluginVersion.minor && latestVersion.patch > pluginVersion.patch);
    }
}
