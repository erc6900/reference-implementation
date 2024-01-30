// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.19;

interface IVersionRegistry {
    struct Version {
        uint8 major;
        uint8 minor;
        uint8 patch;
    }

    /// @notice Register a new plugin version in the registry.
    /// @dev This function can be restricted to only be callable by the contract owner or a specific role.
    /// @param plugin The address of the plugin to register.
    /// @param major The major version number.
    /// @param minor The minor version number.
    /// @param patch The patch version number.
    function registerPlugin(address plugin, uint8 major, uint8 minor, uint8 patch) external;

    /// @notice Retrieve the version information of a given plugin.
    /// @param plugin The address of the plugin whose version information is being queried.
    /// @return The version information of the plugin.
    function getPluginVersion(address plugin) external view returns (Version memory);

    /// @notice Checks if there is a newer version available for a plugin.
    /// @param plugin The address of the plugin.
    /// @return isNewVersionAvailable A boolean indicating whether a newer version is available.
    function isNewVersionAvailable(address plugin) external view returns (bool);
}
