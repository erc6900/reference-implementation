// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IVersionRegistry} from "../../interfaces/IVersionRegistry.sol";
import {Version, decodeVersion} from "../../helpers/VersionDecoder.sol";
import {IPlugin} from "../../interfaces/IPlugin.sol";

/// @title SimpleVersionRegistry.sol for plugins
/// @notice This contract serves as a registry for version information of various plugins.
contract SimpleVersionRegistry is IVersionRegistry, Initializable {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev Address of the contract owner or authorized entity for version management.
    address private owner;

    /// @dev Mapping to check the compatibility between plugins.
    mapping(bytes32 nameHash => EnumerableSet.AddressSet compatibleVersions) internal pluginsGroup;

    /// @notice Event for plugin registration
    /// @param plugin Address of the plugin that is registered
    event PluginRegistered(address indexed plugin);

    error NotCalledByOwner();
    error InvalidVersion();

    /// @notice Modifier to restrict certain functions to the contract owner only.
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert NotCalledByOwner();
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        owner = msg.sender;
    }

    /// @inheritdoc IVersionRegistry
    function registerPlugin(address plugin) external onlyOwner {
        bytes32 nameHash = keccak256(abi.encode(IPlugin(plugin).pluginMetadata().name));
        EnumerableSet.AddressSet storage pluginGroup = pluginsGroup[nameHash];

        if (pluginGroup.length() != 0) {
            // Get the version of the first registered plugin
            address firstPlugin = pluginGroup.at(0);
            Version memory originalVersion = getPluginVersion(firstPlugin);
            Version memory version = getPluginVersion(plugin);
            if (
                (version.major != originalVersion.major)
                    || (version.major == originalVersion.major && version.minor != originalVersion.minor)
                    || (
                        version.major == originalVersion.major && version.minor == originalVersion.minor
                            && version.patch == originalVersion.patch
                    )
            ) {
                revert InvalidVersion();
            }
        }

        pluginGroup.add(plugin);

        emit PluginRegistered(plugin);
    }

    /// @inheritdoc IVersionRegistry
    function getPluginVersion(address plugin) public pure returns (Version memory) {
        string memory versionString = IPlugin(plugin).pluginMetadata().version;
        return decodeVersion(versionString);
    }

    /// @inheritdoc IVersionRegistry
    function isPluginCompatible(address oldPlugin, address newPlugin) external view returns (bool isCompatible) {
        bytes32 nameHash = keccak256(abi.encode(IPlugin(oldPlugin).pluginMetadata().name));
        isCompatible = pluginsGroup[nameHash].contains(newPlugin);

        return isCompatible;
    }
}
