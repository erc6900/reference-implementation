// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {PluginManifest, IPlugin, PluginMetadata} from "../../src/interfaces/IPlugin.sol";

contract MockPlugin is ERC165 {
    // It's super inefficient to hold the entire abi-encoded manifest in storage, but this is fine since it's
    // just a mock. Note that the reason we do this is to allow copying the entire contents of the manifest
    // into storage in a single line, since solidity fails to compile with memory -> storage copying of nested
    // dynamic types when compiling without `via-ir` in the lite profile.
    // See the error code below:
    // Error: Unimplemented feature (/solidity/libsolidity/codegen/ArrayUtils.cpp:228):Copying of type
    // struct ManifestAssociatedFunction memory[] memory to storage not yet supported.
    bytes internal _manifest;

    string public constant NAME = "Mock Plugin Modifiable";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    event ReceivedCall(bytes msgData, uint256 msgValue);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    constructor(PluginManifest memory _pluginManifest) {
        _manifest = abi.encode(_pluginManifest);
    }

    function _getManifest() internal view returns (PluginManifest memory) {
        PluginManifest memory m = abi.decode(_manifest, (PluginManifest));
        return m;
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

    function pluginManifest() external pure returns (PluginManifest memory) {
        return _castToPure(_getManifest)();
    }

    function pluginMetadata() external pure returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;
        return metadata;
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IPlugin interface is a requirement for plugin installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to plugins.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    receive() external payable {}

    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        emit ReceivedCall(msg.data, msg.value);
        if (
            msg.sig == IPlugin.userOpValidationFunction.selector
                || msg.sig == IPlugin.runtimeValidationFunction.selector
                || msg.sig == IPlugin.preExecutionHook.selector
        ) {
            // return 0 for userOp/runtimeVal case, return bytes("") for preExecutionHook case
            assembly ("memory-safe") {
                mstore(0, 0)
                return(0x00, 0x20)
            }
        }
    }
}
