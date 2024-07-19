// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {IExecutionHook} from "../../src/interfaces/IExecutionHook.sol";
import {IModule, ModuleManifest, ModuleMetadata} from "../../src/interfaces/IModule.sol";
import {IValidation} from "../../src/interfaces/IValidation.sol";

contract MockModule is ERC165 {
    // It's super inefficient to hold the entire abi-encoded manifest in storage, but this is fine since it's
    // just a mock. Note that the reason we do this is to allow copying the entire contents of the manifest
    // into storage in a single line, since solidity fails to compile with memory -> storage copying of nested
    // dynamic types when compiling without `via-ir` in the lite profile.
    // See the error code below:
    // Error: Unimplemented feature (/solidity/libsolidity/codegen/ArrayUtils.cpp:228):Copying of type
    // struct ManifestAssociatedFunction memory[] memory to storage not yet supported.
    bytes internal _manifest;

    string internal constant _NAME = "Mock Module Modifiable";
    string internal constant _VERSION = "1.0.0";
    string internal constant _AUTHOR = "ERC-6900 Authors";

    event ReceivedCall(bytes msgData, uint256 msgValue);

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Module interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    constructor(ModuleManifest memory _moduleManifest) {
        _manifest = abi.encode(_moduleManifest);
    }

    function _getManifest() internal view returns (ModuleManifest memory) {
        ModuleManifest memory m = abi.decode(_manifest, (ModuleManifest));
        return m;
    }

    function _castToPure(function() internal view returns (ModuleManifest memory) fnIn)
        internal
        pure
        returns (function() internal pure returns (ModuleManifest memory) fnOut)
    {
        assembly ("memory-safe") {
            fnOut := fnIn
        }
    }

    function moduleManifest() external pure returns (ModuleManifest memory) {
        return _castToPure(_getManifest)();
    }

    function moduleMetadata() external pure returns (ModuleMetadata memory) {
        ModuleMetadata memory metadata;
        metadata.name = _NAME;
        metadata.version = _VERSION;
        metadata.author = _AUTHOR;
        return metadata;
    }

    /// @dev Returns true if this contract implements the interface defined by
    /// `interfaceId`. See the corresponding
    /// https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
    /// to learn more about how these ids are created.
    ///
    /// This function call must use less than 30 000 gas.
    ///
    /// Supporting the IModule interface is a requirement for module installation. This is also used
    /// by the modular account to prevent standard execution functions `execute` and `executeBatch` from
    /// making calls to modules.
    /// @param interfaceId The interface ID to check for support.
    /// @return True if the contract supports `interfaceId`.

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IModule).interfaceId || super.supportsInterface(interfaceId);
    }

    receive() external payable {}

    // solhint-disable-next-line no-complex-fallback
    fallback() external payable {
        emit ReceivedCall(msg.data, msg.value);
        if (
            msg.sig == IValidation.validateUserOp.selector || msg.sig == IValidation.validateRuntime.selector
                || msg.sig == IExecutionHook.preExecutionHook.selector
        ) {
            // return 0 for userOp/runtimeVal case, return bytes("") for preExecutionHook case
            assembly ("memory-safe") {
                mstore(0, 0)
                return(0x00, 0x20)
            }
        }
    }
}
