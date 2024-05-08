// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IPluginManager} from "../../../src/interfaces/IPluginManager.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    PluginMetadata,
    SelectorPermission
} from "../../../src/interfaces/IPlugin.sol";
import {IStandardExecutor} from "../../../src/interfaces/IStandardExecutor.sol";
import {BasePlugin} from "../../../src/plugins/BasePlugin.sol";
import {ISingleOwnerPlugin} from "../../../src/plugins/owner/ISingleOwnerPlugin.sol";

/// Copy of SingleOwnerPlugin with differently-named execution functions,
// so it can be installed with overlapping validation to the regular SingleOwnerPlugin.
// Also missing isValidSignature
contract SingleOwnerPlugin2 is BasePlugin {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    string public constant NAME = "Single Owner Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "ERC-6900 Authors";

    uint256 internal constant _SIG_VALIDATION_PASSED = 0;
    uint256 internal constant _SIG_VALIDATION_FAILED = 1;

    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    mapping(address => address) internal _owners;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function transferOwnership2(address newOwner) external {
        _transferOwnership(newOwner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function onInstall(bytes calldata data) external override {
        _transferOwnership(abi.decode(data, (address)));
    }

    function onUninstall(bytes calldata) external override {
        _transferOwnership(address(0));
    }

    function runtimeValidationFunction(uint8 functionId, address sender, uint256, bytes calldata)
        external
        view
        override
    {
        if (functionId == uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER_OR_SELF)) {
            // Validate that the sender is the owner of the account or self.
            if (sender != _owners[msg.sender]) {
                // solhint-disable-next-line custom-errors
                revert("NotAuthorized()");
            }
            return;
        }
        revert NotImplemented();
    }

    function userOpValidationFunction(uint8 functionId, PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        if (functionId == uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER_OR_SELF)) {
            // Validate the user op signature against the owner.
            (address signer,,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
            if (signer == address(0) || signer != _owners[msg.sender]) {
                return _SIG_VALIDATION_FAILED;
            }
            return _SIG_VALIDATION_PASSED;
        }
        revert NotImplemented();
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function owner2() external view returns (address) {
        return _owners[msg.sender];
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function ownerOf(address account) external view returns (address) {
        return _owners[account];
    }

    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.executionFunctions = new bytes4[](2);
        manifest.executionFunctions[0] = this.transferOwnership2.selector;
        manifest.executionFunctions[1] = this.owner2.selector;

        ManifestFunction memory ownerValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(ISingleOwnerPlugin.FunctionId.VALIDATION_OWNER_OR_SELF),
            dependencyIndex: 0 // Unused.
        });
        manifest.validationFunctions = new ManifestAssociatedFunction[](6);
        manifest.validationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.transferOwnership2.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.execute.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: IStandardExecutor.executeBatch.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[3] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.installPlugin.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[4] = ManifestAssociatedFunction({
            executionSelector: IPluginManager.uninstallPlugin.selector,
            associatedFunction: ownerValidationFunction
        });
        manifest.validationFunctions[5] = ManifestAssociatedFunction({
            executionSelector: UUPSUpgradeable.upgradeToAndCall.selector,
            associatedFunction: ownerValidationFunction
        });

        return manifest;
    }

    function pluginMetadata() external pure virtual override returns (PluginMetadata memory) {
        PluginMetadata memory metadata;
        metadata.name = NAME;
        metadata.version = VERSION;
        metadata.author = AUTHOR;

        // Permission strings
        string memory modifyOwnershipPermission = "Modify Ownership";

        // Permission descriptions
        metadata.permissionDescriptors = new SelectorPermission[](1);
        metadata.permissionDescriptors[0] = SelectorPermission({
            functionSelector: this.transferOwnership2.selector,
            permissionDescription: modifyOwnershipPermission
        });

        return metadata;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISingleOwnerPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _transferOwnership(address newOwner) internal {
        address previousOwner = _owners[msg.sender];
        _owners[msg.sender] = newOwner;
        emit OwnershipTransferred(msg.sender, previousOwner, newOwner);
    }
}
