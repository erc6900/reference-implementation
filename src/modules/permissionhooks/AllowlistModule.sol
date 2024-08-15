// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";

import {ModuleMetadata} from "../../interfaces/IModule.sol";

import {Call, IStandardExecutor} from "../../interfaces/IStandardExecutor.sol";
import {IValidationHookModule} from "../../interfaces/IValidationHookModule.sol";
import {BaseModule} from "../../modules/BaseModule.sol";

contract AllowlistModule is IValidationHookModule, BaseModule {
    struct AllowlistInit {
        address target;
        bool hasSelectorAllowlist;
        bytes4[] selectors;
    }

    struct AllowlistEntry {
        bool allowed;
        bool hasSelectorAllowlist;
    }

    mapping(uint32 entityId => mapping(address target => mapping(address account => AllowlistEntry))) public
        targetAllowlist;
    mapping(
        uint32 entityId => mapping(address target => mapping(bytes4 selector => mapping(address account => bool)))
    ) public selectorAllowlist;

    event AllowlistTargetUpdated(
        uint32 indexed entityId, address indexed account, address indexed target, AllowlistEntry entry
    );
    event AllowlistSelectorUpdated(
        uint32 indexed entityId, address indexed account, bytes24 indexed targetAndSelector, bool allowed
    );

    error TargetNotAllowed();
    error SelectorNotAllowed();
    error NoSelectorSpecified();

    function onInstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        for (uint256 i = 0; i < init.length; i++) {
            setAllowlistTarget(entityId, init[i].target, true, init[i].hasSelectorAllowlist);

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    setAllowlistSelector(entityId, init[i].target, init[i].selectors[j], true);
                }
            }
        }
    }

    function onUninstall(bytes calldata data) external override {
        (uint32 entityId, AllowlistInit[] memory init) = abi.decode(data, (uint32, AllowlistInit[]));

        for (uint256 i = 0; i < init.length; i++) {
            setAllowlistTarget(entityId, init[i].target, false, false);

            if (init[i].hasSelectorAllowlist) {
                for (uint256 j = 0; j < init[i].selectors.length; j++) {
                    setAllowlistSelector(entityId, init[i].target, init[i].selectors[j], false);
                }
            }
        }
    }

    function preUserOpValidationHook(uint32 entityId, PackedUserOperation calldata userOp, bytes32)
        external
        view
        override
        returns (uint256)
    {
        checkAllowlistCalldata(entityId, userOp.callData);
        return 0;
    }

    function preRuntimeValidationHook(uint32 entityId, address, uint256, bytes calldata data, bytes calldata)
        external
        view
        override
    {
        checkAllowlistCalldata(entityId, data);
        return;
    }

    // solhint-disable-next-line no-empty-blocks
    function preSignatureValidationHook(uint32, address, bytes32, bytes calldata) external pure override {}

    function moduleMetadata() external pure override returns (ModuleMetadata memory) {
        ModuleMetadata memory metadata;
        metadata.name = "Allowlist Module";
        metadata.version = "v0.0.1";
        metadata.author = "ERC-6900 Working Group";

        return metadata;
    }

    function setAllowlistTarget(uint32 entityId, address target, bool allowed, bool hasSelectorAllowlist) public {
        AllowlistEntry memory entry = AllowlistEntry(allowed, hasSelectorAllowlist);
        targetAllowlist[entityId][target][msg.sender] = entry;
        emit AllowlistTargetUpdated(entityId, msg.sender, target, entry);
    }

    function setAllowlistSelector(uint32 entityId, address target, bytes4 selector, bool allowed) public {
        selectorAllowlist[entityId][target][selector][msg.sender] = allowed;
        bytes24 targetAndSelector = bytes24(bytes24(bytes20(target)) | (bytes24(selector) >> 160));
        emit AllowlistSelectorUpdated(entityId, msg.sender, targetAndSelector, allowed);
    }

    function checkAllowlistCalldata(uint32 entityId, bytes calldata callData) public view {
        if (bytes4(callData[:4]) == IStandardExecutor.execute.selector) {
            (address target,, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkCallPermission(entityId, msg.sender, target, data);
        } else if (bytes4(callData[:4]) == IStandardExecutor.executeBatch.selector) {
            Call[] memory calls = abi.decode(callData[4:], (Call[]));

            for (uint256 i = 0; i < calls.length; i++) {
                _checkCallPermission(entityId, msg.sender, calls[i].target, calls[i].data);
            }
        }
    }

    function _checkCallPermission(uint32 entityId, address account, address target, bytes memory data)
        internal
        view
    {
        AllowlistEntry storage entry = targetAllowlist[entityId][target][account];
        (bool allowed, bool hasSelectorAllowlist) = (entry.allowed, entry.hasSelectorAllowlist);

        if (!allowed) {
            revert TargetNotAllowed();
        }

        if (hasSelectorAllowlist) {
            if (data.length < 4) {
                revert NoSelectorSpecified();
            }

            bytes4 selector = bytes4(data);

            if (!selectorAllowlist[entityId][target][selector][account]) {
                revert SelectorNotAllowed();
            }
        }
    }
}
